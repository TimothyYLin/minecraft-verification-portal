const express = require('express')
const cors = require('cors');
const helmet = require('helmet')
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
// const { Rcon: rcon } = require('rcon-client').Rcon; // TODO: Use when Minecraft
const Database = require('better-sqlite3');
require('dotenv').config();

const app = express();
app.set('trust proxy', 1);
const db = new Database('./minecraft.db');
const PORT = 3000;  // Default HTTPS port

const EMAIL_VERIFICATION_EXPIRATION_MINUTES = 15;
const MC_CODE_EXPIRATION_MINUTES = 15;
const SEVEN_DAYS_IN_MS = 60 * 1000;
const ACCESS_TOKEN_EXPIRES_IN = '15m';
const REFRESH_TOKEN_EXPIRES_IN = '7d';

// TODO: process.env.JWT_SECRET use Kubernetes Secrets
// TODO: Environment validation of dotenv

// Middleware
app.use(cookieParser());
app.use(cors({
    origin: process.env.FRONTEND_URL || 'https://localhost:5173',
    credentials: true
}));
app.use(helmet()); // Add security headers
app.use(express.json());  // Parse incoming json req

// For debugging purposes
// app.use(express.json({
//     verify: (req, res, buf, encoding) => {
//         // This function is called with the raw buffer of the body
//         // before express.json() tries to parse it.
//         // We'll store it on the request object to log it in the actual route
//         // if an error occurs, or just log it here for all requests if needed.
//         try {
//             // You can try to parse it here to see if it's valid immediately
//             console.log("REQ:", req);
//             JSON.parse(buf.toString(encoding));
//         } catch (e) {
//             // If it's not valid JSON, log the raw buffer content
//             console.error('RAW BODY RECEIVED (INVALID JSON):', buf.toString(encoding));
//         }
//         // You can also attach it to req to be logged in the specific route handler
//         req.rawBodyBuffer = buf; // Store the buffer
//     }
// }));

// SQLite Table Creation
try {
    db.exec(`
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email_verified INTEGER DEFAULT 0,
            mc_username TEXT,
            approved INTEGER DEFAULT 0,
            mc_verified INTEGER DEFAULT 0,
            refresh_token TEXT UNIQUE,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS email_verifications(
            user_id INTEGER PRIMARY KEY,
            code TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS minecraft_verification_codes(
            user_id INTEGER PRIMARY KEY,
            code TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_mc_username_verified ON users(mc_username, mc_verified);

        CREATE UNIQUE INDEX IF NOT EXISTS idx_users_refresh_token ON users(refresh_token);
    `);

    console.log('Database setup complete or already exists.');
} catch (err) {
    console.error('Error creating schema or index:', err.message);
}

// Utility
async function sendVerificationEmail(toEmail, code) {
    const appBaseUrl = process.env.APP_BASE_URL || `http://localhost:${process.env.PORT || 3000}`;
    const verificationUrl = `${appBaseUrl}/api/verify-email?code=${code}`;

    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });

    const mailOptions = {
        from: `"Konoha Minecraft Server Access Portal" <${process.env.EMAIL_USER}>`,
        to: toEmail,
        subject: "Verify your email for Konoha Minecraft Server",
        html: `
            <div style="font-family: sans-serif; line-height: 1.6;">
                <h2> Welcome to the Konoha Minecraft Server Access Portal! </h2>
                <p> To verify your email address and continue the registration process,
                please click the link below: </p>
                <p>
                    <a href="${verificationUrl}"
                       target="_blank"
                       style="background-color: #4CAF50;
                              color: white;
                              padding: 10px 20px;
                              text-decoration: none;">Verify Email</a>
                </p>
                <p>This link will expire in ${EMAIL_VERIFICATION_EXPIRATION_MINUTES} 
                   minutes for security purposes.
                </p>
                <hr />
                <p>If you did not request this, please ignore this email.</p>
            </div>
        `
    };

    const info = await transporter.sendMail(mailOptions);
    console.log(`Verification email sent: ${info.messageId}`);
    console.log(`Verification URL (for local testing): ${verificationUrl}`);
}

async function isValidMinecraftUsername(username) {
    const response = await fetch(`https://api.mojang.com/users/profiles/minecraft/${username}`);
    return response.status === 200;
}

// Middleware Functions
function authenticateToken(req, res, next){
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if(!token){
        return res.status(401).json({
            code: 'TOKEN_MISSING',
            error: 'Unauthorized: Missing token'
        });
    }

    console.log('JWT_SECRET used for verification:', process.env.JWT_SECRET);
    console.log('Token being verified:', token);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if(err){
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({
                    code: 'TOKEN_EXPIRED',
                    error: 'Unauthorized: Token has expired'
                });
            }
            return res.status(403).json({
                code: 'TOKEN_INVALID',
                error: 'Forbidden: Invalid token'
            });
        }
        req.user = user;
        next();
    });
}

// Routes
app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    try {
        const existingUser = db.prepare('SELECT id, email_verified FROM users WHERE email = ?').get(email);

        if (existingUser && existingUser.email_verified) {
            return res.status(409).json({ error: 'Email already registered and verified. Please log in.' });
        }

        if (existingUser) {
            const existingCode = db.prepare('SELECT expires_at FROM email_verifications WHERE user_id = ?').get(existingUser.id);

            if (existingCode) {
                const expirationTime = new Date(existingCode.expires_at);
                if (Date.now() < expirationTime) {
                    return res.status(400).json({
                        code: 'ACTIVE_LINK_EXISTS',
                        message: `An active verification link has already been sent to ${email}. Please check your inbox (and spam folder).`,
                        expiresAt: expirationTime.toISOString()
                    });
                } 
            }
        }

        const hash = await bcrypt.hash(password, 10);
        let userId;

        if (existingUser) {
            userId = existingUser.id;
            db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, userId);
            console.log(`Password updated for unverified user: ${email}`);
        } else {
            const result = db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)').run(email, hash);
            userId = result.lastInsertRowid;
        }

        const transaction = db.transaction(() => {
            db.prepare('DELETE FROM email_verifications WHERE user_id = ?').run(userId);

            const code = uuidv4();
            const expiresAt = new Date(
                Date.now() + (EMAIL_VERIFICATION_EXPIRATION_MINUTES * 60 * 1000)
            ).toISOString();
            
            db.prepare('INSERT INTO email_verifications (user_id, code, expires_at) VALUES (?, ?, ?)').run(userId, code, expiresAt);
            return code;
        });

        const verificationCode = transaction();

        try{
            await sendVerificationEmail(email, verificationCode);
            return res.status(201).json({ message: 'Registration successful. Please check your email to verify your account.' });
        }catch(emailError){
            console.error('CRITICAL: Failed to send verification email AFTER code generation:', emailError);
            db.prepare('DELETE FROM email_verifications WHERE user_id = ? AND code = ?').run(userId, verificationCode);
            console.log(`Rolled back (deleted) verification code for user ${userId} due to email sending failure.`);
            
            return res.status(500).json({
                error: `We could not send a verification email at this time. Please try registering again shortly or 
                        contact support if the issue persists.`,
                details: emailError.message // Optionally, you might not want to send raw error details to the client
            });
        }

    } catch (dbError) {
        console.error('Registration error or bcrypt error:', dbError);
        if (dbError.message.includes('UNIQUE constraint failed: users.email') && !existingUser) {
            return res.status(409).json({ error: 'This email address is already registered.' });
        }
        return res.status(500).json({ error: 'Internal server error during registration process.' });
    }
});

app.get('/api/verify-email', (req, res) => {
    const { code } = req.query;

    if(!code){
        // TODO: render error page
        return res.status(400).send('<h1>Error: Verification code is missing.</h1>');
    }

    try{
        const transaction = db.transaction(() => {
            const verificationRecord = db.prepare(`
                SELECT user_id, expires_at FROM email_verifications WHERE code = ?
            `).get(code);

            if(!verificationRecord){
                return { error: 'Invalid verification code.' };
            }

            if (new Date() > new Date(verificationRecord.expires_at)){
                db.prepare('DELETE FROM email_verifications WHERE code = ?').run(code);
                return { error: 'This verification link has expired. Please request a new one.'};
            }

            db.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run(verificationRecord.user_id);

            const user = db.prepare('SELECT id, email FROM users WHERE id = ?').get(verificationRecord.user_id);
            db.prepare(`DELETE FROM email_verifications WHERE code = ?`).run(code);

            if(!user){
                return { error: 'Could not find user associated with this verification code.'};
            }

            return { success: true, user: user };
        });

        const result = transaction();
        if(result.error){
            return res.status(400).send(`<h1>Verification Failed</h1><p>${result.error}</p>`);
        }

        const user = result.user;

        const accessToken = jwt.sign(
            { id: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: ACCESS_TOKEN_EXPIRES_IN }
        );

        const refreshToken = jwt.sign(
            { id: user.id },
            process.env.REFRESH_TOKEN_SECRET,
            { expiresIn: REFRESH_TOKEN_EXPIRES_IN }
        );

        db.prepare('UPDATE users SET refresh_token = ? WHERE id = ?').run(refreshToken, user.id);

        console.log(`[VERIFY-EMAIL] Setting cookie for user ${user.id} with token: ${refreshToken}`);
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: SEVEN_DAYS_IN_MS
        });

        const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
        return res.redirect(`${frontendUrl}/login-success?token=${accessToken}`);
    }catch(dbError){
        console.error("Database error during email verification:", dbError);
        return res.status(500).send(`<h1>Error</h1><p>An internal server error occurred.</p>`);
    }
});

app.post('/api/resend-verification', async (req, res) => {
    const { email } = req.body;
    if(!email){
        return res.status(400).json({ error: 'Email is required.' });
    }

    try {
        const user = db.prepare('SELECT id, email_verified FROM users WHERE email = ?').get(email);
        if(!user){
            return res.status(200).json({ 
                message: 'If an account with this email exists, a new verification link has been sent.'
            });
        }

        if(user.email_verified){
            return res.status(400).json({ error: 'This email has already been verified. Please log in.' });
        }

        const transaction = db.transaction(() => {
            db.prepare('DELETE FROM email_verifications WHERE user_id = ?').run(user.id);

            const code = uuidv4();
            const expiresAt = new Date(
                Date.now() + (EMAIL_VERIFICATION_EXPIRATION_MINUTES * 60 * 1000)
            ).toISOString();

            const insertVerification = db.prepare(`
                INSERT INTO email_verifications
                    (user_id, code, expires_at)
                VALUES
                    (?, ?, ?)
            `);
            insertVerification.run(user.id, code, expiresAt);
            return code;
        });

        const newCode = transaction();

        await sendVerificationEmail(email, newCode);

        return res.status(200).json({ message: 'A new verification link has been sent to your email.' });
    }catch(err){
        console.error('Resend verification error:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
        if (!user) {
            return res.status(401).json({
                code: 'INVALID_CREDENTIALS',
                error: 'Invalid email or password'
            });
        }

        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) {
            return res.status(401).json({
                code: 'INVALID_CREDENTIALS',
                error: 'Invalid email or password'
            });
        }

        if (!user.email_verified) {
            return res.status(403).json({ 
                code: 'EMAIL_NOT_VERIFIED',
                message: 'Your email address must be verified before you can log in.' 
            });
        }

        const accessToken = jwt.sign(
            { id: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: ACCESS_TOKEN_EXPIRES_IN }
        );

        const refreshToken = jwt.sign(
            { id: user.id },
            process.env.REFRESH_TOKEN_SECRET,
            { expiresIn: REFRESH_TOKEN_EXPIRES_IN }
        );

        db.prepare('UPDATE users SET refresh_token = ? WHERE id = ?').run(refreshToken, user.id);

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: SEVEN_DAYS_IN_MS
        });

        return res.status(200).json({ 
            message: 'Login successful.',
            token: accessToken 
        });
    } catch (err) {
        console.error('Login error:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }

});

app.post('/api/refresh-token', (req, res) => {
    const oldRefreshToken = req.cookies.refreshToken;
    console.log(`[REFRESH-TOKEN] Received cookie with token: ${oldRefreshToken}`);
    if(!oldRefreshToken){
        return res.status(401).json({
            code: 'REFRESH_TOKEN_MISSING',
            error: 'No refresh token provided.'
        });
    }

    try{
        const user = db.prepare('SELECT * FROM users WHERE refresh_token = ?').get(oldRefreshToken);
        if(!user){
            try {
                const decoded = jwt.decode(oldRefreshToken);
                if (decoded && decoded.id) {
                    console.warn(`SECURITY: Reused refresh token detected for user ID: ${decoded.id}. Forcing logout.`);
                    db.prepare('UPDATE users SET refresh_token = NULL WHERE id = ?').run(decoded.id);
                }
            } catch (decodeError) {
                console.error("Could not decode the invalid refresh token:", decodeError);
            }
            res.clearCookie('refreshToken');
            return res.status(403).json({ error: 'Forbidden' });
        }

        jwt.verify(oldRefreshToken, process.env.REFRESH_TOKEN_SECRET, (err, decoded) => {
            if(err || user.id !== decoded.id){
                db.prepare('UPDATE users SET refresh_token = NULL WHERE id = ?').run(user.id);
                res.clearCookie('refreshToken');
                return res.status(403).json({ error: 'Forbidden' });
            }

            // Sliding Session Logic
            const newAccessToken = jwt.sign(
                { id: user.id, email: user.email },
                process.env.JWT_SECRET,
                {expiresIn: ACCESS_TOKEN_EXPIRES_IN }
            );

            const newRefreshToken = jwt.sign(
                { id: user.id },
                process.env.REFRESH_TOKEN_SECRET,
                { expiresIn: REFRESH_TOKEN_EXPIRES_IN }
            );

            db.prepare('UPDATE users SET refresh_token = ? WHERE id = ?').run(newRefreshToken, user.id);

            res.cookie('refreshToken', newRefreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'lax',
                maxAge: SEVEN_DAYS_IN_MS
            });

            res.status(200).json({ token: newAccessToken });
        });
    }catch(dbError){
        console.error("Database error during token refresh:", dbError);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/logout', (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    try{
        if(refreshToken){
            db.prepare('UPDATE users SET refresh_token = NULL WHERE refresh_token = ?').run(refreshToken);
        }
        res.clearCookie('refreshToken');
        return res.status(200).json({ message: 'Logout successful.' });
    }catch(dbError){
        console.error("Database error during logout:", dbError);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

app.use(authenticateToken);

app.post('/api/mc-username', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const { mc_username } = req.body;

    if(!mc_username){
        return res.status(400).json({ error: 'Missing mc_username' });
    }

    try {
        const valid = await isValidMinecraftUsername(mc_username);
        if (!valid) {
            return res.status(400).json({ error: 'Minecraft username does not exist' });
        }

        const user = db.prepare('SELECT mc_username, mc_verified FROM users WHERE id = ?').get(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found.' });
        }

        if (user.mc_verified) {
            // TODO: Decide if a user can change their MC username if already verified.
            return res.status(400).json({ error: 'Minecraft username already verified for this account.' });
        }

        const existingVerifiedMcUser = db.prepare(`
            SELECT
                id
            FROM
                users
            WHERE
                mc_username = ? AND mc_verified = 1
        `).get(mc_username);

        if (existingVerifiedMcUser) {
            return res.status(409).json({
                error: 'This Minecraft username is already verified by another user.'
            });
        }

        const existingCode = db.prepare(`
            SELECT
                code,
                expires_at
            FROM
                minecraft_verification_codes
            WHERE
                user_id = ?
        `).get(userId);

        const currentTime = new Date();

        if (existingCode) {
            const expirationTime = new Date(existingCode.expires_at);

            if (currentTime < expirationTime) {
                return res.status(400).json({
                    message: `
                        You already have an active verification code (${existingCode.code}).
                        Please use it. It expires at ${expirationTime.toLocaleString()}.
                    `
                });
            } else {
                db.prepare('DELETE FROM minecraft_verification_codes WHERE user_id = ?').run(userId);
                console.log(`Expired code for user ${userId} deleted.`);
            }
        }

        const generatedCode = db.transaction(() => {
            const updateStmt = db.prepare(`
                UPDATE
                    users
                SET
                    mc_username = ?,
                    mc_verified = 0
                WHERE
                    id = ?
            `);
            updateStmt.run(mc_username, userId);

            const min = 100000;
            const max = 999999;
            const verificationCode = Math.floor(min + Math.random() * (max - min + 1)).toString();

            const expiresAt = new Date(
                Date.now() + (MC_CODE_EXPIRATION_MINUTES * 60 * 1000)
            ).toISOString();

            const insertPendingStmt = db.prepare(`
                INSERT INTO minecraft_verification_codes
                    (user_id, code, expires_at)
                VALUES
                    (?, ?, ?)
            `);
            insertPendingStmt.run(userId, verificationCode, expiresAt);

            return verificationCode;
        })();

        return res.status(200).json({
            message: 'Mincraft username linked. Please use the following code in-game:',
            code: generatedCode
        });

    } catch (err) {
        console.error('Error in /api/mc-username:', err.message);
        return res.status(500).json({ error: 'Internal server error.' });
    }
});


const ACTUAL_PORT = process.env.PORT || 3000;

app.listen(ACTUAL_PORT, () => {
    console.log(`Server running on http://localhost:${ACTUAL_PORT}`);
});