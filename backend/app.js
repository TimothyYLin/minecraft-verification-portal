const express = require('express')
const cors = require('cors');
const helmet = require('helmet')
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');
// const { Rcon: rcon } = require('rcon-client').Rcon; // TODO: Use when Minecraft

require('dotenv').config();

const app = express();
app.set('trust proxy', 1);

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

pool.query('SELECT NOW()', (err, res) => {
    if(err){
        console.error('Error connecting to PostgreSQL database', err.stack);
    }else{
        console.log('Successfully connected to PostgreSQL database.');
    }
})

// Constants
const EMAIL_VERIFICATION_EXPIRATION_MINUTES = 15;
const MC_CODE_EXPIRATION_MINUTES = 15;
const SEVEN_DAYS_IN_MS = 7 * 24 * 60 * 60 * 1000;
const ACCESS_TOKEN_EXPIRES_IN = '15m';
const REFRESH_TOKEN_EXPIRES_IN = '7d';
const MC_SERVICES_API_URL = 'https://api.minecraftservices.com/minecraft/profile/lookup/name'
const PG_ERROR_CODES = {
    UNIQUE_VIOLATION: '23505'
};

// TODO: process.env.JWT_SECRET use Kubernetes Secrets
// TODO: Environment validation of dotenv

// Middleware
app.use(cookieParser());
if (process.env.NODE_ENV !== 'production'){
    console.log('CORS middleware enabled for development.');
    app.use(cors({
        origin: process.env.FRONTEND_URL || 'https://localhost:5173',
        credentials: true
    }));
}
app.use(helmet()); // Add security headers
app.use(express.json());  // Parse incoming json req

// PostgreSQL Table Creation
async function setupDatabase(){
    const client = await pool.connect();
    try{
        await client.query(`
            -- Stores the main portal accounts
            CREATE TABLE IF NOT EXISTS users(
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email_verified BOOLEAN DEFAULT false,
                approved BOOLEAN DEFAULT true,
                refresh_token TEXT,
                access_tier TEXT NOT NULL DEFAULT 'standard',
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            );

            -- Stores the different Minecraft servers in the network
            CREATE TABLE IF NOT EXISTS servers(
                id SERIAL PRIMARY KEY,
                server_name TEXT NOT NULL,
                server_identifier TEXT UNIQUE NOT NULL,
                required_tier TEXT NOT NULL DEFAULT 'standard'
            );

            -- Stores unique Minecraft accounts a user has linked
            CREATE TABLE IF NOT EXISTS minecraft_accounts(
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                mc_uuid TEXT NOT NULL,
                mc_username TEXT NOT NULL,
                is_verified BOOLEAN DEFAULT false,
                linked_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, mc_uuid)
            );

            -- Links a user's VERIFIED Minecraft account to a specific server
            CREATE TABLE IF NOT EXISTS activations (
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
                minecraft_account_id INTEGER NOT NULL REFERENCES minecraft_accounts(id) ON DELETE CASCADE,
                activated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, server_id)
            );

            -- Email verifications sent out to users registering on the portal
            CREATE TABLE IF NOT EXISTS email_verifications(
                user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                code TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMPTZ NOT NULL
            );

            -- Minecraft verification 6 digit codes sent to users verifying they own the minecraft account
            CREATE TABLE IF NOT EXISTS minecraft_verification_codes(
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                minecraft_account_id INTEGER NOT NULL REFERENCES minecraft_accounts(id) ON DELETE CASCADE,
                code TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMPTZ NOT NULL,
                UNIQUE(user_id),
                UNIQUE(minecraft_account_id)
            );

            -- Indexes for performance
            DO $$ BEGIN
                -- Index on users table for faster email lookups
                IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_users_email') THEN
                    CREATE INDEX idx_users_email ON users(email);
                END IF;
                -- Unique index on users' refresh tokens (allows NULLs, unlike a UNIQUE constraint)
                IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_users_refresh_token') THEN
                    CREATE UNIQUE INDEX idx_users_refresh_token ON users(refresh_token) WHERE refresh_token IS NOT NULL;
                END IF;
                -- Index on minecraft_accounts for faster UUID lookups (for linking checks)
                IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_mc_account_uuid') THEN
                    CREATE INDEX idx_mc_account_uuid ON minecraft_accounts(mc_uuid);
                END IF;
                -- Index on activations for faster lookups based on minecraft account
                IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_activations_mc_account') THEN
                    CREATE INDEX idx_activations_mc_account ON activations(minecraft_account_id);
                END IF;
                -- Enforces that mc_uuid is unique ONLY for rows where is_verified is true.
                IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'minecraft_accounts_verified_mc_uuid_idx') THEN
                    CREATE UNIQUE INDEX minecraft_accounts_verified_mc_uuid_idx ON minecraft_accounts(mc_uuid) WHERE is_verified = true;
                END IF;
            END $$;
        `);
        console.log('Database setup complete or already exists.');
    }catch(err){
        console.error('Error creating schema:', err.stack);
    } finally {
        client.release();
    }
}

setupDatabase().catch(console.error);

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

async function getMinecraftProfile(username) {
    try{
        const response = await fetch(`${MC_SERVICES_API_URL}/${username}`);
        if(response.status === 200){
            const data = await response.json();
            return { uuid: data.id, name: data.name };
        }
        return null;
    }catch(error){
        console.error("Error fetching from Mojang API:", error);
        return null;
    }
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

function authenticateInternalService(req, res, next){
    const apiKey = req.headers['x-internal-api-key'];
    if(!apiKey || apiKey !== process.env.INTERNAL_API_KEY){
        console.warn('Unauthorized attempt to access internal API endpoint. Missing or invalid API key.');
        return res.status(403).json({ error: 'Forbidden' });
    }

    next();
}

// Routes
app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    let client;

    try {
        client = await pool.connect();

        const existingUserResult = await client.query(
            'SELECT id, email_verified FROM users WHERE email = $1',
            [email]
        );
        const existingUser = existingUserResult.rows[0];

        if (existingUser && existingUser.email_verified) {
            return res.status(409).json({ error: 'Email already registered and verified. Please log in.' });
        }

        if (existingUser) {
            const existingCodeResult = await client.query(
                'SELECT expires_at FROM email_verifications WHERE user_id = $1 AND expires_at > NOW()',
                [existingUser.id]
            );

            if(existingCodeResult.rows.length > 0){
                const expirationTime = existingCodeResult.rows[0].expires_at;
                return res.status(400).json({
                    code: 'ACTIVE_LINK_EXISTS',
                    message: `An active verification link has already been sent to ${email}. Please check your inbox (and spam folder).`,
                    expiresAt: expirationTime.toISOString()
                });
            }
        }

        await client.query('BEGIN');

        const hash = await bcrypt.hash(password, 10);
        let userId;

        if (existingUser) {
            userId = existingUser.id;
            await client.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, userId]);
            console.log(`Password updated for unverified user: ${email}`);
        } else {
            const result = await client.query(
                'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id',
                [email, hash]
            );

            userId = result.rows[0].id;
        }

        const code = uuidv4();
        const expiresAtQuery = `NOW() + INTERVAL'${EMAIL_VERIFICATION_EXPIRATION_MINUTES} minutes'`;
        await client.query('DELETE FROM email_verifications WHERE user_id = $1', [userId]);
        await client.query(
            `INSERT INTO email_verifications (user_id, code, expires_at) VALUES ($1, $2, ${expiresAtQuery})`,
            [userId, code]
        );

        try{
            await sendVerificationEmail(email, code);
        }catch(emailError){
            console.error(`CRITICAL: Rolling back transaction.
                Failed to send verification email AFTER code generation:`, emailError);
            throw new Error('EmailServiceError');
        }

        await client.query('COMMIT');

        return res.status(201).json({ message: 'Registration successful. Please check your email to verify your account.' });

    } catch (err) {
        if(client){
            await client.query('ROLLBACK').catch(rollbackErr => {
                console.error('Rollback failed on register:', rollbackErr);
            });
        }

        console.error('Registration error or bcrypt error:', err.stack);

        if(err.message === 'EmailServiceError'){
            return res.status(500).json({
                error: 'We could not send a verification email at this time. Please try again later.'
            });
        }

        if (err.code === PG_ERROR_CODES.UNIQUE_VIOLATION && err.constraint == 'users_email_key') {
            return res.status(409).json({ error: 'This email address is already registered.' });
        }

        return res.status(500).json({ error: 'Internal server error during registration process.' });
    } finally {
        if(client){
            client.release();
        }
    }
});

app.get('/api/verify-email', async (req, res) => {
    const { code } = req.query;

    if(!code){
        // TODO: render error page
        return res.status(400).send('<h1>Error: Verification code is missing.</h1>');
    }

    let client;
    try{
        client = await pool.connect();

        const verificationResult = await client.query(
            'SELECT user_id, expires_at FROM email_verifications WHERE code = $1',
            [code]
        );

        if(verificationResult.rows.length === 0){
            return res.status(400).send('<h1>Verification Failed</h1><p>Invalid verification code.</p>');
        }
        const verificationRecord = verificationResult.rows[0];

        const expirationTime = new Date(verificationRecord.expires_at);
        if(Date.now() > expirationTime.getTime()){
            await client.query(
                'DELETE FROM email_verifications WHERE user_id = $1', 
                [verificationRecord.user_id]
            );
            return res.status(400).send('<h1>Verification Failed</h1><p>This verification link has expired. Please request a new one.</p>');
        }

        await client.query('BEGIN');

        await client.query(
            'UPDATE users SET email_verified = true WHERE id = $1',
            [verificationRecord.user_id]
        );

        const userResult = await client.query(
            'SELECT id, email FROM users WHERE id = $1',
            [verificationRecord.user_id]
        );
        const user = userResult.rows[0];

        if(!user){
            await client.query('ROLLBACK');
            return res.status(404).send('<h1>Error</h1><p>Could not find user associated with this verification code.</p>');
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

        await client.query(
            'UPDATE users SET refresh_token = $1 WHERE id = $2',
            [refreshToken, user.id]
        );

        await client.query(
            'DELETE FROM email_verifications WHERE user_id = $1',
            [verificationRecord.user_id]
        );

        await client.query('COMMIT');

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: SEVEN_DAYS_IN_MS
        });

        const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
        return res.redirect(`${frontendUrl}/login-success?token=${accessToken}`);
    }catch(err){
        if(client){
            await client.query('ROLLBACK').catch(rollbackErr => {
                console.error('Rollback failed:', rollbackErr);
            });
        }
        console.error("Database error during email verification:", err.stack);
        return res.status(500).send(`<h1>Error</h1><p>An internal server error occurred.</p>`);
    }finally{
        if(client){
            client.release();
        }
    }
});

app.post('/api/resend-verification', async (req, res) => {
    const { email } = req.body;
    if(!email){
        return res.status(400).json({ error: 'Email is required.' });
    }

    let client;
    try {
        client = await pool.connect();

        const userResult = await client.query(
            'SELECT id, email_verified FROM users WHERE email = $1',
            [email]
        );
        const user = userResult.rows[0];
        if(!user){
            return res.status(200).json({ 
                message: 'If an account with this email exists, a new verification link has been sent.'
            });
        }

        if(user.email_verified){
            return res.status(400).json({ error: 'This email has already been verified. Please log in.' });
        }

        await client.query('BEGIN');

        await client.query(
            'DELETE FROM email_verifications WHERE user_id = $1',
            [user.id]
        );

        const code = uuidv4();
        const expiresAtQuery = `NOW() + INTERVAL '${EMAIL_VERIFICATION_EXPIRATION_MINUTES} minutes'`;
        await client.query(
            `INSERT INTO email_verifications (user_id, code, expires_at) VALUES ($1, $2, ${expiresAtQuery})`,
            [user.id, code]
        );

        try{
            await sendVerificationEmail(email, code);
        }catch(emailError){
            console.error(`CRITICAL: Rolling back transaction.
                Failed to resend verification email AFTER code generation:`, emailError);
            throw new Error('EmailServiceError');
        }

        await client.query('COMMIT');

        return res.status(200).json({ message: 'A new verification link has been sent to your email. '});

    }catch(err){
        if(client){
            await client.query('ROLLBACK').catch(rollbackErr => {
                console.error('Rollback failed on resend-verification:', rollbackErr);
            });
        }

        console.error('Resend verification error:', err.stack);

        if(err.message === 'EmailServiceError'){
            return res.status(500).json({
                error: 'We could not send a verification email at this time. Please try again later.'
            });
        }

        return res.status(500).json({ error: 'Internal server error' });
    }finally{
        if(client){
            client.release();
        }
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = userResult.rows[0];
        if(!user || !(await bcrypt.compare(password, user.password_hash))){
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

        await pool.query('UPDATE users SET refresh_token = $1 WHERE id = $2', [refreshToken, user.id]);

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

app.post('/api/refresh-token', async (req, res) => {
    const oldRefreshToken = req.cookies.refreshToken;

    if(!oldRefreshToken){
        return res.status(401).json({
            code: 'REFRESH_TOKEN_MISSING',
            error: 'No refresh token provided.'
        });
    }

    let client;
    try{
        client = await pool.connect();

        const userResult = await client.query(
            'SELECT * FROM users WHERE refresh_token = $1',
            [oldRefreshToken]
        );
        const user = userResult.rows[0];

        if(!user){
            // User not found, but it could be an old stolen token.
            // For security, find out who this token belonged to and log them out.
            try{
                const decoded = jwt.decode(oldRefreshToken);
                if (decoded && decoded.id) {
                    console.warn(`SECURITY ALERT: A potentially compromised or reused refresh token was presented
                        for user ID: ${decoded.id}. Invalidating all sessions for this user.`);
                    await client.query('UPDATE users SET refresh_token = NULL WHERE id = $1', [decoded.id]);
                }
            }catch(decodeError){
                console.error("Could not decode the invalid refresh token:", decodeError);
            }

            res.clearCookie('refreshToken');
            return res.status(403).json({ error: 'Forbidden' });
        }

        let decoded;
        try {
            decoded = jwt.verify(oldRefreshToken, process.env.REFRESH_TOKEN_SECRET);
        }catch(err){
            console.warn(`SECURITY: Invalidating session for user ID: ${user.id} due to invalid refresh token.`);
            await client.query('UPDATE users SET refresh_token = NULL WHERE id = $1', [user.id]);
            res.clearCookie('refreshToken');
            return res.status(403).json({ error: 'Forbidden' });
        }

        if(user.id !== decoded.id){
            console.warn(`SECURITY: Invalidating session for user ID: ${user.id} due to invalid refresh token.`);
            await client.query('UPDATE users SET refresh_token = NULL WHERE id = $1', [user.id]);
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

        await client.query('UPDATE users SET refresh_token = $1 WHERE id = $2', [newRefreshToken, user.id]);

        res.cookie('refreshToken', newRefreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: SEVEN_DAYS_IN_MS
        });

        return res.status(200).json({ token: newAccessToken });
    }catch(err){
        console.error("Database error during token refresh:", err.stack);
        return res.status(500).json({ error: 'Internal server error' });
    }finally{
        if(client){
            client.release();
        }
    }
});

app.post('/api/logout', async (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    try{
        if(refreshToken){
            await pool.query('UPDATE users SET refresh_token = NULL WHERE refresh_token = $1', [refreshToken]);
        }
        res.clearCookie('refreshToken');
        return res.status(200).json({ message: 'Logout successful.' });
    }catch(err){
        console.error("Database error during logout:", err.stack);

        // If we fail to clear database refresh_token, we can still clear cookie and logout frontend
        res.clearCookie('refreshToken');
        return res.status(200).json({ error: 'Logout successful' });
    }
});


// Protected Routes
app.post('/api/mc-username', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const { mc_username } = req.body;
    const ACCOUNT_LINK_LIMIT = 3;

    if(!mc_username){
        return res.status(400).json({ error: 'Missing Minecraft username' });
    }

    let client;
    try {
        client = await pool.connect();

        await client.query(
            `DELETE FROM minecraft_verification_codes WHERE user_id = $1 AND expires_at < NOW()`,
            [userId]
        );

        const existingCodeResult = await client.query(
            `SELECT
                vc.code, vc.expires_at, ma.mc_username
             FROM
                minecraft_verification_codes vc
             JOIN minecraft_accounts ma ON vc.minecraft_account_id = ma.id
             WHERE vc.user_id = $1`,
            [userId]
        );

        if(existingCodeResult.rows.length > 0){
            const { code, mc_username: existingMcUsername } = existingCodeResult.rows[0];
            console.log(`User ${userId} already has an active code for ${existingMcUsername}.`);
            return res.status(200).json({
                message: `
                    You already have an active verification code (${code}) for "${existingMcUsername}". Please use it.`,
                code: code
            });
        }

        const profile = await getMinecraftProfile(mc_username);
        if(!profile){
            return res.status(400).json({ error: 'Minecraft username does not exist' });
        }

        // Check if minecraft UUID is verified by someone else
        const otherUserResult = await client.query(
            'SELECT user_id FROM minecraft_accounts WHERE mc_uuid = $1 AND is_verified = true AND user_id != $2',
            [profile.uuid, userId]
        );
        if(otherUserResult.rows.length > 0){
            return res.status(409).json({ error: 'This Minecraft account is already linked and verified by another user.' });
        }

        await client.query('BEGIN');

        // Check if current user already linked minecraft UUID
        const existingLinkResult = await client.query(
            'SELECT id, is_verified, mc_username FROM minecraft_accounts WHERE user_id = $1 AND mc_uuid = $2',
            [userId, profile.uuid]
        );
        const existingLink = existingLinkResult.rows[0];

        let minecraftAccountId;

        // Relinking existing account. Does NOT have to be verified.
        if(existingLink){
            console.log(`User ${userId} is re-linking an existing account: ${profile.name}`);
            minecraftAccountId = existingLink.id;

            if(existingLink.mc_username !== profile.name){
                await client.query(
                    'UPDATE minecraft_accounts SET mc_username = $1 WHERE id = $2',
                    [profile.name, minecraftAccountId]
                );
                console.log(`Updated username for minecraft account ID ${minecraftAccountId} to ${profile.name}`);
            }

            if(existingLink.is_verified){
                await client.query('COMMIT');
                return res.status(200).json({
                    message: 'You have already verified this account. The username has been updated if it changed.'
                });
            }
            console.log(`User ${userId} is re-requesting verification for existing link: ${profile.name}`);
        }else{ // Linking a new account.
            const countResult = await client.query(
                'SELECT COUNT(id) as count FROM minecraft_accounts WHERE user_id = $1',
                [userId]
            );
            if(parseInt(countResult.rows[0].count, 10) >= ACCOUNT_LINK_LIMIT){
                await client.query('ROLLBACK'); 
                return res.status(403).json({
                    error: `You have reached the maximum limit of ${ACCOUNT_LINK_LIMIT} unique Minecraft accounts.`
                });
            }

            const newAccountResult = await client.query(
                `INSERT INTO minecraft_accounts (user_id, mc_uuid, mc_username) VALUES ($1, $2, $3) RETURNING id`,
                [userId, profile.uuid, profile.name]
            );
            minecraftAccountId = newAccountResult.rows[0].id;
            console.log(`User ${userId} is linking a new account: ${profile.name}`);
        }

        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAtQuery = `NOW() + INTERVAL '${MC_CODE_EXPIRATION_MINUTES} minutes'`;
        await client.query(
            `INSERT INTO minecraft_verification_codes
                (user_id, minecraft_account_id, code, expires_at)
             VALUES
                ($1, $2, $3, ${expiresAtQuery})`,
            [userId, minecraftAccountId, verificationCode]
        );

        await client.query('COMMIT');

        return res.status(200).json({
            message: `Minecraft username ${profile.name} linked. Please use the following code in-game to verify:`,
            code: verificationCode
        });

    } catch (err) {
        if(client){
            await client.query('ROLLBACK').catch(rollbackErr => {
                console.error('Rollback failed on mc-username:', rollbackErr);
            });
        }
        console.error('Error in /api/mc-username:', err.message);
        if(err.code === PG_ERROR_CODES.UNIQUE_VIOLATION){
            return res.status(409).json({ error: 'You have already linked this Minecraft account.' });
        }
        return res.status(500).json({ error: 'Internal server error.' });
    }finally{
        if(client){
            client.release();
        }
    }
});

app.get('/api/account-status', authenticateToken, async (req, res) => {
    const userId = req.user.id;

    try{
        const accountsResult = await pool.query(
            `SELECT id, mc_uuid, mc_username, is_verified
             FROM minecraft_accounts
             WHERE user_id = $1
             ORDER BY linked_at DESC`,
             [userId]
        );

        const codeResult = await pool.query(
            `SELECT
                vc.code,
                vc.expires_at,
                ma.mc_username
            FROM minecraft_verification_codes vc
            JOIN minecraft_accounts ma ON vc.minecraft_account_id = ma.id
            WHERE vc.user_id = $1 AND vc.expires_at > NOW()`,
            [userId]
        );

        res.status(200).json({
            linked_accounts: accountsResult.rows,
            active_verification: codeResult.rows[0] || null
        });
    }catch(error){
        console.error('Error fetching account status:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/internal/mc-verify', authenticateInternalService, async (req, res) => {
    const { code, mc_uuid } = req.body;

    if(!code || !mc_uuid){
        return res.status(400).json({ error: 'Missing verification code or Minecraft UUID.' });
    }

    let client;
    try{
        client = await pool.connect();
        const codeResult = await client.query(
            `SELECT
                vc.id AS code_id,
                vc.expires_at,
                ma.id AS minecraft_account_id,
                ma.mc_username
            FROM minecraft_verification_codes vc
            JOIN minecraft_accounts ma ON vc.minecraft_account_id = ma.id
            WHERE vc.code = $1 AND ma.mc_uuid = $2`,
            [code, mc_uuid]
        );

        if(codeResult.rows.length === 0){
            return res.status(404).json({ error: 'Invalid verification code for this player.' });
        }

        const { code_id, expires_at, minecraft_account_id, mc_username } = codeResult.rows[0];
        if(Date.now() > new Date(expires_at).getTime()){
            await client.query('DELETE FROM minecraft_verification_codes WHERE id = $1', [code_id]);
            console.log(`Deleted expired verification code ${code} for mc_uuid ${mc_uuid}`);
            return res.status(410).json({
                error: 'This verification code has expired. Please request a new one from the portal.'
            });
        }

        await client.query('BEGIN');

        await client.query(
            'UPDATE minecraft_accounts SET is_verified = true WHERE id = $1',
            [minecraft_account_id]
        );

        const deleteResult = await client.query(
            'DELETE FROM minecraft_accounts WHERE mc_uuid = $1 AND is_verified = false',
            [mc_uuid]
        );
        if(deleteResult.rowCount > 0){
            console.log(`Cleaned up ${deleteResult.rowCount} conflicting unverified link(s) for mc_uuid ${mc_uuid}.`);
        }

        await client.query('DELETE FROM minecraft_verification_codes WHERE id = $1', [code_id]);

        await client.query('COMMIT');

        return res.status(200).json({ message: `Successfully verified Minecraft account: ${mc_username}.` });
    }catch(err){
        if(client){
            await client.query('ROLLBACK').catch(rollbackErr => {
                console.error('Rollback failed on mc-verify:', rollbackErr);
            });
        }
        console.error('Error in /api/internal/mc-verify:', err.stack);
        if(err.code === PG_ERROR_CODES.UNIQUE_VIOLATION){
            return res.status(409).json({ error: 'This Minecraft account was just verified by another user.' });
        }
        return res.status(500).json({ error: 'Internal server error.' });
    }finally{
        if(client){
            client.release();
        }
    }
});

const ACTUAL_PORT = process.env.PORT || 3000;

app.listen(ACTUAL_PORT, () => {
    console.log(`Server running on http://localhost:${ACTUAL_PORT}`);
});