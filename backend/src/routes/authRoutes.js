const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');

const pool = require('@/config/db');
const { sendVerificationEmail } = require('@/services/emailService');
const { 
    EMAIL_VERIFICATION_EXPIRATION_MINUTES, 
    PG_ERROR_CODES, 
    ACCESS_TOKEN_EXPIRES_IN, 
    REFRESH_TOKEN_EXPIRES_IN, 
    SEVEN_DAYS_IN_MS 
} = require('@/config/constants');

// POST /api/register
router.post('/register', async (req, res) => {
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

// GET /api/verify-email
router.get('/verify-email', async (req, res) => {
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
            secure: true,
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

// POST /api/resend-verification
router.post('/resend-verification', async (req, res) => {
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

// POST /api/login
router.post('/login', async (req, res) => {
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
            secure: true,
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

// POST /api/refresh-token
router.post('/refresh-token', async (req, res) => {
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
            secure: true,
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

// POST /api/logout
router.post('/logout', async (req, res) => {
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

module.exports = router;
