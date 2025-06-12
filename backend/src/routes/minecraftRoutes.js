const express = require('express');
const router = express.Router();

const pool = require('@/config/db');
const { getMinecraftProfile } = require('@/services/minecraftService');
const { authenticateToken } = require('@/middleware/authenticate');
const { 
    ACCOUNT_LINK_LIMIT,
    PG_ERROR_CODES, 
    MC_CODE_EXPIRATION_MINUTES 
} = require('@/config/constants');

// POST /api/mc-username
router.post('/mc-username', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const { mc_username } = req.body;

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
                    code: 'ALREADY_VERIFIED',
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

// GET /api/account-status
router.get('/account-status', authenticateToken, async (req, res) => {
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

module.exports = router;
