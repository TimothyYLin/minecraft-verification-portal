const express = require('express');
const router = express.Router();

const pool = require('@/config/db');
const { authenticateInternalService } = require('@/middleware/authenticate');
const { PG_ERROR_CODES } = require('@/config/constants');

// POST /api/internal/mc-verify
router.post('/mc-verify', authenticateInternalService, async (req, res) => {
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

module.exports = router;
