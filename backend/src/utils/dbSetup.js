const pool = require('@/config/db')

async function setupDatabase(){
    const client = await pool.connect();
    try{
        await client.query(`
            -- Stores the main portal accounts
            CREATE TABLE IF NOT EXISTS users(
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                access_tier TEXT NOT NULL DEFAULT 'standard',
                email_verified BOOLEAN DEFAULT false,
                approved BOOLEAN DEFAULT true,
                refresh_token TEXT,
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

module.exports = { setupDatabase };
