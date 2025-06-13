const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env')});

const moduleAlias = require('module-alias');
moduleAlias.addAliases({
  '@': path.join(__dirname, 'src')
});

const express = require('express')
const cors = require('cors');
const helmet = require('helmet')
const cookieParser = require('cookie-parser');
// const { Rcon: rcon } = require('rcon-client').Rcon; // TODO: Use when Minecraft

const { setupDatabase } = require('@/utils/dbSetup');
const authRoutes = require('@/routes/authRoutes');
const minecraftRoutes = require('@/routes/minecraftRoutes');
const internalRoutes = require('@/routes/internalRoutes');

// Initialize Express App
const app = express();
app.set('trust proxy', 1);

// TODO: process.env.JWT_SECRET use Kubernetes Secrets
// TODO: Environment validation of dotenv

// Core Middleware
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

// Mount Routers
app.use('/api', authRoutes);
app.use('/api', minecraftRoutes);
app.use('/api/internal', internalRoutes);


const startServer = async () => {
    try{
        // Try starting database
        console.log('Connecting to database and setting up schema...');
        await setupDatabase();

        console.log('Database setup successful.');

        const ACTUAL_PORT = process.env.PORT || 3000;
        app.listen(ACTUAL_PORT, () => {
            console.log(`Server running on http://localhost:${ACTUAL_PORT}`);
        });
    }catch(error){
        console.error('CRITICAL: Failed to set up database on startup. Application will exit.', error);
        process.exit(1);
    }
};

// Server Start
startServer();