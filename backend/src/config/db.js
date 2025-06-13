const { Pool } = require('pg');

const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

pool.query('SELECT NOW()', (err, res) => {
    if(err){
        console.error('Error connecting to PostgreSQL database', err.stack);
    }else{
        console.log('Successfully connected to PostgreSQL database.');
    }
})

module.exports = pool;
