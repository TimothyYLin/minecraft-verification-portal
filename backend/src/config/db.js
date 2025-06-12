const { Pool } = require('pg');

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

module.exports = pool;
