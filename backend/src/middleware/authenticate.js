const jwt = require('jsonwebtoken');

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

module.exports = {
    authenticateToken,
    authenticateInternalService
};
