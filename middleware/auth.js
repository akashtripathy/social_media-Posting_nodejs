const jwt = require('jsonwebtoken');
const config = require('config');

module.exports = function(req,res,next){
    // Get the token from header
    const token = req.header('x-auth-token');

    // Check if no token
    if(!token){
        return res.status(401).json({msg:"No token, authentication denied"});
    }

    // Varify token
    try {
        const decode = jwt.verify(token, config.get('jwtSecret'));
        req.user = decode.user;
        next();
    } catch (err) {
        res.status(401).json({msg: 'token is not valid'});
    }
}