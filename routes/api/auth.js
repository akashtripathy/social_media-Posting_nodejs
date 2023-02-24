const express = require('express');
const router = express.Router();
const {check,validationResult} = require('express-validator');
const config = require('config');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const auth = require('../../middleware/auth');

const User = require('../../models/User')

// @route   GET api/auth
// @desc    Get User
// @access  Public
router.get('/', auth , async (req,res)=> {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// @route   POST api/auth
// @desc    Authenticatre user & get token
// @access  Public
router.post('/',[
    check('email',"Enter a valid email").isEmail(),
    check('password',"Password is required").exists()
],
async(req,res)=> {
    const error = validationResult(req);
    if(!error.isEmpty()){
        return res.status(400).json({error: error.array()});
    }
    
    const { email, password}= req.body;

    try {
        // See if user credential is valid or not
        let user = await User.findOne({email});

        if(!user){
          return res.status(400).json({errors: [{msg: 'Invalid Credentials'}]});
        }

        const isMatch = await bcrypt.compare(password,user.password);

        if(!isMatch){
            return res.status(400).json({error: [{msg: 'Invalid Credentials'}]});
        }

        // Return jsonwebtoken
        const payload = {
            user: {
                id: user.id
            }
        }
        jwt.sign(
            payload, 
            config.get('jwtSecret'),
            {expiresIn: 360000},
            (err,token)=>{
                if(err) throw err;
                res.json({token});
            }
        );

        // res.send('User registered');
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }

}
);

module.exports = router;