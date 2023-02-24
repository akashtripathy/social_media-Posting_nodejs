const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const config = require('config');
const {check,validationResult} = require('express-validator');

const User = require('../../models/User');

// @route   POST api/users
// @desc    Register User
// @access  Public
router.post('/',[
    check('name','Name is required').not().isEmpty(),
    check('email',"Enter a valid email").isEmail(),
    check('password',"Please enter a password with more than 5 characters").isLength({min:6})
],
async(req,res)=> {
    const error = validationResult(req);
    if(!error.isEmpty()){
        return res.status(400).json({error: error.array()});
    }
    
    const { name, email, password}= req.body;

    try {
        // See if user exists
        let user = await User.findOne({email});

        if(user){
          return res.status(400).json({errors: [{msg: 'User already exist'}]});
        }

        // Get users gravator
        const avatar = gravatar.url(email,{
            s: '200',
            r: 'pg',
            d: 'mm'
        });

        user = new User({
            name,
            email,
            avatar,
            password
        });

        // Encrypt Password
        const salt = await bcrypt.genSalt(10);

        user.password = await bcrypt.hash(password,salt);

        await user.save();

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