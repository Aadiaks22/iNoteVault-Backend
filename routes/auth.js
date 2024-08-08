const express = require('express');
const User = require('../models/User');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken');
var fetchuser = require('../middleware/fetchuser');

const JWT_SECRET = 'ADITYAISAGOODB$OY';

//Route 1: Create a user using: POST "/api/auth/createuser". Doesn't require Auth
router.post('/createuser', [
    body('name', 'Enter a valid name').isLength({ min: 3 }),
    body('email', 'Enter a valid Email').isEmail(),
    body('password', 'Password must be at least 5 characters').isLength({ min: 5 }),
], async (req, res) => {
    let success = false;
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({success, errors: errors.array() });
    }

    try {
        // Check if a user with the same email already exists
        let user = await User.findOne({ email: req.body.email });
        if (user) {
            return res.status(400).json({success, error: "A user with this email already exists" });
        }

        // Create a new user
        const salt = await bcrypt.genSalt(10);
        const secPass = await bcrypt.hash(req.body.password, salt);
        user = new User({
            name: req.body.name,
            password: secPass,
            email: req.body.email,
        });

        await user.save();

        const data = {
            user:{
                id: user.id
            }
        }
        const authToken = jwt.sign(data, JWT_SECRET);
        success = true;
        res.json({success, authToken});
        //res.json(user);
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server Error');
    }
});

//Route 2: Authenticate a user using: POST "/api/auth/login". No login required
router.post('/login', [
    body('email', 'Enter a valid Email').isEmail(),
    body('password', 'Password Cannot be blank').exists(),
], async (req, res) => {
    let success = false
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({success, errors: errors.array() });
    }

    const {email, password} = req.body;
    try {
        // Check if a user with the same email already exists
        let user = await User.findOne({ email});
        if (!user) {
            return res.status(400).json({success, error: "Please Enter Correct Credentials" });
        }

        const passwordCompare = await bcrypt.compare(password, user.password);
        if(!passwordCompare){
            return res.status(400).json({success, error: "Please Enter Correct Credentials" });
        }
        const data = {
            user:{
                id: user.id,
                username: user.name
            }
        }
        const authToken = jwt.sign(data, JWT_SECRET);
        success = true;
        res.json({success, authToken, username: user.name});

    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server Error');
    }
});

//Route 3: Get Loggedin user details using: POST "/api/auth/getuser". login required
router.post('/getuser',fetchuser, async (req, res) => {
    // Check for validation errors
    try {
        user = req.user.id;
        const user = await User.findById(user).select("-password");
        res.send(user);
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server Error');
    }
});


module.exports = router;
