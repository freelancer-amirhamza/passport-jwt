const express = require('express');
const app = express();
const cors = require("cors")
const passport =require("passport");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const saltRounds = 10;
require('./config/database');

const User = require('./models/user.model');
require('dotenv').config();



app.use(cors());
app.use(express.urlencoded({extended:true}));
app.use(express.json());
app.use(passport.initialize());
require("./config/passport");

app.get("/", (req, res) => {
    res.send(`<h1>Welcome to Home Page</h1>`)
})

// Register Route

app.post("/register", async (req, res) => {
    try {
        const user = await User.findOne({username: req.body.username});
    if(user) return res.status(400).send(`<h2>User Already existed</h2>`);
    bcrypt.hash( req.body.password, saltRounds, 
        async(err, hash) => {
        const newUser = new User({
            username: req.body.username,
            password:hash,
        })
        await newUser.save().then((user)=>{
            res.send({
                success: true,
                message: "User is created successfully",
                user: {
                    id: user._id,
                    username: user.username,
                }
            })   
        }).catch((error)=>{
            res.send({
                success: false,
                message: "User was not created",
                error: error.message,
            })
        })
    });
    } catch (error) {
        res.status(500).send(error.message);
    };  
});


// Login Route   
app.post("/login", async(req, res)=>{
    const user = await User.findOne({username: req.body.username});
    if(!user){
        return res.status(401).send({
            success:false,
            message: "User is not Found"
        })
    }
    bcrypt.compare(req.body.password, user.password, (err, isMatch) => {
        if (err) return res.status(500).send({ success: false, message: err.message });
        if (!isMatch) return res.status(401).send({ success: false, message: "Incorrect Password" });
    
        const payload = {
            id: user._id,
            username: user.username,
        };
        const token = jwt.sign(payload, process.env.SECRET_KEY, { expiresIn: "2h" });
    
        return res.status(200).send({
            success: true,
            message: "User was logged in successfully",
            token: "Bearer " + token,
        });
    });
})     

// Profile Route
app.get(
    "/profile",
    passport.authenticate("jwt", { session: false }),
    (req, res) => {
      return res.status(200).send({
        success: true,
        user: {
          id: req.user._id,
          username: req.user.username,
        },
      });
    }
  );

app.use((req, res, next) =>{
    res.status(404).json({
        message: "The Route Not Found",
        success: false,
    })
})

app.use((err, req, res, next) => {
    console.error(err.stack)
    res.status(500).send('Something broke!')
  })

module.exports = app;