const express               =  require('express'),
      expSession            =  require("express-session"),
      app                   =  express(),
      mongoose              =  require("mongoose"),
      passport              =  require("passport"),
      bodyParser            =  require("body-parser"),
      LocalStrategy         =  require("passport-local"),
      passportLocalMongoose =  require("passport-local-mongoose"),
      User                  =  require("./models/user"),
      mongoSanitize         = require("express-mongo-sanitize"),
      rateLimit             = require("express-rate-limit"),
      xss                   = require("xss-clean"),
      helmet                = require("helmet");

// Add express-validator for input validation
const { body, validationResult } = require('express-validator');

//Connecting database
mongoose.connect("mongodb://127.0.0.1/auth_demo");

app.use(expSession({
    secret:"mysecret",       //decode or encode session
    resave: false,          
    saveUninitialized:true,
    cookie: {
        httpOnly: true,
        secure: true,
        maxAge: 1 * 60 * 1000  // 10 minutes
    }
}))

passport.serializeUser(User.serializeUser());       //session encoding
passport.deserializeUser(User.deserializeUser());   //session decoding
passport.use(new LocalStrategy(User.authenticate()));
app.set("view engine","ejs");
app.use(bodyParser.urlencoded(
      { extended:true }
))
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static("public"));

// Validation middleware

const validateSignup = [
    body('username')
        .notEmpty().withMessage('Username is required')
        .isLength({ min: 5 }).withMessage('Username must be at least 5 characters long'),
    body('password')
        .notEmpty().withMessage('Password is required')
        .isStrongPassword().withMessage('Password must be strong'),
];


//=======================
//      O W A S P
//=======================

// Data Sanitization against NoSQL injection attacks 
app.use(mongoSanitize());

// Preventing Brute force & DOS attacks - Rate limiting
const limit = rateLimit({
    max: 100,    // max requests
    windowMs: 60 * 60 * 1000,   // 1 hour of 'ban' / lockout
    message: 'Too many requests'    // message to send 
});

app.use('/routeName', limit);    // setting limiter on specific route 

// Preventing DOS attacks - Body Parser 
app.use(express.json({ limit: '10kb' }));   // body limit is 10

// Data Sanitization against DOS attacks 
app.use(xss());

// Helmet to secure connection and data 
app.use(helmet());

//=======================
//      R O U T E S
//=======================
app.get("/", (req,res) =>{
    res.render("home");
})
app.get("/userprofile" ,(req,res) =>{
    res.render("userprofile");
})
//Auth Routes
app.get("/login",(req,res)=>{
    res.render("login");
});
app.post("/login",passport.authenticate("local",{
    successRedirect:"/userprofile",
    failureRedirect:"/login"
}),function (req, res){
});
app.get("/register",(req,res) => {
    res.render("register", { errors: {} });
});

app.post("/register", validateSignup, (req,res) => {
    const errors = validationResult(req);

    // If there are validation errors or if the form is submitted empty
    if (!errors.isEmpty() || Object.keys(req.body).length === 0) {
        const errorMessages = errors.array().reduce((acc, cur) => {
            acc[cur.param] = cur.msg;
            return acc;
        }, {});
        res.render("register", { errors: errorMessages });
    } else {
        User.register(new User({username: req.body.username,email: req.body.email,phone: req.body.phone}), req.body.password, function(err,user) {
            if(err){
                console.log(err);
                res.render("register");
            }
            passport.authenticate("local")(req, res, function() {
                res.redirect("/login");
            })    
        })
    }  
});
app.get("/logout",(req,res)=>{
    req.logout();
    res.redirect("/");
});
function isLoggedIn(req,res,next) {
    if(req.isAuthenticated()){
        return next();
    }
    res.redirect("/login");
}

//Listen On Server
app.listen(process.env.PORT || 3000,function (err) {
    if(err){
        console.log(err);
    }else {
        console.log("Server Started At Port 3000");  
    }
});