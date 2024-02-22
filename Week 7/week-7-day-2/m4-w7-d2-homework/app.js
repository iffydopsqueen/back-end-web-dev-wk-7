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

const { check, validationResult } = require('express-validator');

//Connecting database
mongoose.connect("mongodb://localhost/auth_demo");

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
app.get("/register", (req, res) => {
    res.render("register", { errors: null }); // You can initialize errors to null if there are no errors initially
});

app.post("/register", 
    [
        check('username').isLength({ min: 1 }).withMessage('Please enter a username'), // Validation for username
        check('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'), // Validation for password
        check('email').isLength({ min: 1 }).withMessage('Please enter an email'),
        check('phone').isLength({ min: 10, max: 10 }).withMessage('Please enter a 10-digit phone number'),
    ],

    async (req, res) => {
        try {
            const errors = validationResult(req);

            if (!errors.isEmpty()) {
                return res.render("register", { errors: errors.array() });
            }

            const user = new User({ username: req.body.username, email: req.body.email, phone: req.body.phone });
            await User.register(user, req.body.password);

            passport.authenticate("local")(req, res, function () {
                res.redirect("/login");
            });
        } catch (err) {
            console.error(err);
            res.render("register", { errors: [{ msg: "An error occurred during registration" }] });
        }
    }
);

app.get("/logout",(req,res) => {
    req.logout(() => {
        res.redirect("/");
    });
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