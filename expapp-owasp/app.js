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
      rateLimit            = require("express-rate-limit"),
      xss                  = require("xss-clean"),
      helmet               = require("helmet");


//Connecting database
mongoose.connect("mongodb://localhost/auth_demo");

//Core
app.use(express.json({ limit: '10kb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10kb' }));

/* app.use(expSession({
    secret:"mysecret",       //decode or encode session
    resave: false,          
    saveUninitialized:false
})) */

//session 
app.use(expSession({
  secret: "mysecret",
  resave: false,
  saveUninitialized: true,   // true
  cookie: {
    httpOnly: true,
    secure: false,          
    maxAge: 10 * 60 * 1000   // 10 minutes
  }
}));

//Passport Configuration
passport.serializeUser(User.serializeUser());       //session encoding
passport.deserializeUser(User.deserializeUser());   //session decoding
passport.use(new LocalStrategy(User.authenticate()));
app.set("view engine","ejs");
// app.use(bodyParser.urlencoded(
//       { extended:true }
// ))
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static("public"));


//=======================
//      O W A S P
//=======================
//Data Sanitization against NoSQL Injection Attacks
app.use(mongoSanitize());

// Prevent XSS attacks
app.use(xss());

// Secure HTTP headers
app.use(helmet());

// Prevent Brute Force & DOS Attacks
const loginLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 100,                // limit each IP to 100 requests per window
    message: "Too many requests, please try again later."
});

// Rate limiting 
app.use("/login", loginLimiter);
app.use("/register", loginLimiter);

// Static files
app.use(express.static("public"));


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
app.get("/register",(req,res)=>{
    res.render("register");
});

app.post("/register", async (req, res) => {
  try {
    const user = await User.register(
      new User({
        username: req.body.username,
        email: req.body.email,
        phone: req.body.phone
      }),
      req.body.password
    );

    passport.authenticate("local")(req, res, function () {
      res.redirect("/login");
    });

  } catch (err) {
    console.log(err);
    return res.render("register");
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