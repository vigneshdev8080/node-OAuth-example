const fs = require("fs");
const path = require("path");
const https = require("https");
const helmet = require("helmet");
const express = require("express");
const passport = require("passport");
const { Strategy } = require("passport-google-oauth20");
const cookieSession= require("cookie-session");

require("dotenv").config();


const config = {
    CLIENT_SECRET: process.env.CLIENT_SECRET,
    CLIENT_ID: process.env.CLIENT_ID,
    COOKIE_KEY1:process.env.COOKIE_KEY1,
    COOKIE_KEY2:process.env.COOKIE_KEY2,
}

const auth_options = {
    callbackURL: "/auth/google/callback",
    clientID: config.CLIENT_ID,
    clientSecret: config.CLIENT_SECRET
}

const checkLoggedIn = (req, res, next) => {
    const isLoggedIn = req.isAuthenticated()&&req.user;
    if (!isLoggedIn) {
        res.status(401).json({ error: "You must be logged in" })
    }
    next();
}


const verifyCallback = (accessToken, refreshToken, profile, done) => {
    console.log("🚀 ~ file: server.js:35 ~ verifyCallback ~ refreshToken:", refreshToken)
    console.log("🚀 ~ file: server.js:35 ~ verifyCallback ~ accessToken:", accessToken)
    console.log("Google Profile", profile);
    done(null, profile);
}

passport.use(new Strategy(auth_options, verifyCallback))
passport.serializeUser((user,done)=>{
    done(null, user.id);
});
passport.deserializeUser((data,done)=>{
    done(null, data);
})


const app = express();
app.use(helmet());

app.use(cookieSession({
    name:"secure-session",
    maxAge:24*60*60*1000,
    keys:[config.COOKIE_KEY1,config.COOKIE_KEY2]
}))

app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
    res.status(200).sendFile(path.join(__dirname, "public", "index.html"));
})

app.get("/get_secret", checkLoggedIn, (req, res) => {
    res.status(200).json({ message: "Here is your secret key!" });
})


app.get("/auth/google",passport.authenticate('google',{
    scope:['email','profile']
}))

app.get("/auth/google/callback", passport.authenticate('google', { 
    failureRedirect: "/failure",
    successRedirect: "/",
    session: true
}), (req, res) => {
    console.log("Google called back");
})

app.get("/failure",(req, res) => {
    console.log("Failed to Login");
})

app.get("/auth/logout", (req, res) => {
    req.logout()
    return res.redirect("/")
 })

https.createServer({
    key: fs.readFileSync("key.pem"),
    cert: fs.readFileSync("cert.pem"),
}, app).listen(process.env.PORT, () => {
    console.log("Listening on port", process.env.PORT);
})