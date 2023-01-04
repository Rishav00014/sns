//jshint esversion:6
//http://localhost:3000/auth/google/secrets
require('dotenv').config();
const express =require("express")
const bodyParser =require("body-parser")
const ejs =require("ejs")
const mongoose=require("mongoose")
//security and authentication part 
const session =require("express-session")
const passport =require("passport")
const passportLocalMongoose =require("passport-local-mongoose")
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate=require("mongoose-findorcreate")
//const encrypt =require("mongoose-encryption")
//const md5=require("md5")
//const bcrypt =require("bcrypt")
const app = express()

const PORT =3000;
app.set('view engine', 'ejs');
app.use(express.static("public"))
app.use(bodyParser.urlencoded({extended:true}));
app.use(session({
    secret:"Our Little Secrete",
    resave:false,
    saveUninitialized:false
}))
app.use(passport.initialize())
app.use(passport.session())

mongoose.connect("mongodb://localhost:27017/userDB")
const userSchema =new mongoose.Schema({
    username:String,
    password:String,
    googleId:String,
    secret:String
});
userSchema.plugin(passportLocalMongoose)
userSchema.plugin(findOrCreate)
//encriprion is the process of converting normal text into enrypted text
//with the help of key and vise versa 
//it is mathamatical easy to convert encripted txt to normal
//or vise versa
//although it is easy to hacker to break security 
//and get the key 

//we should use hashing instied of encription to increase security
//hashing is mathamatical complex way to convert hash to tex
//and easy to convert text to hash
//eg hash=1*5*5*31*29
//but revrsing and finding factor is quite complex

//userSchema.plugin(encrypt,{secret:process.env.SECRET ,encryptedFields:['password']})
const User =new mongoose.model("User",userSchema)
// here password process
//user pasword ---->hash ----> encrypt --->store
//for login
//user password --->hash
//fetch storage -->decrypt == hash 
//compare hash
passport.use(User.createStrategy())
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
});
  
passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    scope: ['profile', 'email'],
    callbackURL: "http://localhost:3000/auth/google/secrets"
    
},
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/",(req,res)=>{
    res.render("home");
})
app.get("/auth/google",
    passport.authenticate("google",{scope:["profile"]})
)
app.get("/auth/google/secrets",
    passport.authenticate("google",{failureRedirect:"/login"}),
    (req,res)=>{
        res.redirect("/secrets")
    }
)
app.get("/login",(req,res)=>{
    res.render("login");
})
app.get("/register",(req,res)=>{
    res.render("register");
})
app.get("/secrets",(req,res)=>{
    if(req.isAuthenticated()){
        User.find({"secret":{$ne:null}},(err,foundUsers)=>{
            if(err){
                console.log(err)
            }else{
                if(foundUsers){
                    res.render("secrets",{userWithSecrets:foundUsers})
                }
            }
        })
    }else{
        res.redirect("/login")
    }
})
app.get("/submit",(req,res)=>{
    if(req.isAuthenticated()){
        res.render("submit")
    }else{
        res.redirect("/login")
    }
})
app.get("/logout",(req,res)=>{
    req.logout((err)=>{
        if(!err){
            res.redirect("/")      
        }
    })
})
app.post("/submit",(req,res)=>{
    const submittedSecret =req.body.secret;
    User.findById(req.user.id,(err,foundUser)=>{
        if(err){
            console.log(err);
        }else{
            if(foundUser){
                foundUser.secret=submittedSecret;
                foundUser.save(()=>{
                    res.redirect("/secrets")
                })
            }
        }
    })
})
app.post("/register",(req,res)=>{
    User.register({username:req.body.username},req.body.password,(err,user)=>{
        if(err){
            res.redirect("/register")
        }else{
            passport.authenticate("local")(req,res,()=>{
                res.redirect("/secrets")
            })
        }
    })
    /*
    bcrypt.hash(req.body.password,10,(err,hash)=>{
        const newUser =new User({
            email: req.body.username,
            password: hash
        })
        newUser.save((err)=>{
            if(err){
                console.log(err);
            }else{
                res.render("secrets")
            }
        });
    })
    */
})
app.post("/login",(req,res)=>{
    const user =new User({
        username: req.body.username,
        password: req.body.password
    })
    req.login(user,(err)=>{
        if(err){
            console.log(err);
        }else{
            passport.authenticate("local")(req,res,()=>{
                res.redirect("/secrets")
            }) 
        }
    })
    /*
    const password= req.body.password
    const username= req.body.username
    User.findOne({email: username},(err,foundUser)=>{
        if(err){
            console.log(err)
        }else{
            if(foundUser){
                bcrypt.compare(password,foundUser.password,(err,result)=>{
                    if(!err){
                        if(result){
                            res.render("secrets")
                        }else{
                            res.send("incorrect password")
                        }
                    }else{
                        console.log(err)
                        res.send("Server is bussy")
                    }
                })
            }else{
                res.send("not found")
            }
        }
    })
    */
})

app.listen(PORT,()=>{
    console.log("Server is up and running");
})