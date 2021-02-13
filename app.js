//jshint esversion:6

require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const md5 = require('md5');

console.log(md5('hello'));

const app = express();

const port = process.env.PORT || 3000;

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true
});


const userSchema = new mongoose.Schema({
  email: String,
  password: String
});


// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ['password'] });


const User = new mongoose.model("User", userSchema);


app.get("/", function(req, res) {
  res.render("home");
});

app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});



app.post("/register", function(req, res) {
  const newUser = new User({
    email: req.body.username,
    password: md5(req.body.password)
  });

  newUser.save(function(err) {
    if (err) {
      console.log(err);
    } else {
      res.render("secrets");
    }
  });
});


app.post("/login", function(req, res) {
  const username = req.body.username;
  const password = md5(req.body.password);

  User.findOne({
    email: req.body.username
  }, function(err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        if (foundUser.password === password) {
          res.render("secrets");
          console.log("Logged in successfully.");
        } else {
          res.send("Nope, wrong Username or Password");
          console.log("Wrong password");
        }
      } else {
        res.send("Username or Password incorrect!")
        console.log("Not a registered user!");
      }
    }
  });
});



app.listen(port, () => {
  console.log(`Server started on port ${port}`);
});









//
