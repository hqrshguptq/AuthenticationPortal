const express = require ('express');
const router =express.Router();
const bcrypt= require('bcryptjs');
const passport=require('passport');
var async = require("async");
var nodemailer = require("nodemailer");
var crypto = require("crypto");
var Campground = require("../models/campground");


// model
const User =require('../models/User');
//Login page
router.get('/login',(req,res)=>res.render('login'));
//register page
router.get('/register',(req,res)=>res.render('register'));

//register handle
router.post('/register',(req,res)=>{
    const{ name, email, password, password2} = req.body; 

let errors=[];

//checking fields

if(!name || !email || !password || !password2){
    errors.push({msg:'Please fill in all details'});
}
//password match
if (password !== password2){
    errors.push({msg:'Passwords don\'t match'});
}
//password length
if (password.length<6)
{
    errors.push({msg:'Passwords should be atleast 6 characters'});
    
}
if (errors.length>0)
{
res.render('register',{
    errors,
    name,
    email,
    password,
    password2
});

}
else{
    //validation
    User.findOne({email:email})
    .then(user=>{
        if (user){
            //user exists
            errors.push({msg : 'Email already registered'});
            res.render('register',{
                errors,
                name,
                email,
                password,
                password2
            });
        }else{
            const newUser= new User(
                {
                    name,
                    email,
                    password
                });
             //hash password
             bcrypt.genSalt(10,(err,salt)=>
             bcrypt.hash(newUser.password,salt,(err,hash)=>{
                 if(err) throw err;
                 
                 newUser.password=hash;
                 
                 newUser.save()
                 .then(user=>{
                     req.flash('success_msg','You are successfully registered! Log in.. ');
                     res.redirect('/users/login');
                 })
                 .catch(err=>console.log(err));
             }))   
                
        }
    });
}
});

//login page
router.post('/login',(req,res,next)=> {
    passport.authenticate('local',{
        successRedirect:'/dashboard',
        failureRedirect:'/users/login',
        failureFlash:true
    })(req,res,next);
});

//logout
router.get('/logout',(req,res)=>{
    req.logout();
    req.flash('success_msg','You\'re logged out' );
    res.redirect('/users/login');
});


// forgot password
router.get('/forgot', function(req, res) {
    res.render('forgot');
  });
  
  router.post('/forgot', function(req, res, next) {
    async.waterfall([
      function(done) {
        crypto.randomBytes(20, function(err, buf) {
          var token = buf.toString('hex');
          done(err, token);
        });
      },
      function(token, done) {
        User.findOne({email:email})
        .then(user=>{
        if (!user){
            req.flash('error', 'No account with that email address exists.');
            return res.redirect('/forgot');
          }
  
          user.resetPasswordToken = token;
          user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
  
          user.save(function(err) {
            done(err, token, user);
          });
        });
      },
      function(token, user, done) {
        var smtpTransport = nodemailer.createTransport({
          service: 'Gmail', 
          auth: {
            user: 'harshneekh437@gmail.com',
            pass: process.env.GMAILPW
          }
        });
        var mailOptions = {
          to: user.email,
          from: 'harshneekh437@gmail.com',
          subject: 'Node.js Password Reset',
          text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
            'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
            'http://' + req.headers.host + '/reset/' + token + '\n\n' +
            'If you did not request this, please ignore this email and your password will remain unchanged.\n'
        };
        smtpTransport.sendMail(mailOptions, function(err) {
          console.log('mail sent');
          req.flash('success', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
          done(err, 'done');
        });
      }
    ], function(err) {
      if (err) return next(err);
      res.redirect('/users/forgot');
    });
  });
  
  router.get('/reset/:token', function(req, res) {
    User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
      if (!user) {
        req.flash('error', 'Password reset token is invalid or has expired.');
        return res.redirect('/forgot');
      }
      res.render('reset', {token: req.params.token});
    });
  });
  
  router.post('/reset/:token', function(req, res) {
    async.waterfall([
      function(done) {
        User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
          if (!user) {
            req.flash('error', 'Password reset token is invalid or has expired.');
            return res.redirect('back');
          }
          if(req.body.password === req.body.confirm) {
            user.setPassword(req.body.password, function(err) {
              user.resetPasswordToken = undefined;
              user.resetPasswordExpires = undefined;
  
              user.save(function(err) {
                req.logIn(user, function(err) {
                  done(err, user);
                });
              });
            })
          } else {
              req.flash("error", "Passwords do not match.");
              return res.redirect('back');
          }
        });
      },
      function(user, done) {
        var smtpTransport = nodemailer.createTransport({
          service: 'Gmail', 
          auth: {
            user: 'harshneekh437@gmail.com',
            pass: process.env.GMAILPW
          }
        });
        var mailOptions = {
          to: user.email,
          from: 'harshneekh437@gmail.com',
          subject: 'Your password has been changed',
          text: 'Hello,\n\n' +
            'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
        };
        smtpTransport.sendMail(mailOptions, function(err) {
          req.flash('success', 'Success! Your password has been changed.');
          done(err);
        });
      }
    ], function(err) {
      res.redirect('/dashboard');
    });
  });


module.exports = router; 
