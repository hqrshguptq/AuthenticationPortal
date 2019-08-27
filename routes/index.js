const express = require ('express');
const router =express.Router();
const {Authentication}= require('../config/auth');
//Welcome Page
router.get('/',(req,res) => res.render('welcome'));
//dashboard
router.get('/dashboard',Authentication,(req,res) => 
res.render('dashboard',{
    name:req.user.name 
}));

module.exports=router; 
