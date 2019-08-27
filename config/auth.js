module.exports ={
    Authentication: function (req,res,next){
    if(req.isAuthenticated()){
        return next();

    }
    req.flash('error_msg','Please login to visit Dashboard!');
    res.redirect('//users/login');
  }
}