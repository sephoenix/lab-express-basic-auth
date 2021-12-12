const {Router} = require('express');
const router = new Router();
const bcryptjs = require('bcryptjs');
const saltRounds = 20;
const User = require('../models/User.model');

router.get('/sign-up', (req, res)=>{
    res.render('auth/sing-up')
})

router.get('/userProfile', (req, res)=>{
  res.render('users/user-profile')
});

router.post('/sing-up', (req, res, next)=>{
    const { username, password} = req.body;
    bcryptjs
    .genSalt(saltRounds)
    .then(salt => bcryptjs.hash(password, salt))
    .then(hashedPassword => {
      console.log(`Password hash: ${hashedPassword}`);
      return User.create({
        username,
        password: hashedPassword
      })
    })
    .then(userFromDB=>{
      console.log(`New user ${userFromDB} is created`);
      res.redirect('/userProfile')
    })
    .catch(error => next(error));
})

module.exports = router;