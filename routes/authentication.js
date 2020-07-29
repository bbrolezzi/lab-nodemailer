const { Router } = require('express');
const router = new Router();
const nodemailer = require('nodemailer');
const User = require('./../models/user');
const bcryptjs = require('bcryptjs');

const generateRandomToken = length => {
  const characters =
    '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let token = '';
  for (let i = 0; i < length; i++) {
    token += characters[Math.floor(Math.random() * characters.length)];
  }
  return token;
};

const token = generateRandomToken(10);
//just configure it once
const transport = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.NODEMAILER_EMAIL,
    pass: process.env.NODEMAILER_PASSWORD
  }
});

const confirmationUrl = `http://localhost:3000/authentication/confirm-email?token=${token}`;

router.get('/', (req, res, next) => {
  res.render('index');
});

router.get('/sign-up', (req, res, next) => {
  res.render('sign-up');
});

router.post('/sign-up', (req, res, next) => {
  //receiving the info from the field of the view
  const { name, email, password } = req.body;
  //ecrypting the password
  bcryptjs
    .hash(password, 10)
    //crating the user on the database
    .then(hash => {
      return User.create({
        name,
        email,
        passwordHash: hash,
        confirmationToken: token
      });
    })
    //sending the e-mail and saving to the session
    .then(user => {
      req.session.user = user._id;
      return transport.sendMail({
        from: process.env.NODEMAILER_EMAIL,
        to: process.env.NODEMAILER_EMAIL,
        subject: 'An email from Bruno',
        html: `
      <html>
        <body>
          <a href="${confirmationUrl}">Link to confirm email</a>
        </body>
      </html>
    `
      });
    })
    //redirecting to homepage
    .then(result => {
      console.log('Email was sent.');
      console.log(result);
      res.redirect('/');
    })
    .catch(error => {
      next(error);
    });
});

router.get('/sign-in', (req, res, next) => {
  res.render('sign-in');
});

router.post('/sign-in', (req, res, next) => {
  let userId;
  const { email, password } = req.body;
  User.findOne({ email })
    .then(user => {
      if (!user) {
        return Promise.reject(new Error("There's no user with that email."));
      } else {
        userId = user._id;
        return bcryptjs.compare(password, user.passwordHash);
      }
    })
    .then(result => {
      if (result) {
        req.session.user = userId;
        res.redirect('/');
      } else {
        return Promise.reject(new Error('Wrong password.'));
      }
    })
    .catch(error => {
      next(error);
    });
});

router.get('authentication/confirm-email', (req, res, next) => {
  const emailToken = req.query.token;
  //find it put then and catch
  findOneAndUpdate(
    { confirmationToken: emailToken },
    { status: 'active' },
    { new: true }
  );

  res.render('confirmation');
});

router.post('/sign-out', (req, res, next) => {
  req.session.destroy();
  res.redirect('/');
});

const routeGuard = require('./../middleware/route-guard');
const { findOneAndUpdate } = require('./../models/user');

router.get('/private', routeGuard, (req, res, next) => {
  res.render('private');
});

module.exports = router;
