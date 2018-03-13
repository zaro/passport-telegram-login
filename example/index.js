const express = require('express')
var session = require("express-session"),
    bodyParser = require("body-parser");
const app = express()
const passport = require('passport');
const TelegramStrategy = require('../lib/index').Strategy;

passport.use(new TelegramStrategy({
  botToken: '535151433:AAGOTcJHKJrlwZtPs8iCggQcEBlf3Bgrpvk'
}
// , (userData, done) =>{
//   console.log('Success', userData);
//   done(null, userData);
// })
));
passport.serializeUser(function(user, done) {
  console.log('serializeUser', user);
  done(null, JSON.stringify(user));
});

passport.deserializeUser(function(serialized, done) {
  console.log('deserializeUser', serialized);
  done(null, JSON.parse(serialized));
});



app.set('view engine', 'hbs');

app.use(express.static('./'));

// app.use(require('cookie-parser')());
app.use(session({ secret: "cats" }));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(passport.initialize());
app.use(passport.session());

app.get('/', (req, res) => {
  res.render('index', {
    user: req.user,
    something: "else",
  });
});
app.get('/auth/telegram', passport.authenticate('telegram-login', { session: true,  successRedirect: '/' }))

app.listen(3000, () => console.log('Example app listening on port 3000!'))
