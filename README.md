# passport-telegram-login


[Passport](http://passportjs.org/) strategy for authenticating with [Telegram](https://telegram.org/)
using the [Telegram Login Widget](https://core.telegram.org/widgets/login).

This module lets you authenticate using Telegram in your Node.js applications.
By plugging into Passport, Telegram authentication can be easily and
unobtrusively integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

## Install

    $ npm install passport-telegram-login

## Usage

#### Configure Strategy

The Telegram authentication strategy authenticates users using a Telegram Bot.
Check the [Telegram Login Widget](https://core.telegram.org/widgets/login) page 
for information on how to create bot and get the bot token.

```js
passport.use(new TelegramStrategy({
    botToken: TELEGRAM_BOT_TOKEN,
  },
  function(profile, done) {
    User.findOrCreate({ telegramId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));
```

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `telegram-login` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

```js
app.get('/auth/telegram-login/callback',
  passport.authenticate('telegram-login', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/');
  });
```

And in your Telegram login widget configuration set 
```
    data-auth-url="/auth/telegram/callback"
```


## Examples

Take a look at the examples folder for a minimal express example

## License

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2018 Svetlozar Argirov <[http://broken-by.me/](http://broken-by.me/)>
