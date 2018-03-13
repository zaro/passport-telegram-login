/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , util = require('util')
  , crypto = require('crypto');


/**
 * Creates an instance of `Strategy`.
 *
 * The Telegram Login authentication strategy authenticates requests based on
 * the Telegram Login Widget
 *
 *
 * Applications must supply a `verify` callback, for which the function
 * signature is:
 *
 *     function(userData, done) { ... }
 *
 * `userData` is the bearer token provided as a credential.  The verify callback
 * is responsible for finding the user who posesses the token, and invoking
 * `done` with the following arguments:
 *
 *     done(err, user, info);
 *
 * If the token is not valid, `user` should be set to `false` to indicate an
 * authentication failure.  Additional token `info` can optionally be passed as
 * a third argument, which will be set by Passport at `req.authInfo`, where it
 * can be used by later middleware for access control.  This is typically used
 * to pass any scope associated with the token.
 *
 * Options:
 *
 *   - `botToken`   The BOT_TOKEN of the bot used in the login widget
 *
 * Examples:
 *
 *     passport.use(new TelegramLoginStrategy(
 *       { 'botToken': 'BOT_TOKEN'},
 *       function(userData, done) {
 *         done(null, userData);
 *       }
 *     ));
 *
 *
 * @constructor
 * @param {Object} [options]
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  passport.Strategy.call(this);
  this.name = 'telegram-login';
  this._verify = verify;
  this.botToken = options.botToken;
}


/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a HTTP Bearer authorization
 * header, body parameter, or query parameter.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req) {
  const {hash, ...authData}  = req.query;
  const pairs = [];

  for(const key of Object.keys(authData)){
    pairs.push(`${key}=${authData[key]}`)
  }
  pairs.sort();
  const dataCheckString = pairs.join('\n');
  const sha256Hash = crypto.createHash('sha256');
  sha256Hash.update(this.botToken);
  const secretKey = sha256Hash.digest();
  const hmac = crypto.createHmac('sha256', secretKey);
  hmac.update(dataCheckString);
  const calculatedHash = hmac.digest('hex').toLowerCase();

  if(calculatedHash !== hash){
    return this.fail(401);
  }

  if (((new Date().getTime()/1000) - authData['auth_date']) > 86400) {
    return this.fail(401);
  }    

  const verified = (err, user, info) => {
    if (err) { return this.error(err); }
    this.success(user, info);
  }

  if (this._verify) {
    this._verify(authData, verified);
  } else {
    this.success(authData);      
  }

};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;