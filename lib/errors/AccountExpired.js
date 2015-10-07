var util = require('util');

function AccountExpired(username) {
  this.message = "Account expired";
  this.username = username;
  this.name = 'AccountExpired';
  Error.call(this, this.message);
  Error.captureStackTrace(this, this.constructor);
}

util.inherits(AccountExpired, Error);

module.exports = AccountExpired;