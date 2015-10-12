var util = require('util');

function AccountExpired(profile) {
  this.message = "Account expired";
  this.profile = profile;
  this.name = 'AccountExpired';
  Error.call(this, this.message);
  Error.captureStackTrace(this, this.constructor);
}

util.inherits(AccountExpired, Error);

module.exports = AccountExpired;
