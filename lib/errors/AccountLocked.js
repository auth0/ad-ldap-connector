var util = require('util');

function AccountLocked(profile) {
  this.message = "Account locked";
  this.profile = profile;
  this.name = 'AccountLocked';
  Error.call(this, this.message);
  Error.captureStackTrace(this, this.constructor);
}

util.inherits(AccountLocked, Error);

module.exports = AccountLocked;
