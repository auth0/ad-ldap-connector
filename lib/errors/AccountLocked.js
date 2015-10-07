var util = require('util');

function AccountLocked(username) {
  this.message = "Account locked";
  this.username = username;
  this.name = 'AccountLocked';
  Error.call(this, this.message);
  Error.captureStackTrace(this, this.constructor);
}

util.inherits(AccountLocked, Error);

module.exports = AccountLocked;