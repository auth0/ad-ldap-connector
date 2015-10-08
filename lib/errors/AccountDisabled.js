var util = require('util');

function AccountDisabled(username) {
  this.message = "Account disabled";
  this.username = username;
  this.name = 'AccountDisabled';
  Error.call(this, this.message);
  Error.captureStackTrace(this, this.constructor);
}

util.inherits(AccountDisabled, Error);

module.exports = AccountDisabled;
