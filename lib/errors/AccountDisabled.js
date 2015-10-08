var util = require('util');

function AccountDisabled(profile) {
  this.message = "Account disabled";
  this.profile = profile;
  this.name = 'AccountDisabled';
  Error.call(this, this.message);
  Error.captureStackTrace(this, this.constructor);
}

util.inherits(AccountDisabled, Error);

module.exports = AccountDisabled;
