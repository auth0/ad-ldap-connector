var util = require('util');

function PasswordComplexityError(profile) {
  this.message = "Password password doesn’t meet minimum requirements";
  this.profile = profile;
  this.name = 'PasswordComplexityError';
  Error.call(this, this.message);
  Error.captureStackTrace(this, this.constructor);
}

util.inherits(PasswordComplexityError, Error);

module.exports = PasswordComplexityError;