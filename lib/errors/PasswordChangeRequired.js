var util = require('util');

function PasswordChangeRequired(profile) {
  this.message = "Password change required";
  this.profile = profile;
  this.name = 'PasswordChangeRequired';
  Error.call(this, this.message);
  Error.captureStackTrace(this, this.constructor);
}

util.inherits(PasswordChangeRequired, Error);

module.exports = PasswordChangeRequired;
