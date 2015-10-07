var util = require('util');

function PasswordChangeRequired(username) {
  this.message = "Password change required";
  this.username = username;
  this.name = 'PasswordChangeRequired';
  Error.call(this, this.message);
  Error.captureStackTrace(this, this.constructor);
}

util.inherits(PasswordChangeRequired, Error);

module.exports = PasswordChangeRequired;
