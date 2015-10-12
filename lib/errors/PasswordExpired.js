var util = require('util');

function PasswordExpired(profile) {
  this.message = "Password expired";
  this.profile = profile;
  this.name = 'PasswordExpired';
  Error.call(this, this.message);
  Error.captureStackTrace(this, this.constructor);
}

util.inherits(PasswordExpired, Error);

module.exports = PasswordExpired;
