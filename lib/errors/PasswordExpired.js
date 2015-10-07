var util = require('util');

function PasswordExpired(username) {
  this.message = "Password expired";
  this.username = username;
  this.name = 'PasswordExpired';
  Error.call(this, this.message);
  Error.captureStackTrace(this, this.constructor);
}

util.inherits(PasswordExpired, Error);

module.exports = PasswordExpired;