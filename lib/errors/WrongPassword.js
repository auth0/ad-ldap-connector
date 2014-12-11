var util = require('util');

function WrongPassword(profile) {
  this.message = "Wrong password";
  this.profile = profile;
  Error.call(this, this.message);
  Error.captureStackTrace(this, this.constructor);
}

util.inherits(WrongPassword, Error);

module.exports = WrongPassword;