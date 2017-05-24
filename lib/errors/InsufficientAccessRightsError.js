var util = require('util');

function InsufficientAccessRightsError(profile) {
  this.message = "Service Account has Insufficient Access Rights";
  this.profile = profile;
  this.name = 'InsufficientAccessRightsError';
  Error.call(this, this.message);
  Error.captureStackTrace(this, this.constructor);
}

util.inherits(InsufficientAccessRightsError, Error);

module.exports = InsufficientAccessRightsError;