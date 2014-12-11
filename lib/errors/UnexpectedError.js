var util = require('util');

function UnexpectedError(inner) {
  this.message = "Unexpected Error";
  this.inner = inner;

  Error.call(this, this.message);
  Error.captureStackTrace(this, this.constructor);
}

util.inherits(UnexpectedError, Error);

UnexpectedError.wrap = function (err) {
  return (err instanceof UnexpectedError) ? err : new UnexpectedError(err);
};

module.exports = UnexpectedError;