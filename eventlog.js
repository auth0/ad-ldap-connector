if (process.platform !== 'win32') return;

var winston = require("winston");

winston.remove(winston.transports.Console);
winston.add(winston.transports.File, {
  maxsize: 40000,
  maxFiles: 10,
  level: "debug",
  filename: __dirname + '/logs.log',
  json: false,
  handleExceptions: true
});


var old_log = console.log;
var old_error = console.error;

var util = require('util');

console.log = function () {
  var message = util.format.apply(util, arguments).stripColors;
  if (!message) return;
  winston.debug(message);
  old_log.apply(console, arguments);
};

console.error = function () {
  var message = util.format.apply(util, arguments).stripColors;
  if (!message) return;
  winston.error(message);
  old_error.apply(console, arguments);
};