if (process.platform !== 'win32') return;

var winston = require('winston');
var rotator = require('stream-rotate');

var log_stream = rotator({
  path: __dirname,
  name: 'logs',
  size: '1m',
  retention: 5
});

winston.remove(winston.transports.Console);
winston.add(winston.transports.File, {
  stream: log_stream,
  level: "debug",
  json: false,
  handleExceptions: true,
  eol: require('os').EOL
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