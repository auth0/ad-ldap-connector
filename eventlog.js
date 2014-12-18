var winston = require('winston');
var rotator = require('stream-rotate');

winston.remove(winston.transports.Console);

if (process.platform === 'win32') {
  var log_stream = rotator({
    path: __dirname,
    name: 'logs',
    size: '1m',
    retention: 5
  });

  winston.add(winston.transports.File, {
    stream: log_stream,
    level: "debug",
    json: false,
    handleExceptions: true,
    eol: require('os').EOL
  });
}

var old_log = console.log;
var old_error = console.error;

var util = require('util');

function add_timestamp (args) {
  var timestamp = new Date().toISOString().replace(/T/, ' ').replace(/\..+/, '');
  var result = Array.prototype.slice.call(args);
  result[0] = '[' + timestamp + '] ' +  result[0];
  return result;
}

console.log = function () {
  var args = add_timestamp(arguments);
  var message = util.format.apply(util, args).stripColors;
  if (!message) return;
  winston.debug(message);
  old_log.apply(console, args);
};

console.error = function () {
  var args = add_timestamp(arguments);
  var message = util.format.apply(util, args).stripColors;
  if (!message) return;
  winston.error(message);
  old_error.apply(console, args);
};