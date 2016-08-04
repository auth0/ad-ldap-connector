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
var old_warn = console.warn;

var util = require('util');

function add_timestamp (args) {
  var timestamp = new Date().toISOString().replace(/T/, ' ').replace(/\..+/, '');
  var result = Array.prototype.slice.call(args);
  result[0] = '[' + timestamp + '] ' +  result[0];
  return result;
}

function winston_wrap (fn, winston_fn) {
  return function() {
    var args = add_timestamp(arguments);
    var message = util.format.apply(util, args).stripColors;
    if (!message) return;
    winston_fn(message);
    fn.apply(console, args);
  };
}

console.restore = function() {
  console.log = old_log;
  console.error = old_error;
  console.warn = old_warn;
};

console.inject = function() {
  console.log = winston_wrap(old_log, winston.debug);
  console.error = winston_wrap(old_error, winston.error);
  console.warn = winston_wrap(old_warn, winston.warn);
};

console.inject();
