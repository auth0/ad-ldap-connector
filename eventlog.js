var path = require('path');
var winston = require('winston');
// `colors` extends String.prototype with .stripColors, used in winston_wrap below to strip
// ANSI color codes before writing to the log file. Require it here rather than relying on
// another module having loaded it first.
require('colors');

// File logging is only enabled on Windows (the connector's deployment target). On other
// platforms no transport is attached and console output simply passes through untouched —
// matching the previous behaviour. This flag prevents routing to winston when there is no
// transport, which in winston v3 would emit a "no transports" warning (and, since we patch
// console.error below, would recurse infinitely).
var fileLoggingEnabled = process.platform === 'win32';

// winston v3: the default logger's level defaults to 'info', which would filter out the
// debug-level messages emitted below before they reach the transport. Set it to 'debug'
// so console.log output (routed through winston.debug) is actually written.
winston.level = 'debug';

// winston v3: the default logger starts with no transports. On Windows we attach a
// File transport with built-in size-based rotation, replacing the old stream-rotate
// dependency. maxsize + maxFiles + tailable reproduce the previous behaviour: roll to
// a new file at ~1MB and keep the 5 most recent (logs.log, logs1.log ... logs4.log).
if (fileLoggingEnabled) {
  winston.add(new winston.transports.File({
    filename: path.join(__dirname, 'data', 'logs', 'connector', 'logs.log'),
    level: 'debug',
    maxsize: 1024 * 1024, // 1MB, was size: '1m'
    maxFiles: 5,          // was retention: 5
    tailable: true,
    handleExceptions: true,
    format: winston.format.printf(function (info) { return info.message; })
  }));
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
    if (!arguments[0]) { return; }
    var args = add_timestamp(arguments);
    var message = util.format.apply(util, args).stripColors;
    if (!message) return;
    if (fileLoggingEnabled) winston_fn(message);
    fn.apply(console, args);
  };
}

console.restore = function() {
  console.log = old_log;
  console.error = old_error;
  console.warn = old_warn;
};

console.inject = function() {
  // Bind the winston convenience methods: winston v3's default-logger methods rely on
  // `this` being the logger, so they must be bound before being passed around detached.
  console.log = winston_wrap(old_log, winston.debug.bind(winston));
  console.error = winston_wrap(old_error, winston.error.bind(winston));
  console.warn = winston_wrap(old_warn, winston.warn.bind(winston));
};

console.inject();
