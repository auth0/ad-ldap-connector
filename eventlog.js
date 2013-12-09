if (process.platform !== 'win32') return;

var old_log = console.log;
var old_error = console.error;
var EventLog = require('windows-eventlog').EventLog;
var eventlog = new EventLog("Auth0 ADLDAP");

console.log = function () {
  var message = Array.prototype.slice.call(arguments)
                     .join(' ')
                     .stripColors; //remove colors
  if (!message) return;
  eventlog.log(message);
  old_log.apply(console, arguments);
};

console.error = function () {
  var message = Array.prototype.slice.call(arguments)
                     .join(' ')
                     .stripColors; //remove colors
  if (!message) return;
  eventlog.log(message, 'Error');
  old_error.apply(console, arguments);
};