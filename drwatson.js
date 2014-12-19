var request = require('request');
var winston = require('winston');
var util    = require('util');
var xtend   = require('xtend');
var urlJoin = require('url-join');

var DrWatson = module.exports = function (options) {
  winston.Transport.call(this, options);

  this.name   = 'drwatson';
  this.url    = urlJoin(options.base_url, '/drwatson');
  this.meta   = options.meta || {};
  this.app    = options.app;
};

util.inherits(DrWatson, winston.Transport);

DrWatson.prototype.name = 'drwatson';

// ### function log (level, msg, [meta], callback)
// #### @level {string} Level at which to log the message.
// #### @msg {string} Message to log
// #### @meta {Object} **Optional** Additional metadata to attach
// #### @callback {function} Continuation to respond to when complete.
// Core logging method exposed to Winston. Metadata is optional.
DrWatson.prototype.log = function (level, msg, meta, callback) {
  var self = this;

  callback = callback || function () {};
  meta = xtend({}, meta || {}, self.meta);

  if (self.silent) {
    return callback(null, true);
  }

  if (self.ticket) {

  }

  request.post({
    url: self.url,
    json: {
      app: self.app,
      level: level,
      message: msg,
      description: meta
    }
  }, function (err) {
    if (err) {
      self.emit('error', err);
      return callback(err, false);
    }

    self.emit('logged');
    callback(null, true);
  });
};


// Configure DrWatson transport if SEND_LOGS_TO_AUTH0 is TRUE and PROVISIONING_TICKET exists
var url   = require('url');
var nconf = require('nconf');

if (nconf.get('SEND_LOGS_TO_AUTH0') && nconf.get('PROVISIONING_TICKET')) {
  var meta = {
    tenant: nconf.get('REALM') ? nconf.get('REALM').split(':')[2] : '',
    connection: nconf.get('CONNECTION'),
    provisioning_ticket: nconf.get('PROVISIONING_TICKET')
  };

  var ticket_url = url.parse(meta.provisioning_ticket);

  winston.add(DrWatson, {
    app: 'ad-ldap-connection',
    level: 'error',
    base_url: ticket_url.protocol + '//' + ticket_url.host,
    meta: meta
  });
}
