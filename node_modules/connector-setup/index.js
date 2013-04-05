require('colors');

var nconf = require('nconf');

var program = require('commander');
var async = require('async');
var request = require('request');
var urlJoin = require('url-join');

//steps
var certificate = require('./steps/certificate');
var configureConnection = require('./steps/configureConnection');

program
  .version(require('./package.json').version)
  .parse(process.argv);

exports.run = function (workingPath, extraEmptyVars, callback) {
  var provisioningTicket, info; 
  
  if (typeof extraEmptyVars === 'function') {
    callback = extraEmptyVars;
    extraEmptyVars = [];
  }

  async.series([
    function (cb) {
      provisioningTicket = nconf.get('PROVISIONING_TICKET');

      if(provisioningTicket) return cb();

      program.prompt('Please enter the ticket number: ', function (pt) {
        provisioningTicket = pt;
        cb();
      });
    },
    function (cb) {
      request.get({
        url: urlJoin(provisioningTicket, '/info')
      }, function (err, response, body) {
        if (err) return cb(err);
        if (response.statusCode == 404) return cb (new Error('wrong ticket'));
        info = JSON.parse(body);
        cb();
      });
    },
    function (cb) {
      nconf.set('PROVISIONING_TICKET', provisioningTicket);
      nconf.set('WSFED_ISSUER', info.connectionDomain);
      nconf.set('SITE_NAME', info.connectionDomain);
      nconf.set(info.realm.name, info.realm.postTokenUrl);
      extraEmptyVars.forEach(function (ev) {
        if (!nconf.get(ev)) nconf.set(ev, '');
      });
      nconf.save(cb);
    },
    function (cb) {
      certificate(workingPath, info, cb);
    },
    function (cb) {
      configureConnection(program, workingPath,
                          info,
                          provisioningTicket, cb);
    },
    function (cb) {
      nconf.save(cb);
    }
  ], function (err) {
    if (err) return callback(err);
    callback();
  });
};