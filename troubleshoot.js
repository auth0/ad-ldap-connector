require('colors');
require('./lib/initConf');
require('./lib/setupProxy');

var _ = require('lodash');
var fs = require('fs');
var url = require('url');
var path = require('path');
var ldap = require('./lib/ldap');
var async = require('async');
var nconf = require('nconf');
var request = require('request');
var winston = require('winston');
var thumbprint = require('@auth0/thumbprint');
var WebSocket = require('ws');
var isWindows = (process.platform == 'win32');
var cas = require('./lib/add_certs');
var tls = require('tls');
var https = require('https');

var logger = new winston.Logger({
	transports: [
		new winston.transports.Console({
			timestamp: function() {
				var date = new Date();
				var hour = date.getHours();
				hour = (hour < 10 ? "0" : "") + hour;
				var min  = date.getMinutes();
				min = (min < 10 ? "0" : "") + min;
				var sec  = date.getSeconds();
				sec = (sec < 10 ? "0" : "") + sec;
				return hour + ":" + min + ":" + sec;
			},
			level: 'debug',
			handleExceptions: true,
			json: false,
			colorize: true
		})
	],
	exitOnError: false
});
logger.trying = function(message, arg) {
	if (!arg) arg = '';
	logger.info((isWindows ? '* ' : '\u272D ').yellow + message, arg);
};
logger.success = function(message, arg) {
	if (!arg) arg = '';
	logger.info((isWindows ? '\u221A ' : '\u2714 ').green + message, arg);
};
logger.failed = function(message, arg) {
	if (!arg) arg = '';
	logger.error((isWindows ? '\u00D7 ' : '\u2716 ').red + message, arg);
};

process.on('uncaughtException', function (err) {
  console.log(err);
});

console.log('\n Troubleshooting AD LDAP connector\n');

async.series([
	function(callback){
    cas.inject(callback);
  },
  function(callback){
		var HTTP_PROXY = process.env.HTTP_PROXY || process.env.http_proxy;
		if (HTTP_PROXY) {
			logger.info('Proxy configured: %s', HTTP_PROXY);
		} else {
			logger.info('No proxy server configured.');
		}
		callback();
	},
	function(callback){
		logger.trying('Testing connectivity to Auth0...');

		var connectivity_url = 'https://login.auth0.com/test';
		if (nconf.get('PROVISIONING_TICKET')) {
			connectivity_url = 'https://' + url.parse(nconf.get('PROVISIONING_TICKET')).host + '/test';
		}

		logger.info('  > Test endpoint: ' + connectivity_url.green);

		request.get({
			uri: connectivity_url,
			json: true
		}, function (err, res, body) {
			if (err || res.statusCode !== 200) {
				logger.failed('Error connecting to Auth0.');
				if (err)
					logger.error('  > Error: %s', JSON.stringify(err));
				logger.error('  > Status: %s', res.statusCode);
				if (body)
					logger.error('  > Body: %s', body.replace(/\n$/, ''));
			} else {
				logger.success('Connection to test endpoint %s.', 'succeeded'.green);
			}
			callback();
		});
	},
	function(callback){
		logger.trying('Testing hub connectivity (WS).');

		var hubUrl = nconf.get('AD_HUB');
		if (!hubUrl) {
			hubUrl = "https://login.auth0.com/lo/hub";
			logger.warn('Could not load AD_HUB from config. Setting to default.');
		}

		var socket_server_address = hubUrl.replace(/^http/i, 'ws');
		var ws = new WebSocket(socket_server_address);
		ws.on('open', function () {
			logger.success('Connection to hub %s.', 'succeeded'.green);
			ws.close();
			callback();
		}).on('message', function (msg) {
			logger.success('Message received: %s.', msg);
			ws.close();
			callback();
		}).on('error', function (err) {
			logger.failed('Connection to hub %s.', 'failed'.red);
			logger.error('  > Body: %s', err.replace(/\n$/, ''));
			ws.close();
			callback();
		});
	},
	function(callback){
		logger.trying('Testing clock skew...');

		var clock_url = 'https://login.auth0.com/test';
		if (nconf.get('PROVISIONING_TICKET')) {
			clock_url = 'https://' + url.parse(nconf.get('PROVISIONING_TICKET')).host + '/test';
		}

		request.get({
			uri: clock_url,
			json: true
		}, function (err, resp, body) {
			if (err || !body || !body.clock) {
				logger.failed('Error calling the test endpoint.');
				return callback();
			}

			var auth0_time = body.clock;
			var local_time = new Date().getTime();
			var diff = Math.abs(auth0_time - local_time);
			if (diff > 5000) {
				logger.failed('Clock skew detected:');
				logger.error('  > Local time: ' + new Date(local_time).toISOString().replace(/T/, ' ').replace(/\..+/, ''));
				logger.error('  > Auth0 time: ' + new Date(auth0_time).toISOString().replace(/T/, ' ').replace(/\..+/, '').red);
			}
			else {
				logger.success('Everything %s. No clock skew detected.', 'OK'.green);
			}

			callback();
		});
	},
	function(callback){
		logger.trying('Testing certificates...');

		var certPath = path.join(__dirname, 'certs', 'cert.pem');
		fs.exists(certPath, function (exists) {
			var local_thumbprint;
			var server_thumbprint;

			if (!exists) {
				logger.warn('  > Local certificate ' + 'certs/cert.pem'.yellow + ' does not exist. Cannot read thumbprint.');
			}
			else {
				var certContents = fs.readFileSync(path.join(__dirname, 'certs', 'cert.pem')).toString();
				var cert = /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g.exec(certContents);
				if (cert.length > 0) {
					cert = cert[1].replace(/[\n|\r\n]/g, '');
				}

				local_thumbprint = thumbprint.calculate(cert);
				logger.info('  > Local thumbprint: ' + local_thumbprint);
			}

			if (!nconf.get("PROVISIONING_TICKET")) {
				logger.warn('  > ' + 'PROVISIONING_TICKET'.yellow + ' not set. Cannot compare with connection thumbprint (This is optional).');
				return callback();
			}


			var info_url = nconf.get('PROVISIONING_TICKET') + '/info';
			request.get({
				uri: info_url,
				json: true
			}, function (err, res, body) {
				if (res && res.statusCode !== 200 || err) {
					logger.error(' > Error loading certificate from Auth0: %s', res && res.statusCode || err);
					logger.warn('  > Cannot compare with connection thumbprint.');
				} else {
					var thumbprints = body.thumbprints
					if (!thumbprints || thumbprints.length === 0) {
						logger.error(' > No thumbprints available in the connection information. Cannot compare certificates.');
					}
					else {
						server_thumbprint = body.thumbprints[0];
						logger.info('  > Server thumbprint: ' + server_thumbprint);
					}
				}

				if (local_thumbprint && server_thumbprint) {
					if (local_thumbprint === server_thumbprint) {
						logger.success('Local and server certificates match.');
					}
					else {
						logger.failed('Local and server certificates ' + 'don\'t match'.red + '.');
					}
				}

				callback();
			});
		});
	},
	function(callback) {
		logger.trying('Running NLTEST...');

		if (!isWindows) {
			logger.warn('  > NLTEST can only run on Windows.');
			return callback();
		}

		try {
		  var output = '';
		  var spawn = require('child_process').spawn;
		  var nltest = spawn('nltest', ['/dsgetdc:']);
		  nltest.on('error', function (err) {
			  logger.failed('Running NLTEST %s.', 'failed'.red);
			  if (err && err.message)
				  logger.error('  > Error: %s', err.message.replace(/\r\n|\r|\n/, '').red);
			  return callback();
		  });
		  nltest.stdout.on('data', function (data) { output += data; });
		  nltest.stderr.on('data', function (data) { output += data; });
		  nltest.on('close', function (code) {
			  if (output) {
				  var lines = output.replace(/^\s+|\s+$/g,'').replace(/\r\n\s+/g,'\r\n').split(/\r\n/g);
				  for (var i=0; i<lines.length; i++) {
					  if (code === 0)
						  logger.info('  > ' + lines[i]);
					  else
						  logger.error('  > ' + lines[i]);
				  }
			  }
			  return callback();
		  });
		} catch (err) {
			logger.failed('Running NLTEST %s.', 'failed'.red);
			if (err && err.message)
				logger.error('  > Error: %s', err.message.replace(/\r\n|\r|\n/, '').red);
			return callback();
		}
	},
	function(callback) {
		const { host, protocol, port } = url.parse(nconf.get('LDAP_URL'));
		if(protocol !== 'ldaps:') {
			return callback();
		}
		logger.trying('Testing SSL connectivity to LDAP %s.', host);

		tls.connect({
			host,
			port: port || 636,
			ca: https.globalAgent.options.ca,
			checkServerIdentity: nconf.get('SSL_ENABLE_EMPTY_SUBJECT') && tls.checkServerIdentity
		}).once('secureConnect', () => {
			logger.success('Connection to LDAP %s.', 'succeeded'.green);
			callback()
		}).once('error', err => {
			logger.error('  > Error: %s', err.message.replace(/\r\n|\r|\n/, '').trim().red);
			callback(err);
		})
	},
	function(callback) {
		logger.trying('Testing LDAP connectivity.');
		if (!nconf.get("LDAP_BASE")) {
			logger.warn('  > ' + 'LDAP_BASE'.yellow + 'not set. Cannot test connectivity.');
			return callback();
		}

		logger.info('  > LDAP BASE: %s', nconf.get("LDAP_BASE"))

		var opts = {
			scope: 'sub',
			sizeLimit: 5,
			filter: nconf.get('LDAP_SEARCH_ALL_QUERY')
		};

		try {
			ldap.client.search(nconf.get("LDAP_BASE"), opts, function(err, res) {
				if (err) {
					logger.failed('Connection to LDAP %s.', 'failed'.red);
					if (err && err.message)
						logger.error('  > Error: %s', err.message.replace(/\r\n|\r|\n/, '').red);
					return callback();
				}

				var entries = [];
				res.on('searchEntry', function(entry) {
					logger.info('  > Found user: %s', entry.object.sAMAccountName || entry.object.mail || entry.object.name);
					entries.push(entry);
				});
				res.on('error', function(err) {
					if (err.message === 'Size Limit Exceeded' && entries.length > 0) {
						logger.success('Connection to LDAP %s.', 'succeeded'.green);
						return callback();
					}
					logger.failed('Connection to LDAP %s.', 'failed'.red);
					if (err && err.message)
						logger.error('  > Error: %s', err.message.replace(/\r\n|\r|\n/, '').trim().red);
					return callback();
				});
				res.on('end', function() {
				  console.log('end');
					if (!entries || entries.length === 0) {
					  logger.error('  > Error: %s', 'Unable to find users. Verify the permissions for the current user.'.red);
					}
					return callback();
				});
			});
		} catch (e) {
			logger.failed('Connection to LDAP %s.', 'failed'.red);
			if (e && e.message)
				logger.error('  > Error: %s', e.message.replace(/\r\n|\r|\n/, '').red);
			return callback();
		}
	}
],
function(err){
	logger.info('Done!\n');
	process.exit(0);
});
