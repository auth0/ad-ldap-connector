require('colors');
require('./lib/initConf');
require('./lib/setupProxy');

var _ = require('lodash');
var ldap = require('./lib/ldap');
var async = require('async');
var nconf = require('nconf');
var request = require('request');
var winston = require('winston');
var WebSocket = require('ws');
var isWindows = (process.platform == 'win32');

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

console.log('\n Troubleshooting AD LDAP connector\n');

async.series([
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

        request.get({
            uri: "https://login.auth0.com/test",
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

        request.get({
            uri: "https://login.auth0.com/test",
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
    function(callback) {
        logger.trying('Running NLTEST...');

        if (!isWindows) {
            logger.warn('  > NLTEST can only run on Windows.');
            callback();
        }

        var output = '';
        var errors = '';
        var spawn = require('child_process').spawn;
        var nltest = spawn('nltest', ['/dsgetdc:']);
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
            callback();
        });
    },
    function(callback){
        logger.trying('Testing LDAP connectivity.');
        if (!nconf.get("LDAP_BASE")) {
            logger.warn('  > LDAP_BASE not set. Cannot test connectivity.');
            return callback();
        }

        logger.info('  > LDAP BASE: %s', nconf.get("LDAP_BASE"))

        var opts = {
            scope:  'sub',
            sizeLimit: 5,
            filter: nconf.get('LDAP_SEARCH_ALL_QUERY')
        };
        ldap.client.search(nconf.get("LDAP_BASE"), opts, function(err, res){
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
                return callback();
            });
        });
    }
],
function(err, results){
    logger.info('Done!');
    process.exit(0);
});

