require('./lib/initConf');
require('colors');
require('./eventlog');
require('./lib/add_certs');
require('./lib/setupProxy');
var exit = require('./lib/exit');

function end () {
  console.log('Got SIGTERM, exiting now.');
  if (ws_client) {
    process.exiting = true;
    return ws_client.once('close', function () {
      exit(0);
    }).close();
  }
  exit(0);
}

process.on('uncaughtException', function(err) {
  console.error(err.stack);
}).once('SIGTERM', end)
  .once('SIGINT', end);


var nconf = require('nconf');
var ws_client;

var connectorSetup = require('./connector-setup');

connectorSetup.run(__dirname, function(err) {
  if(err) {
    console.log(err.message);
    return exit(2);
  }

  if(!nconf.get('LDAP_URL')) {
    console.error('edit config.json and add your LDAP URL');
    return exit(1);
  }

  if (!nconf.get('ANONYMOUS_SEARCH_ENABLED')) {
    console.log('Anonymous LDAP search not enabled');
    if (!nconf.get('LDAP_BIND_USER') || !nconf.get('LDAP_BIND_CREDENTIALS')) {
      console.error('Anonymous LDAP search is not enabled. Please edit config.json to add LDAP_BIND_USER');
      return exit(1);
    }
  }
  else {
    console.log('Anonymous LDAP search is enabled. LDAP_BIND_USER is not required');
  }

  require('./lib/clock_skew_detector');
  ws_client = require('./ws_validator');
  var latency_test = require('./latency_test');
  latency_test.run_many(10);

  if (!nconf.get('KERBEROS_AUTH') && !nconf.get('CLIENT_CERT_AUTH')) {
    return;
  }

  var express  = require('express');
  var bodyParser = require('body-parser');
  var cookieParser = require('cookie-parser');
  var logger = require('morgan');
  var passport = require('passport');

  require('./lib/setupPassport');

  var cookieSessions = require('cookie-sessions');
  var app = express();

  // configure the webserver
  app.set('view engine', 'ejs');
  app.set('views', __dirname + '/views');

  app.use(express.static(__dirname + '/public'));
  app.use(logger('combined'));

  app.use(cookieParser());
  app.use(bodyParser.json());
  app.use(bodyParser.urlencoded({extended:true}));
  app.use(cookieSessions({
    session_key:    'auth0-ad-conn',
    secret:         nconf.get('SESSION_SECRET')}));

  app.use(passport.initialize());

  require('./endpoints').install(app);

  var options = {
    port: nconf.get('PORT'),
    test_user: nconf.get('KERBEROS_DEBUG_USER')
  };

  // client certificate-based authentication
  if (nconf.get('CLIENT_CERT_AUTH')) {
    console.log('Using client certificate-based authentication');

    // SSL settings
    options.ca = nconf.get('CA_CERT');
    options.pfx = new Buffer(nconf.get('SSL_PFX'), 'base64');
    options.passphrase = nconf.get('SSL_KEY_PASSWORD');
    options.requestCert = true;

    if (!nconf.get('KERBEROS_AUTH')) {
      var https = require('https'); // use https server
      https.createServer(options, app).listen(options.port);
    }
  }

  // kerberos authentication
  if (nconf.get('KERBEROS_AUTH')) {
    console.log('Using kerberos authentication');

    if (process.platform === 'win32') {
      var KerberosServer = require('kerberos-server');
      var kerberosServer = new KerberosServer(app, options);
      kerberosServer.listen(options.port)
                    .on('error', function (err) {
                      console.error(err.message);
                      return process.exit(1);
                    });
    } else if (nconf.get('WITH_KERBEROS_PROXY_FRONTEND')) {
      var http = require('http');
      http.createServer(app).listen(options.port);
    } else {
      return console.log('Detected KERBEROS_AUTH in config, but this platform doesn\'t support it.');
    }

  }

  console.log('listening on port: ' + nconf.get('PORT'));
});
