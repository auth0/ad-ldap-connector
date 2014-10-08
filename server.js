require('colors');
require('./eventlog');

process.on('uncaughtException', function(err) {
  console.error(err);
});

require('./lib/initConf');

var nconf = require('nconf');

var connectorSetup = require('./connector-setup');

var emptyVars = [ 'LDAP_URL',
                  'LDAP_BASE',
                  'LDAP_BIND_USER',
                  'LDAP_BIND_PASSWORD' ];

connectorSetup.run(__dirname, emptyVars, function(err) {
  if(err) {
    console.log(err.message);
    process.exit(2);
  }

  if(!nconf.get('LDAP_URL')) {
    console.error('edit config.json and add your LDAP settings');
    return process.exit(1);
  }

  require('./lib/clock_skew_detector');
  require('./ws_validator');

  if (!nconf.get('KERBEROS_AUTH') && !nconf.get('CLIENT_CERT_AUTH')) {
    return;
  }

  var express  = require('express');
  var passport = require('passport');

  require('./lib/setupPassport');

  var cookieSessions = require('cookie-sessions');
  var app = express();

  // configure the webserver
  app.configure(function(){
    this.set('view engine', 'ejs');
    this.set('views', __dirname + '/views');

    this.use(express.static(__dirname + '/public'));
    this.use(express.logger());

    this.use(express.cookieParser());
    this.use(express.bodyParser());
    this.use(cookieSessions({
      session_key:    'auth0-ad-conn',
      secret:         nconf.get('SESSION_SECRET')
    }));

    this.use(passport.initialize());
    this.use(this.router);
  });

  require('./endpoints').install(app);

  var options = {
    port: nconf.get('PORT')
  };

  // client certificate-based authentication
  if (nconf.get('CLIENT_CERT_AUTH')) {
    console.log('Using client certificate-based authentication');

    // SSL settings
    options.ca = nconf.get('CA_CERT');
    options.pfx = new Buffer(nconf.get('SSL_PFX'));
    options.passphrase = nconf.get('SSL_KEY_PASSWORD');
    //options.key = require('fs').readFileSync('./certs/localhost.key.pem');
    //options.cert = require('fs').readFileSync('./certs/localhost.cert.pem');
    options.requestCert = true;
    //options.rejectUnauthorized = false;

    if (!nconf.get('KERBEROS_AUTH')) {
      var https = require('https'); // use https server
      https.createServer(options, app).listen(options.port);
    }
  }
  
  // kerberos authentication
  if (nconf.get('KERBEROS_AUTH')) {
    console.log('Using kerberos authentication');

    if (process.platform !== 'win32') {
      return console.log('Detected KERBEROS_AUTH in config, but this platform doesn\'t support it.');
    }

    var kerberos_server = require('kerberos-server');
    kerberos_server.createServer(options, app);
  }

  console.log('listening on port: ' + nconf.get('PORT'));
});
