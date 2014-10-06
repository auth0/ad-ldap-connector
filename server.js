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

  var configure_server = function (server) {
    var express  = require('express');
    var passport = require('passport');

    require('./lib/setupPassport');

    var cookieSessions = require('cookie-sessions');
    var app = express();

    //configure the webserver
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

    if (options) { server.createServer(options, app).listen(nconf.get('PORT')); }
    else { server.createServer(nconf.get('PORT'), app); }
    
    console.log('listening on port: ' + nconf.get('PORT'));
  };

  // kerberos authentication
  if (nconf.get('KERBEROS_AUTH')) {
    console.log('Using kerberos authentication');

    if (process.platform !== 'win32') {
      return console.log('Detected KERBEROS_AUTH in config, but this platform doesn\'t support it.');
    }

    var kerberosServer = require('kerberos-server');
    return configure_server(kerberosServer);
  }

  // client certificate-based authentication
  if (nconf.get('CLIENT_CERT_AUTH')) {
    console.log('Using client certificate-based authentication');

    // Validate SSL settings
    if (!nconf.get('SSL_KEY')) { return console.log('Please update your config.json file to include the path of your SSL private key (SSL_KEY).'); }
    if (!nconf.get('SSL_CERT')) { return console.log('Please update your config.json file to include the path of your SSL certificate (SSL_CERT).'); }
    if (!nconf.get('CA_CERT')) { return console.log('Please update your config.json file to include the path(s) of your CA public key(s) (CA_CERT). A certificate that is not signed by the provided CA will be rejected at the protocol layer.'); }

    var fs = require('fs');
    var options = {
      key: fs.readFileSync(nconf.get('SSL_KEY')),
      cert: fs.readFileSync(nconf.get('SSL_CERT')),
      ca: nconf.get('CA_CERT').split(',').map(function (cert) {
        return cert && fs.readFileSync(cert.trim());
      }),
      requestCert: true,
      rejectUnauthorized: false
    };

    var https = require('https');
    return configure_server(https, options);
  }
});
