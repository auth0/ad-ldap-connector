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


  require('./ws_validator');

  if (!nconf.get('KERBEROS_AUTH') || process.platform !== 'win32') {
    return;
  }

  var kerberosServer = require('kerberos-server');
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

  kerberosServer.createServer(nconf.get('PORT'), app);

  console.log('listening on http://localhost:' + nconf.get('PORT'));
});