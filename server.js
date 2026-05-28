require('colors');
const crypto = require('crypto');
const process = require('node:process');
const express  = require('express');
const bodyParser = require('body-parser');
const logger = require('morgan');
const passport = require('passport');
const session = require('express-session');

require('./eventlog');
require('./lib/setupProxy');
const exit = require('./lib/exit');
const config = require('./lib/config');
const certificates = require('./lib/certificates');
const connectorServiceSecretsBridge = require('./lib/connectorServiceSecretsBridge');
const endpoints = require('./endpoints');
const secureStorage = require('./lib/secureStorage');
const { loadProvisioningTicket } = require('./lib/provisioningTicket');
const { configureConnection } = require('./lib/configureConnection');

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


let ws_client;
let maxHeaderSize = Number(config.get('MAX_HEADER_SIZE'));
maxHeaderSize = maxHeaderSize > 0 ? maxHeaderSize : 16834;

console.log('');
console.log('');
console.log('');
console.log('======================== STARTING AD-LDAP CONNECTOR ========================');
console.log('Maximum header size = ' + maxHeaderSize);

(async () => {
  try {
    await connectorServiceSecretsBridge.processBridgeFile();
    await config.initialize();
  } catch (err) {
    console.log(err.message);
    return exit(2);
  }

  const requiredConfigKeys = [
    'PROVISIONING_TICKET',
    'LDAP_URL',
    'LDAP_BASE'
  ];

  const throwImproperInstallError = (reason) => {
    if (process.platform === 'win32') {
      console.error(`${reason}. Please re-run the installer (.msi) to set these values.`.red);
    } else {
      console.error(`${reason}. Please run the installation script under setup/index.js to set these values.`.red);
    }
    process.exit(1);
  };

  for (const key of requiredConfigKeys) {
    if (!config.get(key)) {
      throwImproperInstallError(`Missing required config value: ${key}`);
    }
  }

  if (!config.get('ANONYMOUS_SEARCH_ENABLED')) {
    if (!config.get('LDAP_BIND_USER') || !await secureStorage.get(secureStorage.keys.LDAP_BIND_PASSWORD)) {
      throwImproperInstallError('Anonymous LDAP search is not enabled, and LDAP bind user or password is not set');
    }
  }

  try {
    let provisioningTicket = config.get('PROVISIONING_TICKET');
    const ticketInfo = await loadProvisioningTicket(provisioningTicket);

    // Update config
    config.set('AD_HUB', ticketInfo.adHub);
    config.set('PROVISIONING_TICKET', provisioningTicket);
    config.set('WSFED_ISSUER', ticketInfo.connectionDomain);
    config.set('CONNECTION', ticketInfo.connectionName);
    config.set('CLIENT_CERT_AUTH', ticketInfo.certAuth);
    config.set('KERBEROS_AUTH', ticketInfo.kerberos);
    config.set('REALM', ticketInfo.realm.name);
    config.set('SITE_NAME', config.get('SITE_NAME') || ticketInfo.connectionName);
    config.set(ticketInfo.realm.name, ticketInfo.realm.postTokenUrl);

    // Generate self-signed certificates if needed
    console.log('Generating self-signed certificates...');
    await certificates.initialize({
      connectionDomain: ticketInfo.connectionDomain,
      connectionName: ticketInfo.connectionName,
    });

    // Configure connection using the provisioning ticket
    console.log('Configuring connection ' + ticketInfo.connectionName + '.');
    const { serverUrl, certThumbprint, tenantSigningKey } = await configureConnection({
      provisioningTicket,
      connectionName: ticketInfo.connectionName,
    });

    config.set('SERVER_URL', serverUrl);
    config.set('LAST_SENT_THUMBPRINT', certThumbprint);
    config.set('TENANT_SIGNING_KEY', tenantSigningKey);

    // Save config to file
    await config.save();

    await require('./lib/ldap').initialize();
  } catch (e) {
    console.error(e.message);
    return exit(1);
  }

  require('./lib/clock_skew_detector');
  ws_client = require('./ws_validator');
  var latency_test = require('./latency_test');
  latency_test.run_many(10);

  if (!config.get('KERBEROS_AUTH') && !config.get('CLIENT_CERT_AUTH')) {
    return;
  }

  require('./lib/setupPassport');

  var app = express();

  // configure the webserver
  app.set('view engine', 'ejs');
  app.set('views', __dirname + '/views');

  app.use(express.static(__dirname + '/public'));
  app.use(logger('combined'));
  if(config.get('KERBEROS_DEBUG_USER')) {
    app.use((req, res, next) => {
      req.headers['x-forwarded-user'] = config.get('KERBEROS_DEBUG_USER');
      next();
    });
  }
  app.use(bodyParser.json());
  app.use(bodyParser.urlencoded({extended:true}));

  let sessionSecret = await secureStorage.get(secureStorage.keys.CONNECTOR_SESSION_SECRET);
  if (!sessionSecret) {
    sessionSecret = crypto.randomBytes(32).toString('hex');
    await secureStorage.store(secureStorage.keys.CONNECTOR_SESSION_SECRET, sessionSecret);
  }
  app.use(session({
    secret: sessionSecret,
    saveUninitialized: false,
    resave: false,
  }));

  app.use(passport.initialize());

  await endpoints.install(app);

  await config.save();

  var options = {
    port: config.get('PORT'),
    test_user: config.get('KERBEROS_DEBUG_USER'),
    maxHeaderSize,
  };

  // client certificate-based authentication
  if (config.get('CLIENT_CERT_AUTH')) {
    console.log('Using client certificate-based authentication');

    // SSL settings
    options.ca = config.get('CA_CERT');
    options.pfx = Buffer.from(config.get('SSL_PFX'), 'base64');
    options.passphrase = await secureStorage.get(secureStorage.keys.CUSTOM_SSL_PFX_PASSWORD);
    options.requestCert = true;

    if (!config.get('KERBEROS_AUTH')) {
      var https = require('https'); // use https server
      https.createServer(options, app).listen(options.port);
    }
  }

  // kerberos authentication
  if (config.get('KERBEROS_AUTH')) {
    console.log('Using kerberos authentication');

    if (process.platform === 'win32') {
      var KerberosServer = require('kerberos-server');
      var kerberosServer = new KerberosServer(app, options);
      kerberosServer.listen(options.port)
        .on('error', function (err) {
          console.error(err.message);
          return process.exit(1);
        });
    } else if (config.get('WITH_KERBEROS_PROXY_FRONTEND') || config.get('KERBEROS_DEBUG_USER')) {
      var http = require('http');
      http.createServer({ maxHeaderSize }, app).listen(options.port);
    } else {
      return console.log('Detected KERBEROS_AUTH in config, but this platform doesn\'t support it.');
    }

  }

  console.log('listening on port: ' + config.get('PORT'));
})();
