require('colors');
const config = require('./lib/config');
require('./lib/setupProxy');

const axios = require('axios');
const fs = require('fs');
const url = require('url');
const path = require('path');
const ldap = require('./lib/ldap');
const winston = require('winston');
const thumbprint = require('@auth0/thumbprint');
const WebSocket = require('ws');
const isWindows = process.platform === 'win32';
const cas = require('./lib/add_certs');
const tls = require('tls');
const https = require('https');

// winston v3: build the console output from composable formats. splat() enables the
// printf-style %s interpolation used throughout this file (e.g. logger.error('> %s', x)),
// and the printf format reproduces the previous "HH:mm:ss message" console layout.
const logger = winston.createLogger({
  level: 'debug',
  exitOnError: false,
  transports: [
    new winston.transports.Console({
      handleExceptions: true,
      format: winston.format.combine(
        winston.format.splat(),
        winston.format.timestamp({
          format: function () {
            var date = new Date();
            var hour = date.getHours();
            hour = (hour < 10 ? '0' : '') + hour;
            var min = date.getMinutes();
            min = (min < 10 ? '0' : '') + min;
            var sec = date.getSeconds();
            sec = (sec < 10 ? '0' : '') + sec;
            return hour + ':' + min + ':' + sec;
          },
        }),
        winston.format.printf(function (info) {
          return info.timestamp + ' - ' + info.message;
        })
      ),
    }),
  ],
});
logger.trying = function (message, arg) {
  if (!arg) arg = '';
  logger.info((isWindows ? '* ' : '✭ ').yellow + message, arg);
};
logger.success = function (message, arg) {
  if (!arg) arg = '';
  logger.info((isWindows ? '√ ' : '✔ ').green + message, arg);
};
logger.failed = function (message, arg) {
  if (!arg) arg = '';
  logger.error((isWindows ? '× ' : '✖ ').red + message, arg);
};

process.on('uncaughtException', function (err) {
  console.log(err);
});

function checkConnectivity() {
  logger.trying('Testing connectivity to Auth0...');

  let connectivity_url = 'https://login.auth0.com/test';
  if (config.get('PROVISIONING_TICKET')) {
    connectivity_url =
      'https://' +
      url.parse(config.get('PROVISIONING_TICKET')).host +
      '/test';
  }

  logger.info('  > Test endpoint: ' + connectivity_url.green);

  return axios.get(connectivity_url).then(() => {
    logger.success('Connection to test endpoint %s.', 'succeeded'.green);
  }).catch((err) => {
    if (err.response && err.response.status !== 200) {
      logger.failed('Error connecting to Auth0.');
      logger.error('  > Status: %s', err.response.status);
      logger.error('  > Body: %s', err.response.data.replace(/\n$/, ''));
    } else {
      logger.error('  > Error: %s', JSON.stringify(err, null, 2));
    }
  });
}

function checkHubConnectivity() {
  logger.trying('Testing hub connectivity (WS).');

  let hubUrl = config.get('AD_HUB');
  if (!hubUrl) {
    hubUrl = 'https://login.auth0.com/lo/hub';
    logger.warn('Could not load AD_HUB from config. Setting to default.');
  }

  const socket_server_address = hubUrl.replace(/^http/i, 'ws');

  return new Promise((resolve) => {
    const ws = new WebSocket(socket_server_address);
    ws.on('open', function () {
      logger.success('Connection to hub %s.', 'succeeded'.green);
      ws.close();
      resolve();
    })
      .on('message', function (msg) {
        logger.success('Message received: %s.', msg);
        ws.close();
        resolve();
      })
      .on('error', function (err) {
        logger.failed('Connection to hub %s.', 'failed'.red);
        logger.error('  > Body: %s', err.message.replace(/\n$/, ''));
        ws.close();
        resolve();
      });
  });
}

async function checkClockSkew() {
  logger.trying('Testing clock skew...');

  let clock_url = 'https://login.auth0.com/test';
  if (config.get('PROVISIONING_TICKET')) {
    clock_url =
      'https://' +
      url.parse(config.get('PROVISIONING_TICKET')).host +
      '/test';
  }

  try {
    const response = await axios.get(clock_url);
    const body = response.data;

    if (!body || !body.clock) {
      logger.failed('Error calling the test endpoint.');
      return;
    }

    const auth0_time = body.clock;
    const local_time = new Date().getTime();
    const diff = Math.abs(auth0_time - local_time);
    if (diff > 5000) {
      logger.failed('Clock skew detected:');
      logger.error(
        '  > Local time: ' +
          new Date(local_time).toISOString().replace(/T/, ' ').replace(/\..+/, '')
      );
      logger.error(
        '  > Auth0 time: ' +
          new Date(auth0_time).toISOString().replace(/T/, ' ').replace(/\..+/, '').red
      );
    } else {
      logger.success('Everything %s. No clock skew detected.', 'OK'.green);
    }
  } catch (err) {
    logger.failed('Error calling the test endpoint.', err);
  }
}

async function checkCertificates() {
  logger.trying('Testing certificates...');

  const certPath = path.join(__dirname, 'certs', 'cert.pem');
  let local_thumbprint;

  if (!fs.existsSync(certPath)) {
    logger.warn(
      '  > Local certificate ' +
        'certs/cert.pem'.yellow +
        ' does not exist. Cannot read thumbprint.'
    );
  } else {
    const certContents = fs.readFileSync(certPath).toString();
    let cert =
      /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g.exec(
        certContents
      );
    if (cert.length > 0) {
      cert = cert[1].replace(/[\n|\r\n]/g, '');
    }
    local_thumbprint = thumbprint.calculate(cert);
    logger.info('  > Local thumbprint: ' + local_thumbprint);
  }

  if (!config.get('PROVISIONING_TICKET')) {
    logger.warn(
      '  > ' +
        'PROVISIONING_TICKET'.yellow +
        ' not set. Cannot compare with connection thumbprint (This is optional).'
    );
    return;
  }

  const info_url = config.get('PROVISIONING_TICKET') + '/info';
  try {
    const response = await axios.get(info_url);
    const thumbprints = response.data.thumbprints;
    if (!thumbprints || thumbprints.length === 0) {
      logger.error(
        ' > No thumbprints available in the connection information. Cannot compare certificates.'
      );
    } else {
      const server_thumbprint = response.data.thumbprints[0];
      logger.info('  > Server thumbprint: ' + server_thumbprint);

      if (local_thumbprint) {
        if (local_thumbprint === server_thumbprint) {
          logger.success('Local and server certificates match.');
        } else {
          logger.failed('Local and server certificates ' + 'don\'t match'.red + '.');
        }
      }
    }
  } catch (err) {
    if (err.response && err.response.status !== 200) {
      logger.error(' > Error loading certificate from Auth0: %s', err.response.status);
      logger.warn('  > Cannot compare with connection thumbprint.');
    } else {
      logger.error(' > Error loading certificate from Auth0: %s', err);
      logger.warn('  > Cannot compare with connection thumbprint.');
    }
  }
}

function checkNltest() {
  logger.trying('Running NLTEST...');

  if (!isWindows) {
    logger.warn('  > NLTEST can only run on Windows.');
    return Promise.resolve();
  }

  return new Promise((resolve) => {
    try {
      let output = '';
      const spawn = require('child_process').spawn;
      const nltest = spawn('nltest', ['/dsgetdc:']);
      nltest.on('error', function (err) {
        logger.failed('Running NLTEST %s.', 'failed'.red);
        if (err && err.message)
          logger.error('  > Error: %s', err.message.replace(/\r\n|\r|\n/, '').red);
        resolve();
      });
      nltest.stdout.on('data', function (data) {
        output += data;
      });
      nltest.stderr.on('data', function (data) {
        output += data;
      });
      nltest.on('close', function (code) {
        if (output) {
          const lines = output
            .replace(/^\s+|\s+$/g, '')
            .replace(/\r\n\s+/g, '\r\n')
            .split(/\r\n/g);
          for (let i = 0; i < lines.length; i++) {
            if (code === 0) logger.info('  > ' + lines[i]);
            else logger.error('  > ' + lines[i]);
          }
        }
        resolve();
      });
    } catch (err) {
      logger.failed('Running NLTEST %s.', 'failed'.red);
      if (err && err.message)
        logger.error('  > Error: %s', err.message.replace(/\r\n|\r|\n/, '').red);
      resolve();
    }
  });
}

function checkSslLdap() {
  logger.trying('Testing SSL connectivity to LDAP.');

  if (!config.get('LDAP_URL')) {
    logger.warn(
      '  > ' + 'LDAP_URL'.yellow + ' not set. Cannot test SSL connectivity.'
    );
    return Promise.resolve();
  }

  const { host, protocol, port } = url.parse(config.get('LDAP_URL'));
  if (protocol !== 'ldaps:') {
    return Promise.resolve();
  }
  logger.info('  > Host: ' + host);

  return new Promise((resolve, reject) => {
    tls
      .connect({ host, port: port || 636, ca: https.globalAgent.options.ca })
      .once('secureConnect', () => {
        logger.success('Connection to LDAP %s.', 'succeeded'.green);
        resolve();
      })
      .once('error', (err) => {
        logger.error(
          '  > Error: %s',
          err.message.replace(/\r\n|\r|\n/, '').trim().red
        );
        reject(err);
      });
  });
}

function checkLdapConnectivity() {
  logger.trying('Testing LDAP connectivity.');

  if (!config.get('LDAP_BASE')) {
    logger.warn(
      '  > ' + 'LDAP_BASE'.yellow + ' not set. Cannot test connectivity.'
    );
    return Promise.resolve();
  }

  logger.info('  > LDAP BASE: %s', config.get('LDAP_BASE'));

  const opts = {
    scope: 'sub',
    sizeLimit: 5,
    filter: config.get('LDAP_SEARCH_ALL_QUERY'),
  };

  return new Promise((resolve) => {
    try {
      ldap.client.search(config.get('LDAP_BASE'), opts, function (err, res) {
        if (err) {
          logger.failed('Connection to LDAP %s.', 'failed'.red);
          if (err && err.message)
            logger.error('  > Error: %s', err.message.replace(/\r\n|\r|\n/, '').red);
          return resolve();
        }

        const entries = [];
        res.on('searchEntry', function (entry) {
          logger.info(
            '  > Found user: %s',
            entry.object.sAMAccountName || entry.object.mail || entry.object.name
          );
          entries.push(entry);
        });
        res.on('error', function (err) {
          if (err.message === 'Size Limit Exceeded' && entries.length > 0) {
            logger.success('Connection to LDAP %s.', 'succeeded'.green);
            return resolve();
          }
          logger.failed('Connection to LDAP %s.', 'failed'.red);
          if (err && err.message)
            logger.error('  > Error: %s', err.message.replace(/\r\n|\r|\n/, '').trim().red);
          resolve();
        });
        res.on('end', function () {
          console.log('end');
          if (!entries || entries.length === 0) {
            logger.error(
              '  > Error: %s',
              'Unable to find users. Verify the permissions for the current user.'.red
            );
          }
          resolve();
        });
      });
    } catch (e) {
      logger.failed('Connection to LDAP %s.', 'failed'.red);
      if (e && e.message)
        logger.error('  > Error: %s', e.message.replace(/\r\n|\r|\n/, '').red);
      resolve();
    }
  });
}

console.log('\n Troubleshooting AD LDAP connector\n');

(async function run() {
  await config.initialize();
  await cas.injectAsync();

  const HTTP_PROXY = process.env.HTTP_PROXY || process.env.http_proxy;
  if (HTTP_PROXY) {
    logger.info('Proxy configured: %s', HTTP_PROXY);
  } else {
    logger.info('No proxy server configured.');
  }

  await checkConnectivity();
  await checkHubConnectivity();
  await checkClockSkew();
  await checkCertificates();
  await checkNltest();
  await checkSslLdap();
  await checkLdapConnectivity();

  logger.info('Done!\n');
  process.exit(0);
})();
