const config = require('../lib/config');
require('../lib/setupProxy');

const multer = require('multer');
const {Readable} = require('stream');
const memoryStorage = multer.memoryStorage();
const upload = multer({memoryStorage});
const unzipper = require('unzipper');
const path = require('path');
const archiver = require('archiver');
const cas = require('../lib/add_certs');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const fs = require('fs');
const http = require('http');
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const xtend = require('xtend');
const app = express();
const freeport = require('freeport');
const test_config = require('./test_config');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const passwordStrength = require('./passwordStrength');
const ldap = require('../lib/ldap');
const secureStorage = require('../lib/secureStorage');
const certificates = require('../lib/certificates');
const { loadProvisioningTicket } = require('../lib/provisioningTicket');
const adLdapSettings = require('../lib/adLdapSettings');
const connectorServiceSecretsBridge = require('../lib/connectorServiceSecretsBridge');
const { run, restartConnectorService, getHashedAdminPassword, detectLdapSettings } = require('./utils');
const profileMapper = require('../lib/profileMapper');

const BCRYPT_SALT_ROUNDS = 12;
const SERVER_PORT = 8357;
const CONNECTOR_LOGS_FILE = path.join(__dirname, '../data/logs/connector/logs.log');

const loginRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many login attempts. Please try again later.',
});

var Users = require('../lib/users');
const {
  requireAdminPasswordSet,
  requireAuth,
  mergeConfig,
  setCurrentConfig,
  extractErrorMessage,
  injectRedirectWithError
} = require('./middleware');

const csrfProtection = csrf({cookie: true});
var detectedLdapSettings = {};

async function registerRoutes(app) {
  app.set('views', __dirname + '/views');
  app.set('view engine', 'ejs');
  app.use(express.static(__dirname + '/public'));
  app.use(cookieParser());
  app.use(bodyParser.urlencoded({extended: true}));

  let sessionSecret = await secureStorage.get(secureStorage.keys.ADMIN_CONSOLE_SESSION_SECRET);
  if (!sessionSecret) {
    sessionSecret = crypto.randomBytes(32).toString('hex');
    await secureStorage.store(secureStorage.keys.ADMIN_CONSOLE_SESSION_SECRET, sessionSecret);
  }
  app.use(
    session({
      secret: sessionSecret,
      saveUninitialized: false,
      resave: false,
      cookie: {
        maxAge: 1 * 60 * 60 * 1000,
        httpOnly: true,
        sameSite: 'strict',
      },
    })
  );

  app.use(injectRedirectWithError);

  app.get('/setup', csrfProtection, async function (req, res) {
    if (await getHashedAdminPassword()) {
      return res.redirect('/');
    }
    res.render('setup', {csrfToken: req.csrfToken()});
  });

  app.get('/login', csrfProtection, requireAdminPasswordSet, extractErrorMessage, function (req, res) {
    if (req.session.authenticated) {
      return res.redirect('/');
    }
    res.render('login', {
      csrfToken: req.csrfToken(),
      ERROR: req.errorMessage,
    });
  });

  app.post('/login', loginRateLimit, csrfProtection, requireAdminPasswordSet, async function (req, res, next) {
    const hashedAdminPassword = await getHashedAdminPassword();
    if (!hashedAdminPassword) {
      throw new Error('Admin password not found in keychain.');
    }
    const match = await bcrypt.compare(req.body.password || '', hashedAdminPassword);
    if (!match) {
      return res.redirectWithError({
        url: 'login',
        errorMessage: 'Invalid password'
      });
    }
    req.session.regenerate((err) => {
      if (err) {
        return next(err);
      }

      req.session.authenticated = true;
      res.redirect('/');
    });
  });

  app.get('/logout', function (req, res) {
    req.session.destroy((err) => {
      if (err) {
        console.error(err);
      }
      res.redirect('/login');
    });
  });

  app.use(requireAdminPasswordSet);
  app.use(requireAuth);

  app.get('/', setCurrentConfig, csrfProtection, extractErrorMessage, function (req, res) {
    res.render(
      'index',
      xtend(
        req.current_config,
        {
          SUCCESS: req.query && req.query.s === '1',
          ERROR: req.errorMessage,
          LDAP_RESULTS: req.session.LDAP_RESULTS,
        },
        {
          detected: detectedLdapSettings,
        },
        {
          csrfToken: req.csrfToken(),
        }
      )
    );
    delete req.session.LDAP_RESULTS;
  });

  app.post(
    '/ldap',
    setCurrentConfig,
    csrfProtection,
    function (req, res, next) {
      // Convert ENABLE_WRITE_BACK and ENABLE_ACTIVE_DIRECTORY_UNICODE_PASSWORD to boolean.
      req.body.ENABLE_WRITE_BACK = !!(
        req.body.ENABLE_WRITE_BACK && req.body.ENABLE_WRITE_BACK === 'on'
      );
      req.body.ENABLE_ACTIVE_DIRECTORY_UNICODE_PASSWORD = !!(
        req.body.ENABLE_ACTIVE_DIRECTORY_UNICODE_PASSWORD &&
        req.body.ENABLE_ACTIVE_DIRECTORY_UNICODE_PASSWORD === 'on'
      );

      var config = xtend({}, req.current_config, req.body);
      test_config(config, function (err, result) {
        if (err) {
          return res.render(
            'index',
            xtend(req.current_config, req.body, {
              ERROR: err.message,
              LDAP_RESULTS: result,
            })
          );
        }
        req.session.LDAP_RESULTS = result;
        next();
      });
    },
    function (req, res, next) {
      if (req.body.PORT || req.current_config.PORT) return next();
      freeport(function (er, port) {
        req.body.PORT = port;
        next();
      });
    },
    async function (req, res, next) {
      var password = req.body.LDAP_BIND_PASSWORD;
      if (!password) {
        return next();
      }
      try {
        await connectorServiceSecretsBridge.store(secureStorage.keys.LDAP_BIND_PASSWORD, password);
        ldap.resetCredentials();
        await restartConnectorService();
        next();
      } catch (err) {
        res.redirectWithError({
          errorMessage: err.message
        });
      }
    },
    mergeConfig
  );

  app.post(
    '/server',
    upload.single('SSL_PFX'),
    setCurrentConfig,
    csrfProtection,
    function (req, res, next) {
      if (req.body.PORT || req.current_config.PORT) return next();
      freeport(function (er, port) {
        req.body.PORT = port;
        next();
      });
    },
    async function (req, res, next) {
      try {
        if (!req.file || req.file.buffer.length === 0)
          return next();
        // upload pfx
        req.body.SSL_PFX = req.file.buffer.toString('base64');

        // save SSL_KEY_PASSWORD from form to secure storage
        await connectorServiceSecretsBridge.store(secureStorage.keys.CUSTOM_SSL_PFX_PASSWORD, req.body.SSL_KEY_PASSWORD || '');
        await restartConnectorService();
        next();
      } catch (err) {
        next(err);
      }
    },
    mergeConfig
  );

  app.post(
    '/ticket',
    setCurrentConfig,
    csrfProtection,
    async function (req, res, next) {
      if (!req.body.PROVISIONING_TICKET) {
        return res.redirectWithError({
          errorMessage: 'Provisioning ticket URL is required.'
        });
      }

      const provisioningTicket = req.body.PROVISIONING_TICKET;
      const ticketInfo = await loadProvisioningTicket(provisioningTicket);
      req.body.AD_HUB = ticketInfo.adHub;

      if (!detectedLdapSettings.LDAP_URL) {
        const discoveredSettings = await adLdapSettings.discoverSettings(ticketInfo.connectionDomain);
        console.dir(discoveredSettings);
        detectedLdapSettings = discoveredSettings;
      }
      next();
    },
    mergeConfig
  );

  app.get('/export', setCurrentConfig, function (req, res) {
    console.log('Exporting configuration.');

    var today = new Date()
      .toISOString()
      .substring(0, 19)
      .replace(/\:|\-/g, '')
      .replace('T', '-');

    var archive = archiver('zip', {
      zlib: {level: 9}, // Sets the compression level.
    });

    const files = [
      'data/config.json',
      'data/profileMapper/custom.js',
      'data/certs/cert.key',
      'data/certs/cert.pem',
    ];

    files.forEach((name) => {
      const fullPath = path.join(__dirname, '/../', name);
      if (!fs.existsSync(fullPath)) {
        return;
      }
      archive.file(fullPath, {name});
    });

    res.set('Content-Type', 'application/zip');
    res.set(
      'Content-Disposition',
      'attachment; filename=connector_export_' + today + '.zip'
    );
    archive.pipe(res);
    archive.finalize();
  });

  app.post(
    '/import',
    setCurrentConfig,
    csrfProtection,
    upload.single('IMPORT_FILE'),
    function (req, res, next) {
      console.log('Importing configuration.');

      if (
        !req.file ||
        req.file.buffer.length === 0
      ) {
        return res.redirectWithError({
          errorMessage: 'Upload a valid zip file.',
          anchor: 'export'
        });
      }

      var valid_files = [
        'data/certs/cert.key',
        'data/certs/cert.pem',
        'data/config.json',
        'data/profileMapper/custom.js',
        'lib/profileMapper.js',
      ];

      Readable.from(req.file.buffer)
        .pipe(unzipper.Parse())
        .on('entry', (entry) => {
          if (!valid_files.includes(entry.path)) {
            console.error(`unknown filepath ${entry.path}`);
            return entry.autodrain();
          }
          const filePath = path.join(__dirname, '/../', entry.path);
          console.log('Extracting ' + filePath);
          const fileWriteStream = fs.createWriteStream(filePath);
          entry.pipe(fileWriteStream);
        })
        .on('close', function () {
          restartConnectorService().then(() => {
            Users = require('../lib/users');
            res.redirect('/');
          }).catch((err) =>
          {
            console.error(err);
            return res.redirectWithError({
              errorMessage: 'Could not restart connector service after import.',
              anchor: 'export'
            });
          });
        }).on('error', err => {
          console.error(err);
          return res.redirectWithError({
            errorMessage: 'Upload a valid zip file.',
            anchor: 'export'
          });
        });
    }
  );

  app.get('/logs', function (req, res) {
    res.writeHead(200, {
      'Content-Type': 'text/plain',
    });

    if (!fs.existsSync(CONNECTOR_LOGS_FILE)) {
      res.write('The log file is empty.');
      return res.end();
    }

    fs.readFile(CONNECTOR_LOGS_FILE, 'utf8', function (err, data) {
      if (err) {
        res.status(500);
        res.send({
          error: err,
        });
      } else {
        res.write(data);
        res.end();
      }
    });
  });

  app.post('/logs/clear', csrfProtection, function (req, res) {
    fs.writeFile(CONNECTOR_LOGS_FILE, '', function (err) {
      if (err) {
        res.status(500);
        res.send({
          error: err,
        });
      } else {
        res.status(200);
        res.end();
      }
    });
  });

  app.get('/profile-mapper', function (req, res) {
    res.writeHead(200, {
      'Content-Type': 'text/plain',
    });

    try {
      const profileMappingScript = profileMapper.loadMappingScript({
        fallbackToDefaultScript: true
      });
      if (!profileMappingScript) {
        res.write('');
        return res.end();
      } else {
        res.write(profileMappingScript);
        res.end();
      }
    } catch (err) {
      res.status(500);
      res.send({
        error: err,
      });
    }
  });

  app.post('/profile-mapper', csrfProtection, async function (req, res) {
    try {
      profileMapper.saveMappingScript(req.body.code);
      await restartConnectorService();
      res.status(200);
      res.end();
    } catch (err) {
      res.status(500);
      res.send({
        error: err,
      });
    }
  });

  app.get('/troubleshooter/run', setCurrentConfig, function (req, res) {
    run('node', [__dirname + '/../troubleshoot.js'], function (data) {
      data = data.replace(/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]/g, '').trim();

      res.writeHead(200, {
        'Content-Type': 'text/plain',
      });
      res.write(data);
      return res.end();
    });
  });

  app.get(
    '/troubleshooter/export',
    setCurrentConfig,
    function (req, res, next) {
      console.log('Exporting test results.');

      run(process.execPath, [__dirname + '/../troubleshoot.js'], function (data) {
        data = data.replace(/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]/g, '').trim();

        req.body.TEST_RESULTS = data;
        return next();
      });
    },
    function (req, res, next) {
      console.log('Exporting files.');

      fs.readdir(__dirname + '/../', function (err, list) {
        if (err) {
          res.status(500);
          return res.send({
            error: err,
          });
        } else {
          req.body.LOG_FILES = [];
          list.forEach(function (item) {
            if (item.indexOf('.log') >= 0) {
              req.body.LOG_FILES.push(item);
            }
          });
          return next();
        }
      });
    },
    function (req, res, next) {
      var today = new Date()
        .toISOString()
        .substring(0, 19)
        .replace(/\:|\-/g, '')
        .replace('T', '-');

      var archive = archiver('zip', {
        zlib: {level: 9}, // Sets the compression level.
      });

      const files = [
        'data/config.json',
        'data/profileMapper/custom.js',
        'package.json',
      ].concat(req.body.LOG_FILES);

      files.forEach((name) => {
        const fullPath = path.join(__dirname, '/../', name);
        if (!fs.existsSync(fullPath)) {
          return;
        }
        archive.file(fullPath, {name});
      });

      archive.append(req.body.TEST_RESULTS, {
        name: 'test-results.log',
      });

      res.set('Content-Type', 'application/zip');
      res.set(
        'Content-Disposition',
        'attachment; filename=connector_troubleshoot_' + today + '.zip'
      );
      archive.pipe(res);
      archive.finalize();
    }
  );

  app.get('/version', function (req, res) {
    var p = JSON.parse(fs.readFileSync(__dirname + '/../package.json', 'utf8'));

    res.writeHead(200, {
      'Content-Type': 'text/plain',
    });
    res.write(p.version);
    return res.end();
  });

  app.get('/users/search', function (req, res) {
    var users = new Users(true);
    users.list(req.query.query, {}, function (err, users) {
      if (err) {
        res.status(500);
        res.send({
          error: err,
        });
      } else {
        res.json(users);
      }
    });
  });

  app.get('/users/by-login', function (req, res) {
    var users = new Users(true);
    users.getByUserName(req.query.query, {}, function (err, users) {
      if (err) {
        res.status(500);
        res.send({
          error: err,
        });
      } else {
        res.send(users);
      }
    });
  });

  app.post('/password', setCurrentConfig, csrfProtection, async function (req, res) {
    const currentPassword = req.body.current_password || '';
    const newPassword = req.body.new_password || '';
    const newPasswordConfirm = req.body.confirm_password || '';

    if (!passwordStrength.validate(newPassword)) {
      return res.redirectWithError({
        errorMessage: passwordStrength.validateToString(newPassword),
        anchor: 'security'
      });
    }

    if (newPassword !== newPasswordConfirm) {
      return res.redirectWithError({
        errorMessage: 'Passwords do not match.',
        anchor: 'security'
      });
    }

    try {
      const hashedPassword = await getHashedAdminPassword();
      const match = await bcrypt.compare(currentPassword, hashedPassword || '');
      if (!match) {
        return res.redirectWithError({
          errorMessage: 'Current password is incorrect.',
          anchor: 'security'
        });
      }
      const hashedNewPassword = await bcrypt.hash(newPassword, BCRYPT_SALT_ROUNDS);
      await secureStorage.store(secureStorage.keys.ADMIN_CONSOLE_PASSWORD, hashedNewPassword);
      res.redirect('/?s=1');
    } catch (err) {
      console.error(err);
      return res.redirectWithError({
        errorMessage: 'An error occurred while changing the password.',
        anchor: 'security'
      });
    }
  });
}

/**
 * Registers a final error handler so the server doesn't die on uncaught exceptions.
 *
 * @param app
 * @return {Promise<void>}
 */
async function registerErrorHandler(app) {
  app.use((err, req, res, next) => {
    console.error(err.stack);
    const message = err.message || 'Unknown error. Check logs for details.';
    return res.redirectWithError({
      errorMessage: message
    });
  });
}

/**
 * Moves the admin password setup by the installer from the local file to the secure credential storage.
 *
 * @return {Promise<void>}
 */
async function consumePendingAdminPassword() {
  const pendingPasswordPath = path.join(__dirname, '../data', '.pending-admin-password');
  if (fs.existsSync(pendingPasswordPath)) {
    try {
      const pendingHash = fs.readFileSync(pendingPasswordPath, 'utf8').trim();
      if (pendingHash) {
        await secureStorage.store(secureStorage.keys.ADMIN_CONSOLE_PASSWORD, pendingHash);
        console.log('Admin password set from installer.');
      }
    } catch (err) {
      console.error('Failed to process pending admin password:', err.message);
    } finally {
      try {
        fs.unlinkSync(pendingPasswordPath);
      } catch (_) { /* empty */ }
    }
  }
}

async function runServer() {
  http.createServer(app).listen(SERVER_PORT, '127.0.0.1', function () {
    console.log('Listening on http://localhost:8357.');
  });
}

module.exports = app;

(async function adminConsole() {
  await config.initialize();
  await certificates.initialize();
  detectedLdapSettings = await detectLdapSettings();
  await registerRoutes(app);
  await ldap.initialize();
  await config.save();
  await consumePendingAdminPassword();
  await cas.injectAsync();
  await registerErrorHandler(app);
  await runServer();
})();
