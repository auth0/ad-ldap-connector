require('../lib/initConf');
require('../lib/setupProxy');

var unzipper = require('unzipper');
var path = require('path');
var archiver = require('archiver');
var cas = require('../lib/add_certs');
var csrf = require('csurf');
var os = require('os');
var fs = require('fs');
var http = require('http');
var express = require('express');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var session = require('express-session')
var logger = require('morgan');
var xtend = require('xtend');
var request = require('request');
var urlJoin = require('url-join');
var exec = require('child_process').exec;
var app = express();
var freeport = require('freeport');
var multipart = require('connect-multiparty');
var test_config = require('./test_config');
var Users = require('../lib/users');

app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');
app.use(express.static(__dirname + '/public'));
app.use(bodyParser.urlencoded({extended:true}));
app.use(cookieParser());
app.use(session({
  secret: 'sojo sut ed oterces le'
}));
var csrfProtection = csrf({ cookie: true });
var detected_settings = {};

if (process.platform === 'win32') {
  exec('"' + __dirname + '//settings_detector.exe"', function(err, stdout, stderr) {
    console.log(arguments);
    try {
      var parsed = JSON.parse(stdout);
      console.log(parsed);
      if (parsed.error) {
        parsed = {};
        return;
      }
      detected_settings.LDAP_BASE = parsed.baseDN;
      detected_settings.LDAP_URL = 'ldap://' + parsed.domainController;
    } catch (er) {}
  });
}

function read_current_config() {
  var current_config = {};
  try {
    var content = fs.readFileSync(__dirname + '/../config.json', 'utf8');
    current_config = JSON.parse(content);
  } catch (err) {}
  return current_config;
}

function set_current_config(req, res, next) {
  req.current_config = read_current_config();
  next();
}

function restart_server(cb) {
   // required to test immediately after configuration
  require('../lib/initConf');
  Users = require('../lib/users');

  if (process.platform === 'win32') {
    console.log('Restarting Auth0 ADLDAP Service...');
    return exec('net stop "Auth0 ADLDAP"', function() {
      exec('net start "Auth0 ADLDAP"', function() {
        console.log('Done.');
        setTimeout(function() {
          return cb();
        }, 2000);
      });
    });
  }

  cb();
}

function merge_config(req, res) {
  var new_config = xtend(req.current_config, req.body);
  fs.writeFileSync(__dirname + '/../config.json',
    JSON.stringify(new_config, null, 2));

  if (req.body.LDAP_URL || req.body.PORT || req.body.SERVER_URL) {
    return restart_server(function() {
      return res.redirect('/?s=1');
    });
  }

  res.redirect('/');
}

function run(cmd, args, callback) {
  var spawn = require('child_process').spawn;
  var command = spawn(cmd, args);
  var result = '';
  command.stderr.on('data', function(data) {
    result += data.toString();
  });
  command.stdout.on('data', function(data) {
    result += data.toString();
  });
  command.on('close', function(code) {
    return callback(result);
  });
}

app.get('/', set_current_config, csrfProtection, function(req, res) {
  console.log(req.session.LDAP_RESULTS);
  res.render('index', xtend(req.current_config, {
    SUCCESS: req.query && req.query.s === '1',
    LDAP_RESULTS: req.session.LDAP_RESULTS
  }, {
    detected: detected_settings
  }, {
    csrfToken: req.csrfToken()
  }));
  delete req.session.LDAP_RESULTS;
});

app.post('/ldap', set_current_config, csrfProtection, function(req, res, next) {
  // Convert ENABLE_WRITE_BACK and ENABLE_ACTIVE_DIRECTORY_UNICODE_PASSWORD to boolean.
  req.body.ENABLE_WRITE_BACK = !!(req.body.ENABLE_WRITE_BACK && req.body.ENABLE_WRITE_BACK === 'on');
  req.body.ENABLE_ACTIVE_DIRECTORY_UNICODE_PASSWORD = !!(req.body.ENABLE_ACTIVE_DIRECTORY_UNICODE_PASSWORD && req.body.ENABLE_ACTIVE_DIRECTORY_UNICODE_PASSWORD === 'on');

  var config = xtend({}, req.current_config, req.body);
  test_config(config, function(err, result) {
    if (err) {
      return res.render('index', xtend(req.current_config, req.body, {
        ERROR: err.message,
        LDAP_RESULTS: result
      }));
    }
    req.session.LDAP_RESULTS = result;
    console.log(req.session.LDAP_RESULTS);
    next();
  });
}, function(req, res, next) {
  if (req.body.PORT || req.current_config.PORT) return next();
  freeport(function(er, port) {
    req.body.PORT = port;
    next();
  });
}, merge_config);

app.post('/server', multipart(), set_current_config, function(req, res, next) {
  if (req.body.PORT || req.current_config.PORT) return next();
  freeport(function(er, port) {
    req.body.PORT = port;
    next();
  });
}, function(req, res, next) {
  if (!req.files || !req.files.SSL_PFX || req.files.SSL_PFX.size === 0) return next();
  // upload pfx
  fs.readFile(req.files.SSL_PFX.path, function(err, pfxContent) {
    req.body.SSL_PFX = new Buffer(pfxContent).toString('base64');
    delete req.files;
    next();
  });
}, merge_config);

app.post('/ticket', set_current_config, csrfProtection, function(req, res, next) {
  if (!req.body.PROVISIONING_TICKET) {
    return res.render('index', xtend(req.current_config, {
      ERROR: 'The ticket url ' + req.body.PROVISIONING_TICKET + ' is not vaild.'
    }));
  }

  var info_url = urlJoin(req.body.PROVISIONING_TICKET, '/info');

  request.get({
    url: info_url,
    json: true
  }, function(err, resp, body) {
    if (err){
      if (err.code === 'ECONNREFUSED') {
        console.error('Unable to reach auth0 at: ' + info_url);
        return res.render('index', xtend(req.current_config, {
          ERROR: 'Unable to connect to Auth0, verify internet connectivity.'
        }));
      }

      if (err.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || err.code ==='CERT_UNTRUSTED') {
        console.error('The Auth0 certificate at ' + info_url + ' could not be validated', err);
        return res.render('index', xtend(req.current_config, {
          ERROR: 'The Auth0 server is using a certificate issued by an untrusted Certification Authority. Go to https://auth0.com/docs/connector/ca-certificates for instructions on how to install your certificate Authority. \n ' + err.message
        }));
      }

      if (err.code === 'DEPTH_ZERO_SELF_SIGNED_CERT') {
        console.error('The Auth0 certificate at ' + info_url + ' could not be validated', err);
        return res.render('index', xtend(req.current_config, {
          ERROR: 'The Auth0 server is using a selg-signed certificate. Go to https://auth0.com/docs/connector/ca-certificates for instructions on how to install your certificate. \n' + err.message
        }));
      }

      return res.render('index', xtend(req.current_config, {
        ERROR: 'Network error: ' + err.message
      }));
    }

    if (resp.statusCode !== 200 || !body || !body.adHub) {
      return res.render('index', xtend(req.current_config, {
        ERROR: 'Wrong ticket url.'
      }));
    }

    req.body.AD_HUB = body.adHub;

    if (!detected_settings.LDAP_URL) {
      var adLdapSettings = require('../connector-setup/steps/ad-ldap-settings.js');
      adLdapSettings.discoverSettings(body.connectionDomain, function(config) {
        console.dir(config);
        detected_settings = config;
        next();
      });
    } else {
      next();
    }
  });
}, merge_config);

app.get('/export', set_current_config, function(req, res) {
  console.log('Exporting configuration.');

  var today = new Date().toISOString()
    .substring(0, 19)
    .replace(/\:|\-/g, '')
    .replace('T', '-');

  var archive = archiver('zip', {
    zlib: { level: 9 } // Sets the compression level.
  });

  const files = [
    'config.json',
    'lib/profileMapper.js',
    'certs/cert.key',
    'certs/cert.pem'
  ];

  files.forEach(name => {
    const fullPath = path.join(__dirname, '/../', name);
    if (!fs.existsSync(fullPath)) { return; }
    archive.file(fullPath, { name });
  });

  res.set('Content-Type', 'application/zip')
  res.set('Content-Disposition', 'attachment; filename=connector_export_' + today + '.zip');
  archive.pipe(res);
  archive.finalize();
});

app.post('/import', set_current_config, csrfProtection, multipart(), function(req, res, next) {
  console.log('Importing configuration.');

  if (!req.files || !req.files.IMPORT_FILE || req.files.IMPORT_FILE.size === 0) {
    return res.render('index', xtend(req.current_config, {
      ERROR: 'Upload a valid zip file.'
    }));
  }

  var valid_files = ['certs/cert.key', 'certs/cert.pem', 'config.json', 'lib/profileMapper.js'];

  fs.createReadStream(req.files.IMPORT_FILE.path)
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
    .on('close', function() {
      restart_server(function() {
        res.render('index', xtend(read_current_config(), {
          SUCCESS: true
        }));
      });
    });
});

app.get('/logs', function(req, res) {
  res.writeHead(200, {
    "Content-Type": "text/plain"
  });

  if (!fs.existsSync(__dirname + '/../logs.log')) {
    res.write('The log file is empty.');
    return res.end();
  }

  fs.readFile(__dirname + '/../logs.log', "utf8", function(err, data) {
    if (err) {
      res.status(500);
      res.send({
        error: err
      });
    } else {
      res.write(data);
      res.end();
    }
  });
});

app.post('/logs/clear', csrfProtection, function(req, res) {
  fs.writeFile(__dirname + '/../logs.log', '', function(err) {
    if (err) {
      res.status(500);
      res.send({
        error: err
      });
    } else {
      res.status(200);
      res.end();
    }
  });
});

app.get('/profile-mapper', function(req, res) {
  res.writeHead(200, {
    "Content-Type": "text/plain"
  });

  if (!fs.existsSync(__dirname + '/../lib/profileMapper.js')) {
    res.write('');
    return res.end();
  }

  fs.readFile(__dirname + '/../lib/profileMapper.js', "utf8", function(err, data) {
    if (err) {
      res.status(500);
      res.send({
        error: err
      });
    } else {
      res.write(data);
      res.end();
    }
  });
});

app.post('/profile-mapper', csrfProtection, function(req, res) {
  fs.writeFile(__dirname + '/../lib/profileMapper.js', req.body.code, function(err) {
    if (err) {
      res.status(500);
      res.send({
        error: err
      });
    } else {
      return restart_server(function() {
        res.status(200);
        res.end();
      });
    }
  });
});

app.get('/troubleshooter/run', set_current_config, function(req, res) {
  run('node', [__dirname + '/../troubleshoot.js'], function(data) {
    data = data.replace(/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]/g, '').trim();

    res.writeHead(200, {
      "Content-Type": "text/plain"
    });
    res.write(data);
    return res.end();
  });
});

app.get('/troubleshooter/export', set_current_config,
  function(req, res, next) {
    console.log('Exporting test results.');

    run(process.execPath, [__dirname + '/../troubleshoot.js'], function(data) {
      data = data.replace(/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]/g, '').trim();

      req.body.TEST_RESULTS = data;
      return next();
    });
  },
  function(req, res, next) {
    console.log('Exporting files.');

    fs.readdir(__dirname + '/../', function(err, list) {
      if (err) {
        res.status(500);
        return res.send({
          error: err
        });
      } else {
        req.body.LOG_FILES = [];
        list.forEach(function(item) {
          if (item.indexOf('.log') >= 0) {
            req.body.LOG_FILES.push(item);
          }
        });
        return next();
      }
    });
  },
  function(req, res, next) {
    var today = new Date().toISOString()
      .substring(0, 19)
      .replace(/\:|\-/g, '')
      .replace('T', '-');

    var archive = archiver('zip', {
      zlib: { level: 9 } // Sets the compression level.
    });

    const files = [
      'config.json',
      'lib/profileMapper.js',
      'package.json'
    ].concat(req.body.LOG_FILES);

    files.forEach(name => {
      const fullPath = path.join(__dirname, '/../', name);
      if (!fs.existsSync(fullPath)) { return; }
      archive.file(fullPath, { name });
    });

    archive.append(req.body.TEST_RESULTS, {
      name: 'test-results.log'
    });

    res.set('Content-Type', 'application/zip')
    res.set('Content-Disposition', 'attachment; filename=connector_troubleshoot_' + today + '.zip');
    archive.pipe(res);
    archive.finalize();
  });

app.post('/updater/run', csrfProtection, set_current_config, function(req, res) {
  run(__dirname + '/../update-connector.cmd', [], function(data) {
    res.writeHead(200, {
      "Content-Type": "text/plain"
    });
    res.write(data);
    return res.end();
  });
});

app.get('/updater/logs', function(req, res) {

  res.writeHead(200, {
    "Content-Type": "text/plain"
  });

  if (!fs.existsSync(os.tmpdir() + '/adldap-update.log')) {
    res.write('');
    return res.end();
  }

  fs.readFile(os.tmpdir() + '/adldap-update.log', "utf8", function(err, data) {
    if (err) {
      res.status(500);
      res.send({
        error: err
      });
    } else {
      res.write(data.replace(/\n\r\n/g, "\n"));
      res.end();
    }
  });
});

app.get('/version', function(req, res) {
  var p = JSON.parse(fs.readFileSync(__dirname + '/../package.json', 'utf8'));

  res.writeHead(200, {
    "Content-Type": "text/plain"
  });
  res.write(p.version);
  return res.end();
});


app.get('/users/search', function(req, res) {
  var users = new Users(true);
  users.list(req.query.query, function(err, users) {
    if (err) {
      res.status(500);
      res.send({
        error: err
      });
    }
    else {
      res.json(users);
    }
  });
});

app.get('/users/by-login', function(req, res) {
  var users = new Users(true);
  users.getByUserName(req.query.query, function(err, users) {
    if (err) {
      res.status(500);
      res.send({
        error: err
      });
    }
    else {
      res.send(users);
    }
  });
});

cas.inject(function(err) {
  if (err) console.log('Custom CA certificates were not loaded',err);

  http.createServer(app).listen(8357, '127.0.0.1', function() {
    console.log('Listening on http://localhost:8357.');
  });
});
