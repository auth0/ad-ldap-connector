require('../lib/add_certs');
var os = require('os');
var fs = require('fs');
var zip = require('adm-zip');
var http = require('http');
var express = require('express');
var xtend = require('xtend');
var request = require('request');
var urlJoin = require('url-join');
var exec = require('child_process').exec;
var app = express();
var freeport = require('freeport');
var multipart = require('connect-multiparty');
var test_config = require('./test_config');
var Users = require('../lib/users');

require('../lib/initConf');
require('../lib/setupProxy');

app.configure(function() {
  this.set('views', __dirname + '/views');
  this.set('view engine', 'ejs');
  this.use(express.static(__dirname + '/public'));
  this.use(express.urlencoded());
  this.use(express.cookieParser());
  this.use(express.session({
    secret: 'sojo sut ed oterces le'
  }));
});

var detected_settings = {};

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
  return exec('net stop "Auth0 ADLDAP"', function() {
    exec('net start "Auth0 ADLDAP"', function() {
      setTimeout(function() {
        return cb();
      }, 2000);
    });
  });
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

app.get('/', set_current_config, function(req, res) {
  console.log(req.session.LDAP_RESULTS);
  res.render('index', xtend(req.current_config, {
    SUCCESS: req.query && req.query.s === '1',
    LDAP_RESULTS: req.session.LDAP_RESULTS
  }, {
    detected: detected_settings
  }));
  delete req.session.LDAP_RESULTS;
});

app.post('/ldap', set_current_config, function(req, res, next) {
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

app.post('/ticket', set_current_config, function(req, res, next) {
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
    if (err && err.code === 'ECONNREFUSED') {
      console.error('Unable to reach auth0 at: ' + info_url);
      return res.render('index', xtend(req.current_config, {
        ERROR: 'Unable to connect to Auth0, verify internet connectivity.'
      }));
    }

    if (err) {
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

    next();
  });
}, merge_config);

app.get('/export', set_current_config, function(req, res) {
  console.log('Exporting configuration.');

  var today = new Date().toISOString()
    .substring(0, 19)
    .replace(/\:|\-/g, '')
    .replace('T', '-');

  var exp = new zip();
  if (fs.existsSync(__dirname + '/../config.json')) {
    exp.addLocalFile(__dirname + '/../config.json');
  }
  if (fs.existsSync(__dirname + '/../lib/profileMapper.js')) {
    exp.addLocalFile(__dirname + '/../lib/profileMapper.js', 'lib/');
  }
  if (fs.existsSync(__dirname + '/../certs/cert.key')) {
    exp.addLocalFile(__dirname + '/../certs/cert.key', 'certs/');
  }
  if (fs.existsSync(__dirname + '/../certs/cert.pem')) {
    exp.addLocalFile(__dirname + '/../certs/cert.pem', 'certs/');
  }

  var data = exp.toBuffer();
  res.set('Content-Type', 'application/zip')
  res.set('Content-Disposition', 'attachment; filename=connector_export_' + today + '.zip');
  res.set('Content-Length', data.length);
  res.end(data, 'binary');
});

app.post('/import', set_current_config, multipart(), function(req, res, next) {
  console.log('Importing configuration.');

  if (!req.files || !req.files.IMPORT_FILE || req.files.IMPORT_FILE.size === 0) {
    return res.render('index', xtend(req.current_config, {
      ERROR: 'Upload a valid zip file.'
    }));
  }

  var valid_files = ['certs/cert.key', 'certs/cert.pem', 'config.json', 'lib/profileMapper.js'];

  var config = new zip(req.files.IMPORT_FILE.path);
  config.getEntries().forEach(function(entry) {
    var entryName = entry.entryName;
    if (valid_files.indexOf(entryName) >= 0) {
      console.log('Extracting ' + entryName);

      config.extractEntryTo(entryName, __dirname + '/../', true, true);
    }
  });

  return restart_server(function() {
    return res.render('index', xtend(read_current_config(), {
      SUCCESS: true
    }));
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

app.post('/logs/clear', function(req, res) {
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

app.post('/profile-mapper', function(req, res) {
  fs.writeFile(__dirname + '/../lib/profileMapper.js', req.body.code, function(err) {
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

    var node_process = 'node';
    if (process.platform === 'win32') {
      node_process = __dirname + '/../node.exe';
    }

    run(node_process, [__dirname + '/../troubleshoot.js'], function(data) {
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

    var exp = new zip();
    if (fs.existsSync(__dirname + '/../config.json')) {
      exp.addLocalFile(__dirname + '/../config.json');
    }
    if (fs.existsSync(__dirname + '/../lib/profileMapper.js')) {
      exp.addLocalFile(__dirname + '/../lib/profileMapper.js');
    }
    if (fs.existsSync(__dirname + '/../package.json')) {
      exp.addLocalFile(__dirname + '/../package.json');
    }

    exp.addFile("test-results.log", req.body.TEST_RESULTS);

    req.body.LOG_FILES.forEach(function(file) {
      exp.addLocalFile(__dirname + '/../' + file);
    });

    var data = exp.toBuffer();
    res.set('Content-Type', 'application/zip')
    res.set('Content-Disposition', 'attachment; filename=connector_troubleshoot_' + today + '.zip');
    res.set('Content-Length', data.length);
    res.end(data, 'binary');
  });

app.post('/updater/run', set_current_config, function(req, res) {
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
  var users = new Users(false);
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
  var users = new Users(false);
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

http.createServer(app).listen(8357, '127.0.0.1', function() {
  console.log('Listening on http://localhost:8357.');
});
