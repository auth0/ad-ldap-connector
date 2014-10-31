var fs      = require('fs');
var http    = require('http');
var express = require('express');
var xtend   = require('xtend');
var request = require('request');
var urlJoin = require('url-join');
var exec    = require('child_process').exec;
var app     = express();
var freeport = require('freeport');
var multipart = require('connect-multiparty');
var test_config = require('./test_config');

require('../lib/setupProxy');

app.configure(function () {
  this.set('views', __dirname + '/views');
  this.set('view engine', 'ejs');
  this.use(express.static(__dirname + '/public'));
  this.use(express.urlencoded());
  this.use(express.cookieParser());
  this.use(express.session({ secret: 'sojo sut ed oterces le' }));
});

var detected_settings = {};

exec('"' + __dirname + '//settings_detector.exe"', function (err, stdout, stderr) {
  console.log(arguments);
  try {
    var parsed = JSON.parse(stdout);
    console.log(parsed);
    if (parsed.error) {
      parsed = {};
      return;
    }
    detected_settings.LDAP_BASE = parsed.baseDN;
    detected_settings.LDAP_URL =  'ldap://' + parsed.domainController;
  }catch(er) {}
});

function set_current_config (req, res, next) {
  var current_config = {};
  try {
    var content = fs.readFileSync(__dirname + '/../config.json', 'utf8');
    current_config = JSON.parse(content);
  }catch(err){}
  req.current_config = current_config;
  next();
}

function merge_config (req, res) {
  var new_config = xtend(req.current_config, req.body);
  fs.writeFileSync(__dirname + '/../config.json',
      JSON.stringify(new_config, null, 2));

  if(req.body.LDAP_URL || req.body.PORT || req.body.SERVER_URL) {
    return exec('net stop "Auth0 ADLDAP"', function () {
      exec('net start "Auth0 ADLDAP"', function () {
        setTimeout(function () {
          return res.redirect('/?s=1');
        }, 2000);
      });
    });
  }

  res.redirect('/');
}

app.get('/', set_current_config, function (req, res) {
  console.log(req.session.LDAP_RESULTS);
  res.render('index', xtend(req.current_config, {
    SUCCESS: req.query && req.query.s === '1',
    LDAP_RESULTS: req.session.LDAP_RESULTS
  }, { detected: detected_settings }));
  delete req.session.LDAP_RESULTS;
});

app.post('/ldap', set_current_config, function (req, res, next) {
  var config = xtend({}, req.body, req.current_config);
  test_config(config, function (err, result) {
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
}, function (req, res, next) {
  if (req.body.PORT || req.current_config.PORT) return next();
  freeport(function (er, port) {
    req.body.PORT = port;
    next();
  });
} , merge_config);

app.post('/server', multipart(), set_current_config, function (req, res, next) {
  if (req.body.PORT || req.current_config.PORT) return next();
  freeport(function (er, port) {
    req.body.PORT = port;
    next();
  });
}, function (req, res, next) {
  if (!req.files || !req.files.SSL_PFX || req.files.SSL_PFX.size === 0) return next();
  // upload pfx
  fs.readFile(req.files.SSL_PFX.path, function (err, pfxContent) {
    req.body.SSL_PFX = new Buffer(pfxContent).toString('base64');
    delete req.files;
    next();
  });
}, merge_config);

app.post('/ticket', set_current_config, function (req, res, next) {
  if (!req.body.PROVISIONING_TICKET) {
    return res.render('index', xtend(req.current_config, {
      ERROR: 'The ticket url ' + req.body.PROVISIONING_TICKET + ' is not vaild.'
    }));
  }

  var info_url = urlJoin(req.body.PROVISIONING_TICKET, '/info');

  request.get({
    url:  info_url,
    json: true
  }, function (err, resp, body) {
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

http.createServer(app).listen(8357, '127.0.0.1', function () {
  console.log('listening on http://localhost:8357');
});