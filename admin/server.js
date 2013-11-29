var fs      = require('fs');
var http    = require('http');
var express = require('express');
var xtend   = require('xtend');
var request = require('request');
var urlJoin = require('url-join');
var test_ldap = require('./test_ldap');

var app     = express();

app.configure(function () {
  this.set('views', __dirname + '/views');
  this.set('view engine', 'ejs');
  this.use(express.static(__dirname + '/public'));
  this.use(express.urlencoded());
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

  if(req.body.LDAP_URL) {
    return res.redirect('/?s=1');
  }

  res.redirect('/');
}

app.get('/', set_current_config, function (req, res) {
  res.render('index', xtend(req.current_config, {
    SUCCESS: req.query && req.query.s === '1'
  }));
});

app.get('/test-ldap', set_current_config, function (req, res) {
  test_ldap(req.current_config, function (err) {
    if (err) {
      return res.json(400, {
        ERROR: err.message
      });
    }
    res.send(200);
  });
});

app.post('/ldap', set_current_config, function (req, res, next) {
  test_ldap(req.body, function (err) {
    console.log(err);
    if (err) {
      return res.render('index', xtend(req.current_config, req.body, {
        ERROR: err.message
      }));
    }
    next();
  });
}, merge_config);

app.post('/ticket', set_current_config, function (req, res, next) {
  if (!req.body.PROVISIONING_TICKET) {
    return res.render('index', xtend(req.current_config, {
      ERROR: 'The ticket url ' + req.body.PROVISIONING_TICKET + ' is not vaild.'
    }));
  }

  request(urlJoin(req.body.PROVISIONING_TICKET, '/info'), function (err, resp, body) {
    var payload = {};
    try{
      payload = JSON.parse(body);
    } catch(ex){}
    if (err || resp.statusCode !== 200 || !payload.realm) {
      return res.render('index', xtend(req.current_config, {
        ERROR: 'The ticket url ' + req.body.PROVISIONING_TICKET + ' is not vaild.'
      }));
    }

    next();
  });
}, merge_config);

http.createServer(app).listen(8357, '127.0.0.1', function () {
  console.log('listening on http://localhost:8357');
});