var WebSocket = require('ws');

var jwt = require('jsonwebtoken');
var nconf = require('nconf');
var fs = require('fs');
var Users = require('./lib/users');
var users = new Users();

var cert = {
  key:  fs.readFileSync(__dirname + '/certs/cert.key'),
  cert: fs.readFileSync(__dirname + '/certs/cert.pem')
};

var socket_server_address = nconf.get('AD_HUB').replace(/^http/i, 'ws');
var ws = new WebSocket(socket_server_address);
var profileMapper = require('./lib/profileMapper');

console.log('connecting to ' + socket_server_address.green);


ws.sendEvent = function (name, payload) {
  this.send(JSON.stringify({
    n: name,
    p: payload
  }));
};

function ping (client) {
  client.ping();

  var check = setTimeout(function () {
    console.log("server didn't respond ping command");
    process.exit(1);
  }, 5000);

  client.once('pong', function () {
    clearTimeout(check);
  });
}

ws.on('open', function () {
  authenticate_connector();
}).on('message', function (msg) {
  console.log(m);
  var m;
  try {
    m = JSON.parse(msg);
  } catch (er) {
    return;
  }
  if (!m || !m.n) return;
  this.emit(m.n, m.p);
}).on('error', function (err) {
  console.error('socket error: ' + err);
  process.exit(1);
}).on('authenticated', function () {
  console.log('authenticated!');
  var client = this;
  setInterval(function () {
    ping(client);
  }, 10000);
}).on('authentication_failure', function () {
  console.error('authentication failure');
  process.exit(0);
}).on('close', function () {
  console.error('connection closed');
  process.exit(1);
}).on('authenticate_user', function (msg) {
  jwt.verify(msg.jwt, nconf.get('TENANT_SIGNING_KEY'), function (err, payload) {
    if (err) {
      console.error('unauthorized attemp of authentication');
      return;
    }
    users.validate(payload.username, payload.password, function (err, user) {
      if (err) return ws.sendEvent(payload.pid + '_result', {err: err});

      if (!user) {
        return ws.sendEvent(payload.pid + '_result', {
          err: new Error('wrong username or password')
        });
      }

      var profile = profileMapper(user);

      console.log('user ' + (profile.nickname || profile.displayName || '').green + ' authenticated');

      ws.sendEvent(payload.pid + '_result', {
        profile: profile
      });
    });
  });
});

function authenticate_connector() {
  var token = jwt.sign({}, cert.key, {
    algorithm: 'RS256',
    expiresInMinutes: 1,
    issuer: nconf.get('CONNECTION'),
    audience: nconf.get('REALM')
  });
  ws.sendEvent('authenticate', { jwt: token });
}