var request  = require('request');
var nconf    = require('nconf');
var url      = require('url');
var test_url = 'https://' + url.parse(nconf.get('PROVISIONING_TICKET')).host + '/test';
var exit     = require('./exit');

function check (callback) {
  request.get({
    uri: test_url,
    json: true
  }, function (err, resp, body) {
    if (err || !body || !body.clock) {
      return callback();
    }

    var auth0_time = body.clock;
    var local_time = new Date().getTime();
    var dif = Math.abs(auth0_time - local_time);

    if (dif > 5000) {
      var message = [ 'Clock skew detected.',
                      '- Local time: ' + new Date(local_time),
                      '- Auth0 time: ' + new Date(auth0_time)].join('\n');

      return callback(new Error(message));
    }

    callback();
  });
}

function schedule () {
  setTimeout(function () {
    check(function (err) {
      if (err) {
        console.error(err.message);
        return exit(1);
      }
      schedule();
    });
  }, 5000);
}

schedule();