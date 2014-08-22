var request  = require('request');
var nconf    = require('nconf');
var url      = require('url');
var test_url = 'https://' + url.parse(nconf.get('PROVISIONING_TICKET')).host + '/test';

function check (callback) {
  request.get({
    uri: test_url,
    json: true
  }, function (err, resp, body) {
    if (err || !body || !body.clock) {
      return callback();
    }

    var current_time = new Date().getTime();
    var dif = current_time - body.clock;

    if (dif > 5000) {
      return callback(new Error('clock skew detected'));
    }

    callback();
  });
}

function schedule () {
  setTimeout(function () {
    check(function (err) {
      if (err) {
        console.log(err.message);
        return process.exit(1);
      }
      schedule();
    });
  }, 60000);
}

schedule();