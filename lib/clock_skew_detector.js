const axios = require('axios');
const nconf = require('nconf');
const url = require('url');
const test_url =
  'https://' + url.parse(nconf.get('PROVISIONING_TICKET')).host + '/test';
const exit = require('./exit');

function check(callback) {
  axios
    .get(test_url)
    .then((response) => {
      const body = response.data;

      if (!body || !body.clock) {
        return callback();
      }

      const auth0_time = body.clock;
      const local_time = new Date().getTime();
      const dif = Math.abs(auth0_time - local_time);

      if (dif > 5000) {
        var message = [
          'Clock skew detected.',
          '- Local time: ' + new Date(local_time),
          '- Auth0 time: ' + new Date(auth0_time),
        ].join('\n');

        return callback(new Error(message));
      }
    })
    .finally(() => {
      return callback();
    });
}

function schedule() {
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
