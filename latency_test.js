var latency_test = module.exports;
const axios = require('axios');
const _ = require('lodash');
const async = require('async');
const nconf = require('nconf');
const url = require('url');
const test_url =
  'https://' + url.parse(nconf.get('PROVISIONING_TICKET')).host + '/test';
const exit = require('./lib/exit');

/**
 * test the url and return the ns
 * @param  {[type]}   message [description]
 * @param  {Function} done    [description]
 * @return {[type]}           [description]
 */
latency_test.run = function (done) {
  var start = process.hrtime();
  axios
    .get(test_url)
    .then((response) => {
      var took = process.hrtime(start);
      done(null, took[0] * 1e9 + took[1]);
    })
    .catch((err) => done(err));
};

latency_test.run_many = function (n, done) {
  async.mapSeries(
    _.range(n),
    function (n, callback) {
      latency_test.run(callback);
    },
    function (err, times) {
      if (err) {
        console.log('Error when doing the latency test, exiting.');
        exit(1);
      }

      var sum = times.reduce(function (prev, curr) {
        return prev + curr;
      }, 0);

      var max = times.reduce(function (prev, curr) {
        return Math.max(prev, curr);
      }, 0);

      var min = times.reduce(function (prev, curr) {
        return Math.min(prev, curr);
      }, Infinity);

      var result = [sum / n, max, min].map(function (nanos) {
        return (nanos / 1e6).toFixed(2);
      });

      console.log(
        'latency test took avg: %d ms, max: %d ms, min: %d ms',
        result[0],
        result[1],
        result[2]
      );

      if (done) {
        done(null, result);
      }
    }
  );
};

if (require.main === module) {
  latency_test.run_many(10);
}
