var https = require('https');
var fs = require('fs');
var path = require('path');
var exec = require('child_process').exec;
var async = require('async');
var nconf = require('nconf');

const SSL_OPENSSLDIR_PATTERN = new RegExp(nconf.get('SSL_OPENSSLDIR_PATTERN'));
const SSL_CA_PATH = nconf.get('SSL_CA_PATH');
const SSL_CA_FILE = new RegExp(nconf.get('SSL_CA_FILE'), ((process.platform === 'win32') ? 'i': ''));

function addCertificates(cb){
  return function(err, certificates) {
    if (err) {
      console.error('Custom/System CAs could not be imported', err);
      return cb(err);
    }

    if (certificates) {
      var cas = https.globalAgent.options.ca =
        https.globalAgent.options.ca || [];

      if (!cas.__added){
        console.log('Adding', certificates.length, 'certificates');
        certificates.forEach(function (cert) {
          cas.push(cert.pem);
        });
        cas.__added = true;
      }
    }
    cb();
  }
}

function readPEM(file, cb){
  fs.readFile(file, function(err,data) {
    if (err) return cb(err);

    cb(null, {pem: data});
  });
}

function readCertficatesFromPath(certPath, cb){
  console.log('Reading CA certificates from', certPath);
  fs.readdir(certPath, function(err, files) {
    if (err) cb (err);

    files = files
      .filter(function (file){ return SSL_CA_FILE.test(file);})
      .map(function(file) {
        return path.join(certPath, file);
      });
    async.map(files, readPEM, cb);
  });
}

function readSystemCAs(cb) {
  switch(process.platform) {
    case 'win32':
      console.log('Reading CA certificates from Windows Store');
      const ca = require('win-ca');
      const list = [];
      ca({
        format: ca.der2.pem,
        store: ['root', 'ca', 'trustedpeople'],
        ondata: list
      });
      cb(null, list.map(c => ({ pem: c })));
      break;
    case 'freebsd':
    case 'linux':
      console.log('Reading CA certificates from OPENSSLDIR');
      exec('openssl version -d', function(err, stdout, stderr){
        if (err) return cb(err);

        var match = SSL_OPENSSLDIR_PATTERN.exec(stdout);
        if (match && match.length > 1) {
          return readCertficatesFromPath(path.join(match[1], 'certs'), cb);
        }

        cb();
      });
      break;
    default:
      console.warn('CA import is not implemented for platform', process.platform);
      cb();
  }
}

function getCAs(cb) {
  if (SSL_CA_PATH) {
    readCertficatesFromPath(SSL_CA_PATH, cb);
  } else {
    readSystemCAs(cb);
  }
}

function injectHttpsCAs(cb) {
  getCAs(addCertificates(cb));
}

module.exports = {
  inject: injectHttpsCAs,
  getSystemCAs : getCAs
};
