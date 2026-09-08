const https = require('https');
const fs = require('fs');
const path = require('path');
const exec = require('child_process').exec;
const async = require('async');
const { promisify } = require('util');
const ca = require('win-ca');
const config = require('./config');
const process = require('node:process');

let SSL_OPENSSLDIR_PATTERN;
let SSL_CA_PATH;
let SSL_CA_FILE;

/**
 * Node by default uses a set of well-known CAs, but in some environments (e.g. corporate environments with custom CAs)
 * it may be necessary to add additional CAs to the trusted list.
 *
 * This module provides functionality to do that by reading certificates from the system or a specified directory
 * and adding them to the https agent's options.
 */

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
  };
}

function readPEM(file, cb){
  fs.readFile(file, function(err,data) {
    if (err) return cb(err);

    cb(null, {pem: data});
  });
}

function readCertificatesFromPath(certPath, cb){
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
  const list = [];
  switch(process.platform) {
  case 'win32':
    console.log('Reading CA certificates from Windows Store');
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
        return readCertificatesFromPath(path.join(match[1], 'certs'), cb);
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
    readCertificatesFromPath(SSL_CA_PATH, cb);
  } else {
    readSystemCAs(cb);
  }
}

function injectHttpsCAs(cb) {
  SSL_OPENSSLDIR_PATTERN = new RegExp(config.get('SSL_OPENSSLDIR_PATTERN'));
  SSL_CA_PATH = config.get('SSL_CA_PATH');
  SSL_CA_FILE = new RegExp(config.get('SSL_CA_FILE'), ((process.platform === 'win32') ? 'i': ''));
  getCAs(addCertificates(cb));
}

module.exports = {
  inject: injectHttpsCAs,
  injectAsync: promisify(injectHttpsCAs),
};
