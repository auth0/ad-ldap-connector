var fs    = require('fs');
var path  = require('path');
var wsfed = require('wsfed');

var wsfedMiddleware = wsfed({
  issuer:       'wellscordoba-idp',
  callbackUrl:  'https://mdocs.auth0.com/login/callback',
  cert:         fs.readFileSync(path.join(__dirname, '/certs/wsfed.test-cert.pem')),
  key:          fs.readFileSync(path.join(__dirname, '/certs/wsfed.test-cert.key')),
  endpointPath: '/wsfed/'
});

module.exports = wsfedMiddleware;