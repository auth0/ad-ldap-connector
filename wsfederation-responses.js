var fs = require('fs');
var path = require('path');
var wsfed = require('wsfed');

var issuer = process.env.WSFED_ISSUER;

var credentials = {
  cert: fs.readFileSync(path.join(__dirname, '/certs/cert.pem')),
  key:  fs.readFileSync(path.join(__dirname, '/certs/cert.key'))
};

exports.token = wsfed.auth({
  issuer:      issuer,
  cert:        credentials.cert,
  key:         credentials.key,
  getPostURL:  function (wtrealm, wreply, req, callback) {
    var realmPostURLs = process.env['REALM-' + wtrealm];
    if (realmPostURLs) {
      realmPostURLs = realmPostURLs.split(',');
      if (wreply && ~realmPostURLs.indexOf(wreply)) {
        return callback(null, wreply);
      }
      if(!wreply){
        return callback(null, realmPostURLs[0]);
      }
    }
    callback();
  }
});

exports.metadata = function () {
  if (process.env.AUTHENTICATION === 'INTEGRATED') {
    return wsfed.metadata({
        cert:   credentials.cert,
        issuer: issuer,
        endpointPath: '/wa'
      });
  }
  return wsfed.metadata({
    cert:   credentials.cert,
    issuer: issuer
  });
};