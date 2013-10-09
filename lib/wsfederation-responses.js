var fs    = require('fs');
var path  = require('path');
var wsfed = require('wsfed');


var credentials = {
  cert: fs.readFileSync(path.join(__dirname, '../certs/cert.pem')),
  key:  fs.readFileSync(path.join(__dirname, '../certs/cert.key'))
};

var nconf = require('nconf');
var issuer = nconf.get('WSFED_ISSUER');

exports.token = wsfed.auth({
  issuer:      issuer,
  cert:        credentials.cert,
  key:         credentials.key,
  getPostURL:  function (wtrealm, wreply, req, callback) {
    var realmPostURLs = nconf.get(wtrealm || nconf.get('REALM'));
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
  return wsfed.metadata({
    cert:   credentials.cert,
    issuer: issuer
  });
};