var fs              = require('fs');
var path            = require('path');
var wsfed           = require('wsfed');
var xtend           = require('xtend');
var cookieSessions  = require('cookie-sessions');

var credentials = {
  cert: fs.readFileSync(path.join(__dirname, '../certs/cert.pem')),
  key:  fs.readFileSync(path.join(__dirname, '../certs/cert.key'))
};

var nconf   = require('nconf');
var issuer  = nconf.get('WSFED_ISSUER');
var audience = nconf.get('REALM');

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

exports.tokenDirect = function (req, res, next) {

  var wctx = xtend({
    strategy: 'ad'
  }, req.body, {
    session: cookieSessions.serialize(nconf.get('SESSION_SECRET'), req.session)
  });

  delete wctx.username;
  delete wctx.password;

  return wsfed.auth({
    issuer:      issuer,
    cert:        credentials.cert,
    key:         credentials.key,
    audience:    audience,
    plain_form:  true,
    wctx:        JSON.stringify(wctx),
    getPostURL:  function (wtrealm, wreply, req, callback) {
      var realmPostURLs = nconf.get(wtrealm || nconf.get('REALM'));
      if (realmPostURLs) {
        realmPostURLs = realmPostURLs.split(',');
        
        if (wreply && ~realmPostURLs.indexOf(wreply)) {
          return callback(null, wreply);
        }

        if (!wreply) {
          return callback(null, realmPostURLs[0]);
        }
      }

      callback();
    }
  })(req, res, next);
};

exports.metadata = function () {
  return wsfed.metadata({
    cert:   credentials.cert,
    issuer: issuer
  });
};
