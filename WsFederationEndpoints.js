var fs       = require('fs');
var path     = require('path');
var passport = require('passport');
var wsfed    = require('wsfed');

var callbacks = process.env.WSFED_CALLBACKS_URLS
                       .split(',')
                       .map(function (url) { return url.trim(); });

var issuer = process.env.WSFED_ISSUER;

var credentials = {
  cert: fs.readFileSync(path.join(__dirname, '/certs/contoso.pem')),
  key:  fs.readFileSync(path.join(__dirname, '/certs/contoso.key'))
};

exports.install = function (app) {
  app.post('/wsfed', function (req, res, next) {
    //authenticate the user, on success call next middleware
    passport.authenticate('local', { 
      failureRedirect: req.url,
      session:         false
    })(req, res, next);
  }, 
  function (req, res, next) {
    console.log(req.user);
    next();
  }, wsfed.auth({
    issuer:      issuer,
    callbackUrl: callbacks,
    cert:        credentials.cert,
    key:         credentials.key
  }));

  app.get('/wsfed/FederationMetadata/2007-06/FederationMetadata.xml',
    wsfed.metadata({
      cert:   credentials.cert,
      issuer: issuer
    }));
};