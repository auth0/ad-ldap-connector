var fs       = require('fs');
var path     = require('path');
var passport = require('passport');
var wsfed    = require('wsfed');

var callbacks = process.env.WSFED_CALLBACKS_URLS
                       .split(',')
                       .map(function (url) { 
                          return url.trim(); 
                        });

var issuer = process.env.WSFED_ISSUER;

var credentials = {
  cert: fs.readFileSync(path.join(__dirname, '/certs/contoso.pem')),
  key:  fs.readFileSync(path.join(__dirname, '/certs/contoso.key'))
};

var respondWsFederation = wsfed.auth({
  issuer:      issuer,
  callbackUrl: callbacks,
  cert:        credentials.cert,
  key:         credentials.key
});

exports.install = function (app) {
  app.get('/wsfed', 
    function (req, res, next) {
      if (req.session.user) {
        req.user = req.session.user;
        return respondWsFederation(req, res);
      }
      next();
    },
    function (req, res) {
      return res.render('login', {
        title: process.env.SITE_NAME
      });
    });

  app.post('/wsfed', function (req, res, next) {
      //authenticate the user, on success call next middleware
      passport.authenticate('local', { 
        failureRedirect: req.url,
        session: false
      })(req, res, next);
    }, function (req, res, next) {
      req.session.user = req.user;
      next();
    }, respondWsFederation);

  app.get('/wsfed/FederationMetadata/2007-06/FederationMetadata.xml',
    wsfed.metadata({
      cert:   credentials.cert,
      issuer: issuer
    }));

  app.get('/logout', function (req, res) {
    delete req.session;
    res.send('bye');
  });
};