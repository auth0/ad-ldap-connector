var passport              = require('passport');
var wsfederationResponses = require('./lib/wsfederation-responses');
var nconf                 = require('nconf');

exports.install = function (app) {

  app.get('/wsfed',
    function (req, res, next) {
      passport.authenticate({
        failureRedirect: req.url,
        failureMessage: "The username or password you entered is incorrect.",
        session: false
      }, function (err, profile) {
        if (err) return next(err);
        if (!profile) return next();
        req.session.user = profile;
        next();
      })(req, res, next);
    },
    function (req, res, next) {
      if (req.session.user && req.query.wprompt !== 'consent') {
        req.user = req.session.user;
        return wsfederationResponses.token(req, res);
      }
      next();
    },
    function (req, res) {
      var messages = (req.session.messages || []).join('<br />');
      delete req.session.messages;
      return res.render('login', {
        title: nconf.get('SITE_NAME'),
        errors: messages
      });
    });

  app.post('/wsfed', function (req, res, next) {
      passport.authenticate('WindowsAuthentication', {
        failureRedirect: req.url,
        failureMessage: "The username or password you entered is incorrect.",
        session: false
      })(req, res, next);
    }, function (req, res, next) {
      console.log('user ' + (req.user.displayName || 'unknown').green + ' authenticated');
      req.session.user = req.user;
      next();
    }, wsfederationResponses.token);

  app.get('/logout', function (req, res) {
    console.log('user ' + (req.session.user.displayName || 'unknown').green + ' logged out');
    delete req.session;
    res.send('bye');
  });

  app.get('/wsfed/FederationMetadata/2007-06/FederationMetadata.xml',
    wsfederationResponses.metadata());
};