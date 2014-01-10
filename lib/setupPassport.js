var passport        = require('passport');
var WindowsStrategy = require('passport-windowsauth');
var nconf           = require('nconf');
var profileMapper   = require('./profileMapper');

if (nconf.get('LDAP_URL')) {

  var Users           = require('./users');
  var users           = new Users();

  function finish(preprofile, done) {
    if (!preprofile) return done();

    var profile = profileMapper(preprofile._json);

    users.getAllGroups(preprofile._json, function (err, groups) {
      if (err) {
        return done(null, profile);
      }

      profile.groups = groups.map(function (g) {
        return g.cn;
      });

      return done(null, profile);
    });
  }

  passport.use('IISIntegrated', new WindowsStrategy({
    ldap: {
      url:             nconf.get("LDAP_URL"),
      base:            nconf.get("LDAP_BASE"),
      bindDN:          nconf.get("LDAP_BIND_USER"),
      bindCredentials: nconf.get("LDAP_BIND_PASSWORD")
    }
  }, finish));

  passport.use('ApacheKerberos', new WindowsStrategy({
    ldap: {
      url:             nconf.get("LDAP_URL"),
      base:            nconf.get("LDAP_BASE"),
      bindDN:          nconf.get("LDAP_BIND_USER"),
      bindCredentials: nconf.get("LDAP_BIND_PASSWORD")
    },
    getUserNameFromHeader: function (req) {
      var forwarded_user = req.headers['x-forwarded-user'];

      if (!forwarded_user || forwarded_user === '(null)'){
        return null;
      }

      if (~forwarded_user.indexOf('@')) {
        return forwarded_user.split('@')[0];
      } else if (~forwarded_user.indexOf('\\')) {
        return forwarded_user.split('\\')[1];
      }

      return forwarded_user;
    }
  }, finish));

  passport.use('WindowsAuthentication', new WindowsStrategy({
    ldap: {
      url:             nconf.get("LDAP_URL"),
      base:            nconf.get("LDAP_BASE"),
      bindDN:          nconf.get("LDAP_BIND_USER"),
      bindCredentials: nconf.get("LDAP_BIND_PASSWORD")
    },
    integrated:      false
  }, finish));

} else {
  //LDAP connectivity is not yet setup, use a fake user.
  var LocalStrategy = require('passport-local').Strategy;
  passport.use('WindowsAuthentication', new LocalStrategy(function (username, password, done) {
    if (username === 'test' && password === '123') {
      return done(null, {
                          id:           123,
                          username:     'test',
                          displayName:  'test user',
                          name: {
                            familyName: 'user',
                            givenName:  'test'
                          },
                          emails:   [ { value: 'foo@bar.com'} ]
                        });
    }
    done(null, false);
  }));

}

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});
