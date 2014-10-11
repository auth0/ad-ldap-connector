var passport        = require('passport');
var WindowsStrategy = require('passport-windowsauth');
var SslCertStrategy = require('passport-ssl-certificate');
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
      url:             nconf.get('LDAP_URL'),
      base:            nconf.get('LDAP_BASE'),
      bindDN:          nconf.get('LDAP_BIND_USER'),
      bindCredentials: nconf.get('LDAP_BIND_PASSWORD'),
      search_query:    nconf.get('LDAP_USER_BY_NAME')
    }
  }, finish));

  passport.use('ApacheKerberos', new WindowsStrategy({
    ldap: {
      url:             nconf.get('LDAP_URL'),
      base:            nconf.get('LDAP_BASE'),
      bindDN:          nconf.get('LDAP_BIND_USER'),
      bindCredentials: nconf.get('LDAP_BIND_PASSWORD'),
      search_query:    nconf.get('LDAP_USER_BY_NAME')
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
      url:             nconf.get('LDAP_URL'),
      base:            nconf.get('LDAP_BASE'),
      bindDN:          nconf.get('LDAP_BIND_USER'),
      bindCredentials: nconf.get('LDAP_BIND_PASSWORD'),
      search_query:    nconf.get('LDAP_USER_BY_NAME')
    },
    integrated:      false
  }, finish));

  passport.use('ClientCertAuthentication', new SslCertStrategy({passReqToCallback: true}, function (req, cert, done) {
    req.session.cert = cert;

    if (!cert.subject) {
      return done(new Error('Specified certificate does not contain subject attribute'));
    }

    console.log('Authenticating user from certificate with subject.CN: ' + cert.subject.CN);

    // get user by certificate subject
    users.getByUserName(cert.subject.CN, function (err, rawProfile) {
      if (err) { return done(err); }
      finish({_json: rawProfile}, done);
    });
  }));

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
