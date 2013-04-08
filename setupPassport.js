var passport = require('passport');
var WindowsStrategy = require('passport-windowsauth');
var nconf = require('nconf');

if (nconf.get('LDAP_URL')) {
  passport.use(new WindowsStrategy({ 
    ldap: {
      url:             nconf.get("LDAP_URL"),
      base:            nconf.get("LDAP_BASE"),
      bindDN:          nconf.get("LDAP_BIND_USER"),
      bindCredentials: nconf.get("LDAP_BIND_PASSWORD")
    },
    integrated:      false
  }, function(user, done){
    done(null, user);
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
