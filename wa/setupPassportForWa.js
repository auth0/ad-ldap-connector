var WindowsStrategy = require('passport-windowsauth');
var passport = require('passport');

passport.use(new WindowsStrategy({ 
  ldap: {
    url:             process.env.LDAP_URL,
    base:            process.env.LDAP_BASE,
    bindDN:          process.env.LDAP_BIND_USER,
    bindCredentials: process.env.LDAP_BIND_PASSWORD
  }
}, function(user, done){
  done(null, user);
}));

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});