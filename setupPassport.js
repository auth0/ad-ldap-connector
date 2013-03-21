var passport = require('passport');
var WindowsStrategy = require('passport-windowsauth');

passport.use(new WindowsStrategy({ 
  ldap: {
    url:             process.env.LDAP_URL,
    base:            process.env.LDAP_BASE,
    bindDN:          process.env.LDAP_BIND_USER,
    bindCredentials: process.env.LDAP_BIND_PASSWORD
  },
  integrated:      false
}, function(user, done){
  done(null, user);
}));

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});