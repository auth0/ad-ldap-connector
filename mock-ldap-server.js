const ldap = require('ldapjs');
const db = require('./test/resources/mock_ldap_data.json');
const nconf = require('nconf');
const BASE_DN = 'dc=example,dc=org';
const LDAP_SERVER_PORT = 4444;

nconf.set('LDAP_URL', `ldap://0.0.0.0:${LDAP_SERVER_PORT}`);
nconf.set('LDAP_BASE', 'dc=example,dc=org');
nconf.set('LDAP_BIND_USER', 'cn=admin,dc=example,dc=org');
nconf.set('LDAP_BIND_PASSWORD', 'admin');
nconf.set('LDAP_USER_BY_NAME', '(&(objectClass=inetOrgPerson)(uid={0}))');
nconf.set(
  'LDAP_SEARCH_QUERY',
  '(&(objectClass=inetOrgPerson)(|(cn={0})(givenName={0})(sn={0})(uid={0})))'
);
nconf.set('LDAP_SEARCH_ALL_QUERY', '(objectClass=inetOrgPerson)');
nconf.set('LDAP_SEARCH_GROUPS', '(member={0})');

// This is an in-memory LDAP server used to run unit/integration tests
// It is based on the example of the ldapjs library: http://ldapjs.org/examples.html
const server = ldap.createServer();

server.bind(BASE_DN, function (req, res, next) {
  if (!req.credentials || req.credentials === '') {
    return next(new ldap.InvalidCredentialsError());
  }
  
  var dn = req.dn.format({ skipSpace: true });
  if (!db[dn]) return next(new ldap.NoSuchObjectError(dn));

  if (!db[dn].userPassword)
    return next(new ldap.NoSuchAttributeError('userPassword'));

  if (db[dn].userPassword !== req.credentials)
    return next(new ldap.InvalidCredentialsError());

  res.end();
  return next();
});

server.search(BASE_DN, function (req, res, next) {
  var dn = req.dn.format({ skipSpace: true });
  if (!db[dn]) return next(new ldap.NoSuchObjectError(dn));

  var scopeCheck;

  switch (req.scope) {
  case 'base':
    if (req.filter.matches(db[dn])) {
      res.send({
        dn: dn,
        attributes: db[dn],
      });
    }

    res.end();
    return next();

  case 'one':
    scopeCheck = function (k) {
      if (req.dn.equals(k)) return true;

      var parent = ldap.parseDN(k).parent();
      return parent ? parent.equals(req.dn) : false;
    };
    break;

  case 'sub':
    scopeCheck = function (k) {
      return req.dn.equals(k) || req.dn.parentOf(k);
    };

    break;
  }

  Object.keys(db).forEach(function (key) {
    if (!scopeCheck(key)) return;

    if (req.filter.matches(db[key])) {
      res.send({
        dn: key,
        attributes: db[key],
      });
    }
  });

  res.end();
  return next();
});

server.listen(LDAP_SERVER_PORT, () => {
  console.log(`LDAP server running on ${LDAP_SERVER_PORT}`);
});
