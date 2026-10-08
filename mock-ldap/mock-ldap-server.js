const ldap = require('ldapjs');
const fs = require('fs');
const { parseArgs } = require('node:util');
const db = require('./mock_ldap_data.json');
const config = require('../lib/config');
const BASE_DN = 'dc=example,dc=org';
const LDAP_SERVER_PORT = 4444;

// Serve LDAPS only when both --cert and --key are provided; otherwise fall back to
// plain LDAP. Pointing these at a cert whose issuing CA the client does not trust
// reproduces the connector's LDAPS trust failures (e.g. UNABLE_TO_GET_ISSUER_CERT_LOCALLY).
const { values: cliArgs } = parseArgs({
  options: {
    cert: { type: 'string' },
    key:  { type: 'string' },
  },
  strict: false,
});
const certPath = cliArgs.cert;
const keyPath = cliArgs.key;
const useSsl = Boolean(certPath && keyPath);
const protocol = useSsl ? 'ldaps' : 'ldap';
// LDAPS needs a host that matches the certificate SAN (localhost); plain LDAP keeps 0.0.0.0.
const host = useSsl ? 'localhost' : '0.0.0.0';

config.set('LDAP_URL', `${protocol}://${host}:${LDAP_SERVER_PORT}`);
config.set('LDAP_BASE', 'dc=example,dc=org');
config.set('LDAP_BIND_USER', 'cn=admin,dc=example,dc=org');
config.set('LDAP_BIND_PASSWORD', 'admin');
config.set('LDAP_USER_BY_NAME', '(&(objectClass=inetOrgPerson)(uid={0}))');
config.set(
  'LDAP_SEARCH_QUERY',
  '(&(objectClass=inetOrgPerson)(|(cn={0})(givenName={0})(sn={0})(uid={0})))'
);
config.set('LDAP_SEARCH_ALL_QUERY', '(objectClass=inetOrgPerson)');
config.set('LDAP_SEARCH_GROUPS', '(member={0})');

// This is an in-memory LDAP server used to run unit/integration tests
// It is based on the example of the ldapjs library: http://ldapjs.org/examples.html

function registerHandlers(s) {
  s.bind(BASE_DN, function (req, res, next) {
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

  s.search(BASE_DN, function (req, res, next) {
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
}

const serverOptions = {};
if (useSsl) {
  serverOptions.certificate = fs.readFileSync(certPath);
  serverOptions.key = fs.readFileSync(keyPath);
}
const server = ldap.createServer(serverOptions);
registerHandlers(server);

if (require.main === module) {
  server.listen(LDAP_SERVER_PORT, () => {
    console.log(`${useSsl ? 'LDAPS' : 'LDAP'} server running on ${LDAP_SERVER_PORT}`);
  });
}

module.exports = server;

// Factory for creating a fresh server with optional TLS options.
// Used by tests to spin up an LDAPS-mode server without affecting the singleton above.
module.exports.createServer = function (opts) {
  const s = ldap.createServer(opts || {});
  registerHandlers(s);
  return s;
};
