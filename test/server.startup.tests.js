'use strict';

const expect = require('chai').expect;
const { startup } = require('../server');
const config = require('../lib/config');
const ldapModule = require('../lib/ldap');
const secureStorage = require('../lib/secureStorage');
const mockLdapServer = require('../mock-ldap/mock-ldap-server');

const LDAP_BASE = 'dc=example,dc=org';
const LDAP_BIND_USER = 'cn=admin,dc=example,dc=org';
const LDAP_BIND_PASS = 'admin';

// Stubs for every dependency that makes a network/disk/keychain call, leaving
// ldapInit at its default so the real LDAP connection path runs end-to-end
// against the in-memory mock server. This exercises the injectable startup()
// scaffold without touching real infrastructure.
function makeStartupMocks() {
  return {
    processBridgeFile: async () => {},
    configInitialize: async () => {},
    configSave: async () => {},
    loadTicket: async () => ({
      adHub: 'https://test.auth0.com',
      connectionDomain: 'test.auth0.com',
      connectionName: 'test-connection',
      certAuth: false,
      kerberos: false,
      realm: { name: 'test-realm', postTokenUrl: '' },
    }),
    initCerts: async () => {},
    configureAuth0LDAPConnection: async () => ({
      serverUrl: 'https://test.auth0.com',
      certThumbprint: 'test-thumbprint',
      tenantSigningKey: 'test-signing-key',
    }),
    storageGet: async (key) => {
      if (key === secureStorage.keys.LDAP_BIND_PASSWORD) return LDAP_BIND_PASS;
      return null;
    },
    startClockSkewDetector: () => {},
    startWsValidator: () => {},
    startLatencyTest: () => {},
  };
}

describe('server.js startup — scaffold and basic LDAP connectivity', function () {
  let ldapServer;
  let port;

  before(async function () {
    process.env.OVERRIDE_CONFIG = 'false';
    await config.initialize();
  });

  beforeEach(function (done) {
    ldapServer = mockLdapServer.createServer({});
    ldapServer.listen(0, function () {
      port = ldapServer.address().port;
      config.set('LDAP_URL', `ldap://localhost:${port}`);
      config.set('LDAP_BASE', LDAP_BASE);
      config.set('LDAP_BIND_USER', LDAP_BIND_USER);
      config.set('LDAP_BIND_PASSWORD', LDAP_BIND_PASS);
      config.set('PROVISIONING_TICKET', 'https://test.auth0.com/p/test/abc123');
      done();
    });
  });

  afterEach(function () {
    ldapServer.close();
  });

  it('runs the full injectable startup sequence to completion with injected mocks', async function () {
    // Every external dependency is replaced with a stub, so startup() resolves
    // without touching the network, disk, or keychain. This verifies the
    // dependency-injection scaffold and that the module can be required without
    // auto-starting the connector (require.main === module guard).
    await startup(makeStartupMocks());
  });

  it('establishes a basic LDAP connection after startup (bind + search)', async function () {
    await startup(makeStartupMocks());

    // createConnection() uses the plain ldap:// LDAP_URL configured above, so a
    // bind + search exercises the same client path the connector uses at runtime.
    const client = ldapModule.createConnection();
    await new Promise((resolve, reject) => {
      client.bind(LDAP_BIND_USER, LDAP_BIND_PASS, (err) => {
        if (err) { client.destroy(); return reject(err); }
        client.search(LDAP_BASE, { filter: '(objectClass=inetOrgPerson)', scope: 'sub' }, (err, res) => {
          if (err) { client.destroy(); return reject(err); }
          const uids = [];
          res.on('searchEntry', e => uids.push(e.object.uid));
          res.on('end', () => {
            client.destroy();
            try {
              expect(uids).to.have.members(['jdoe', 'mdoe', 'jd()e']);
              resolve();
            } catch (e) { reject(e); }
          });
          res.on('error', (e) => { client.destroy(); reject(e); });
        });
      });
    });
  });
});
