'use strict';

const https = require('https');
const tls = require('tls');
const fs = require('fs');
const os = require('os');
const path = require('path');
const expect = require('chai').expect;
const selfsigned = require('selfsigned');
const { startup } = require('../server');
const config = require('../lib/config');
const ldapModule = require('../lib/ldap');
const secureStorage = require('../lib/secureStorage');
const mockLdapServer = require('../mock-ldap/mock-ldap-server');

const LDAP_BASE = 'dc=example,dc=org';
const LDAP_BIND_USER = 'cn=admin,dc=example,dc=org';
const LDAP_BIND_PASS = 'admin';

// Generate a fresh self-signed certificate on each test run so the fixture
// never expires. The same cert is used both as the LDAPS server identity and
// as the CA the connector is told to trust (via SSL_CA_PATH), so a successful
// handshake proves the injected CA actually reached the ldapjs TLS context.
// SANs cover localhost / 127.0.0.1 so hostname verification passes.
function generateCert() {
  const pems = selfsigned.generate(
    [{ name: 'commonName', value: 'localhost' }],
    {
      days: 1,
      keySize: 2048,
      algorithm: 'sha256',
      extensions: [
        { name: 'basicConstraints', cA: true },
        {
          name: 'subjectAltName',
          altNames: [
            { type: 2, value: 'localhost' },
            { type: 7, ip: '127.0.0.1' },
          ],
        },
      ],
    }
  );
  return { cert: pems.cert, key: pems.private };
}

function makeStartupMocks({ injectCAs } = {}) {
  const mocks = {
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

  if (injectCAs !== undefined) {
    mocks.injectCAs = injectCAs;
  }

  return mocks;
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

describe('server.js startup — CA injection and LDAPS connectivity', function () {
  let ldapsServer;
  let tlsPort;
  let tmpDir;
  let serverCert;
  let serverKey;
  let savedCa;
  let savedRejectUnauth;

  before(async function () {
    process.env.OVERRIDE_CONFIG = 'false';
    await config.initialize();
    ({ cert: serverCert, key: serverKey } = generateCert());
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ldap-tls-test-'));
    fs.writeFileSync(path.join(tmpDir, 'ca.pem'), serverCert);
  });

  after(function () {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  beforeEach(function (done) {
    savedCa = https.globalAgent.options.ca;
    https.globalAgent.options.ca = null;
    savedRejectUnauth = tls.DEFAULT_REJECTUNAUTHORIZED;
    tls.DEFAULT_REJECTUNAUTHORIZED = true;
    // ldapjs reads process.env.NODE_TLS_REJECT_UNAUTHORIZED directly; must unset
    // it (not just tls.DEFAULT_REJECTUNAUTHORIZED) to enable real cert verification.
    delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;

    ldapsServer = mockLdapServer.createServer({
      certificate: Buffer.from(serverCert),
      key: Buffer.from(serverKey),
    });
    ldapsServer.listen(0, function () {
      tlsPort = ldapsServer.address().port;
      config.set('LDAP_URL', `ldaps://localhost:${tlsPort}`);
      config.set('LDAP_BASE', LDAP_BASE);
      config.set('LDAP_BIND_USER', LDAP_BIND_USER);
      config.set('LDAP_BIND_PASSWORD', LDAP_BIND_PASS);
      config.set('PROVISIONING_TICKET', 'https://test.auth0.com/p/test/abc123');
      config.set('SSL_CA_PATH', tmpDir);
      config.set('SSL_CA_FILE', '.+.(pem|crt|cer)$');
      done();
    });
  });

  afterEach(function () {
    ldapsServer.close();
    https.globalAgent.options.ca = savedCa;
    tls.DEFAULT_REJECTUNAUTHORIZED = savedRejectUnauth;
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  });

  it('startup injects the custom CA so subsequent LDAPS connections succeed', async function () {
    await startup(makeStartupMocks());

    // CA should have been added to the global agent by the real cas.injectAsync()
    expect(https.globalAgent.options.ca).to.be.an('array').with.length.greaterThan(0);

    // Simulate an LDAP operation arriving after startup (as a real auth request would).
    // createConnection() reads https.globalAgent.options.ca into tlsOptions.ca — this is
    // the exact path that was broken by the CA injection bug.
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

  it('startup without CA injection causes LDAPS connections to fail (regression guard)', async function () {
    await startup(makeStartupMocks({ injectCAs: async () => {} }));

    // https.globalAgent.options.ca is still null — createConnection() passes
    // tlsOptions: { ca: null }, so no custom CA is trusted.
    const client = ldapModule.createConnection();
    await new Promise((resolve, reject) => {
      let settled = false;
      const finish = (err) => {
        if (settled) return;
        settled = true;
        client.destroy();
        if (err) return resolve(); // expected: TLS handshake failure
        reject(new Error('Expected LDAPS to fail without CA injection, but connection succeeded'));
      };
      client.on('error', finish);
      client.bind(LDAP_BIND_USER, LDAP_BIND_PASS, finish);
    });
  });
});
