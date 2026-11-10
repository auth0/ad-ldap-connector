require('colors');

const { expect } = require('chai');
const crypto = require('crypto');
const forge = require('node-forge');
const jwt = require('jsonwebtoken');

const { SigningKeys } = require('../lib/signingKeys');

const PROVISIONING_TICKET = 'https://tenant.example.com/p/ad/abc123';
const JWKS_URI = 'https://tenant.example.com/.well-known/jwks.json';

/**
 * Generates an RSA key pair and the matching JWKS entry for a given kid.
 */
function generateKey(kid) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

  const jwk = publicKey.export({ format: 'jwk' });
  jwk.kid = kid;
  jwk.use = 'sig';
  jwk.alg = 'RS256';

  return {
    kid,
    jwk,
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString()
  };
}

function sign(key, payload = { username: 'jsmith' }) {
  return jwt.sign(payload, key.privatePem, { algorithm: 'RS256', keyid: key.kid });
}

function makeConfig(values = {}) {
  const store = Object.assign({ PROVISIONING_TICKET: PROVISIONING_TICKET }, values);

  return {
    values: store,
    get: (key) => store[key],
    set: (key, value) => {
      store[key] = value;
    },
    saveCalls: 0,
    save: async function () {
      this.saveCalls++;
    }
  };
}

/**
 * Minimal axios stub that records the URLs it was asked for.
 */
function makeAxios(handler) {
  return {
    requests: [],
    get: function (url, options) {
      this.requests.push({ url, options });
      return handler(url, options);
    }
  };
}

function jwksResponse(keys) {
  return Promise.resolve({ data: { keys: keys.map((k) => k.jwk) } });
}

/**
 * Stub for the provisioning ticket process. `answers` is the signing key the server returns on each
 * call ('' means "no key, read the JWKS yourself"); the last answer repeats. Records every call.
 */
function makeTicket(...answers) {
  const calls = [];
  const fn = async (args) => {
    calls.push(args);
    const answer = answers[Math.min(calls.length - 1, answers.length - 1)];
    if (answer instanceof Error) {
      throw answer;
    }
    return { serverUrl: 'https://connector.example.com', certThumbprint: 'aa:bb', tenantSigningKey: answer };
  };
  fn.calls = calls;
  return fn;
}

/**
 * A key the hub signs with when the tenant is still on the deprecated behaviour: no kid in the token.
 */
function signWithoutKid(key, payload = { username: 'jsmith' }) {
  return jwt.sign(payload, key.privatePem, { algorithm: 'RS256' });
}

describe('signingKeys', () => {

  describe('mode detection', () => {
    it('uses JWKS when the server did not send a signing key', () => {
      const signingKeys = new SigningKeys({ configModule: makeConfig() });

      expect(signingKeys.useJwks()).to.equal(true);
    });

    it('uses JWKS when the stored signing key is blank', () => {
      const signingKeys = new SigningKeys({
        configModule: makeConfig({ TENANT_SIGNING_KEY: '   ' })
      });

      expect(signingKeys.useJwks()).to.equal(true);
    });

    it('uses the static key when the server sent a signing key', () => {
      const signingKeys = new SigningKeys({
        configModule: makeConfig({ TENANT_SIGNING_KEY: 'a-global-client-key' })
      });

      expect(signingKeys.useJwks()).to.equal(false);
    });
  });

  describe('jwksUri', () => {
    it('derives the JWKS document from the provisioning ticket origin', () => {
      const signingKeys = new SigningKeys({ configModule: makeConfig() });

      expect(signingKeys.jwksUri()).to.equal(JWKS_URI);
    });

    it('throws when there is no provisioning ticket', () => {
      const config = makeConfig();
      config.set('PROVISIONING_TICKET', undefined);
      const signingKeys = new SigningKeys({ configModule: config });

      expect(() => signingKeys.jwksUri()).to.throw(/PROVISIONING_TICKET is not set/);
    });
  });

  describe('verify in JWKS mode', () => {
    it('verifies a token signed with a key from the JWKS document', (done) => {
      const key = generateKey('kid-1');
      const axiosStub = makeAxios(() => jwksResponse([key]));
      const signingKeys = new SigningKeys({
        configModule: makeConfig(),
        axiosModule: axiosStub
      });

      signingKeys.verify(sign(key), (err, payload) => {
        expect(err).to.equal(null);
        expect(payload.username).to.equal('jsmith');
        expect(axiosStub.requests[0].url).to.equal(JWKS_URI);
        done();
      });
    });

    it('selects the key matching the kid when several are published', (done) => {
      const keyOne = generateKey('kid-1');
      const keyTwo = generateKey('kid-2');
      const signingKeys = new SigningKeys({
        configModule: makeConfig(),
        axiosModule: makeAxios(() => jwksResponse([keyOne, keyTwo]))
      });

      // Signed with the second key, so selection by kid is what makes this pass.
      signingKeys.verify(sign(keyTwo), (err, payload) => {
        expect(err).to.equal(null);
        expect(payload.username).to.equal('jsmith');
        done();
      });
    });

    it('rejects a token whose kid is not published', (done) => {
      const published = generateKey('kid-1');
      const rogue = generateKey('kid-unknown');
      const signingKeys = new SigningKeys({
        configModule: makeConfig(),
        axiosModule: makeAxios(() => jwksResponse([published]))
      });

      signingKeys.verify(sign(rogue), (err) => {
        expect(err).to.be.ok;
        expect(err.message).to.match(/kid "kid-unknown"/);
        done();
      });
    });

    it('rejects a token signed by a different key with a published kid', (done) => {
      const published = generateKey('kid-1');
      // Same kid, different key material - a forged token.
      const forged = generateKey('kid-1');
      const signingKeys = new SigningKeys({
        configModule: makeConfig(),
        axiosModule: makeAxios(() => jwksResponse([published]))
      });

      signingKeys.verify(sign(forged), (err) => {
        expect(err).to.be.ok;
        expect(err.message).to.match(/invalid signature/i);
        done();
      });
    });

    it('rejects an HS256 token forged with the published public key as the secret', (done) => {
      const key = generateKey('kid-1');
      const signingKeys = new SigningKeys({
        configModule: makeConfig(),
        axiosModule: makeAxios(() => jwksResponse([key]))
      });

      // Classic algorithm confusion attack: sign with HMAC using the public key as the secret.
      const forged = jwt.sign({ username: 'attacker' }, key.publicPem, {
        algorithm: 'HS256',
        keyid: 'kid-1'
      });

      signingKeys.verify(forged, (err) => {
        expect(err).to.be.ok;
        expect(err.message).to.match(/invalid algorithm/i);
        done();
      });
    });

    it('falls back to the single published key when the token carries no kid', (done) => {
      const key = generateKey('kid-1');
      const signingKeys = new SigningKeys({
        configModule: makeConfig(),
        axiosModule: makeAxios(() => jwksResponse([key]))
      });

      const token = jwt.sign({ username: 'jsmith' }, key.privatePem, { algorithm: 'RS256' });

      signingKeys.verify(token, (err, payload) => {
        expect(err).to.equal(null);
        expect(payload.username).to.equal('jsmith');
        done();
      });
    });

    it('refuses to guess when the token has no kid and several keys are published', (done) => {
      const keyOne = generateKey('kid-1');
      const keyTwo = generateKey('kid-2');
      const signingKeys = new SigningKeys({
        configModule: makeConfig(),
        axiosModule: makeAxios(() => jwksResponse([keyOne, keyTwo]))
      });

      const token = jwt.sign({ username: 'jsmith' }, keyOne.privatePem, { algorithm: 'RS256' });

      signingKeys.verify(token, (err) => {
        expect(err).to.be.ok;
        expect(err.message).to.match(/no kid/);
        done();
      });
    });

    it('re-fetches on an unknown kid even while the cached document is still fresh', async () => {
      const oldKey = generateKey('kid-old');
      const newKey = generateKey('kid-new');
      let current = [oldKey];
      const axiosStub = makeAxios(() => jwksResponse(current));
      const signingKeys = new SigningKeys({
        configModule: makeConfig(),
        axiosModule: axiosStub,
        // Long freshness window, no cooldown: rotation must still be picked up.
        cacheMaxAgeMs: 60 * 60 * 1000,
        minRefreshIntervalMs: 0
      });

      const first = await new Promise((resolve) => signingKeys.verify(sign(oldKey), resolve));
      expect(first).to.equal(null);

      // The tenant rotates to a new kid without the cache having expired.
      current = [newKey];
      const payload = await new Promise((resolve, reject) => {
        signingKeys.verify(sign(newKey), (err, p) => err ? reject(err) : resolve(p));
      });

      expect(payload.username).to.equal('jsmith');
      expect(axiosStub.requests).to.have.length(2);
    });

    it('caches the JWKS document across verifications', async () => {
      const key = generateKey('kid-1');
      const axiosStub = makeAxios(() => jwksResponse([key]));
      const signingKeys = new SigningKeys({
        configModule: makeConfig(),
        axiosModule: axiosStub
      });

      const verifyOnce = () => new Promise((resolve) => signingKeys.verify(sign(key), resolve));

      await verifyOnce();
      await verifyOnce();
      await verifyOnce();

      expect(axiosStub.requests).to.have.length(1);
    });

    it('shares a single request between concurrent refreshes', async () => {
      const key = generateKey('kid-1');
      let resolveFetch;
      const axiosStub = makeAxios(() => new Promise((resolve) => {
        resolveFetch = () => resolve({ data: { keys: [key.jwk] } });
      }));
      const signingKeys = new SigningKeys({
        configModule: makeConfig(),
        axiosModule: axiosStub
      });

      const first = signingKeys.refresh();
      const second = signingKeys.refresh();
      resolveFetch();
      await Promise.all([first, second]);

      expect(axiosStub.requests).to.have.length(1);
    });
  });

  describe('verify in static key mode', () => {
    it('verifies against the key the server sent, without touching the JWKS endpoint', (done) => {
      const key = generateKey('kid-1');
      const axiosStub = makeAxios(() => {
        throw new Error('the JWKS endpoint must not be called in static key mode');
      });
      const signingKeys = new SigningKeys({
        configModule: makeConfig({ TENANT_SIGNING_KEY: key.publicPem }),
        axiosModule: axiosStub
      });

      signingKeys.verify(sign(key), (err, payload) => {
        expect(err).to.equal(null);
        expect(payload.username).to.equal('jsmith');
        expect(axiosStub.requests).to.have.length(0);
        done();
      });
    });

    it('rejects an HS256 token forged with the static key as the secret', (done) => {
      const key = generateKey('kid-1');
      const signingKeys = new SigningKeys({
        configModule: makeConfig({ TENANT_SIGNING_KEY: key.publicPem })
      });

      // Same algorithm-confusion attack as JWKS mode: the static key is asymmetric, so an HMAC
      // token signed with it as the secret must not verify.
      const forged = jwt.sign({ username: 'attacker' }, key.publicPem, { algorithm: 'HS256' });

      signingKeys.verify(forged, (err) => {
        expect(err).to.be.ok;
        expect(err.message).to.match(/invalid algorithm/i);
        done();
      });
    });
  });

  describe('static key mode with a certificate', () => {
    /**
     * Makes an RSA key pair and a self-signed certificate that is valid between the given years.
     */
    function generateCertificate(validFromYear, validToYear) {
      const keys = forge.pki.rsa.generateKeyPair(2048);
      const cert = forge.pki.createCertificate();
      cert.publicKey = keys.publicKey;
      cert.serialNumber = '01';
      cert.validity.notBefore = new Date(Date.UTC(validFromYear, 0, 1));
      cert.validity.notAfter = new Date(Date.UTC(validToYear, 0, 1));
      const subject = [{ name: 'commonName', value: 'global-client-key' }];
      cert.setSubject(subject);
      cert.setIssuer(subject);
      cert.sign(keys.privateKey, forge.md.sha256.create());

      return {
        certificatePem: forge.pki.certificateToPem(cert),
        privatePem: forge.pki.privateKeyToPem(keys.privateKey)
      };
    }

    const verifyAsync = (signingKeys, token) => new Promise((resolve) => {
      signingKeys.verify(token, (err, payload) => resolve({ err, payload }));
    });

    // Like the hub: RS256, no expiry claim, no kid.
    const signMessage = (privatePem, options = {}) => jwt.sign(
      { pid: 'a-request-id', username: 'jsmith' },
      privatePem,
      { algorithm: 'RS256', ...options }
    );

    it('accepts a message signed with a key whose certificate has expired', async () => {
      const expired = generateCertificate(2019, 2020);
      const signingKeys = new SigningKeys({
        configModule: makeConfig({ TENANT_SIGNING_KEY: expired.certificatePem })
      });

      const { err, payload } = await verifyAsync(signingKeys, signMessage(expired.privatePem));

      // Verification does not look at the dates of the certificate, only at the signature.
      expect(err).to.equal(null);
      expect(payload.username).to.equal('jsmith');
      expect(payload.pid).to.equal('a-request-id');
    });

    it('rejects a message signed with a different key than the certificate', async () => {
      const expired = generateCertificate(2019, 2020);
      const other = generateCertificate(2019, 2020);
      const signingKeys = new SigningKeys({
        configModule: makeConfig({ TENANT_SIGNING_KEY: expired.certificatePem })
      });

      const { err } = await verifyAsync(signingKeys, signMessage(other.privatePem));

      expect(err).to.be.ok;
      expect(err.message).to.match(/invalid signature/i);
    });

    it('still rejects a message whose own expiry claim is in the past', async () => {
      const expired = generateCertificate(2019, 2020);
      const signingKeys = new SigningKeys({
        configModule: makeConfig({ TENANT_SIGNING_KEY: expired.certificatePem })
      });
      const token = signMessage(expired.privatePem, { expiresIn: -60 });

      const { err } = await verifyAsync(signingKeys, token);

      expect(err).to.be.ok;
      expect(err.name).to.equal('TokenExpiredError');
    });
  });

  describe('JWKS fetch failures', () => {
    it('surfaces a verification error when the JWKS document cannot be fetched', (done) => {
      const key = generateKey('kid-1');
      const signingKeys = new SigningKeys({
        configModule: makeConfig(),
        axiosModule: makeAxios(() => Promise.reject(new Error('ECONNREFUSED')))
      });

      signingKeys.verify(sign(key), (err) => {
        expect(err).to.be.ok;
        expect(err.message).to.match(/kid "kid-1"/);
        done();
      });
    });

    it('rejects a JWKS document without a keys array', async () => {
      const signingKeys = new SigningKeys({
        configModule: makeConfig(),
        axiosModule: makeAxios(() => Promise.resolve({ data: {} }))
      });

      let error;
      await signingKeys.refresh().catch((err) => { error = err; });

      expect(error).to.be.ok;
      expect(error.message).to.match(/no "keys" array/);
    });

    it('rejects a JWKS document with no usable keys', async () => {
      const unusable = generateKey('kid-1');
      unusable.jwk.kty = 'OKP';
      const signingKeys = new SigningKeys({
        configModule: makeConfig(),
        axiosModule: makeAxios(() => Promise.resolve({ data: { keys: [unusable.jwk] } }))
      });

      let error;
      await signingKeys.refresh().catch((err) => { error = err; });

      expect(error).to.be.ok;
      expect(error.message).to.match(/No usable signing keys/);
    });

    it('keeps serving previously cached keys when a later fetch fails', async () => {
      const key = generateKey('kid-1');
      let shouldFail = false;
      const signingKeys = new SigningKeys({
        configModule: makeConfig(),
        axiosModule: makeAxios(() => shouldFail
          ? Promise.reject(new Error('ECONNREFUSED'))
          : jwksResponse([key])),
        cacheMaxAgeMs: 0,
        minRefreshIntervalMs: 0
      });

      await signingKeys.refresh({ force: true });
      shouldFail = true;
      await signingKeys.refresh({ force: true }).catch(() => {});

      // The cache was not cleared by the failed fetch, so verification still works.
      const payload = await new Promise((resolve, reject) => {
        signingKeys.verify(sign(key), (err, p) => err ? reject(err) : resolve(p));
      });
      expect(payload.username).to.equal('jsmith');
    });

    it('skips entries that are not signature keys', async () => {
      const sigKey = generateKey('kid-sig');
      const encKey = generateKey('kid-enc');
      encKey.jwk.use = 'enc';
      const signingKeys = new SigningKeys({
        configModule: makeConfig(),
        axiosModule: makeAxios(() => jwksResponse([sigKey, encKey]))
      });

      await signingKeys.refresh();

      // The encryption key was dropped, so a token signed with it cannot be verified.
      const err = await new Promise((resolve) => {
        signingKeys.verify(sign(encKey), resolve);
      });
      expect(err).to.be.ok;
      expect(err.message).to.match(/kid "kid-enc"/);
    });
  });

  describe('refreshOnReconnect', () => {
    it('re-reads the JWKS document when the server sent no signing key', async () => {
      const key = generateKey('kid-1');
      const axiosStub = makeAxios(() => jwksResponse([key]));
      const signingKeys = new SigningKeys({
        configModule: makeConfig(),
        axiosModule: axiosStub,
        configureConnectionFn: makeTicket(''),
        minRefreshIntervalMs: 0
      });

      const refreshed = await signingKeys.refreshOnReconnect();

      expect(refreshed).to.equal(true);
      expect(axiosStub.requests).to.have.length(1);
      expect(axiosStub.requests[0].url).to.equal(JWKS_URI);
    });

    it('picks up a rotated key on reconnect', async () => {
      const oldKey = generateKey('kid-old');
      const newKey = generateKey('kid-new');
      let current = [oldKey];
      const signingKeys = new SigningKeys({
        configModule: makeConfig(),
        axiosModule: makeAxios(() => jwksResponse(current)),
        configureConnectionFn: makeTicket(''),
        minRefreshIntervalMs: 0
      });

      await signingKeys.refreshOnReconnect();

      // The tenant rotates its signing key while the socket is down.
      current = [newKey];
      await signingKeys.refreshOnReconnect();

      const payload = await new Promise((resolve, reject) => {
        signingKeys.verify(sign(newKey), (err, p) => err ? reject(err) : resolve(p));
      });
      expect(payload.username).to.equal('jsmith');
    });

    it('re-runs the provisioning ticket process when the server sent a signing key', async () => {
      const config = makeConfig({ TENANT_SIGNING_KEY: 'an-old-key', CONNECTION: 'my-ad' });
      const calls = [];
      const axiosStub = makeAxios(() => {
        throw new Error('the JWKS endpoint must not be called in static key mode');
      });
      const signingKeys = new SigningKeys({
        configModule: config,
        axiosModule: axiosStub,
        minRefreshIntervalMs: 0,
        // configureConnection returns the refreshed values; signingKeys persists them.
        configureConnectionFn: async (args) => {
          calls.push(args);
          return { serverUrl: 'https://connector.example.com', certThumbprint: 'aa:bb', tenantSigningKey: 'a-rotated-key' };
        }
      });

      const refreshed = await signingKeys.refreshOnReconnect();

      expect(refreshed).to.equal(true);
      expect(calls).to.have.length(1);
      expect(calls[0].provisioningTicket).to.equal(PROVISIONING_TICKET);
      expect(calls[0].connectionName).to.equal('my-ad');
      expect(config.get('TENANT_SIGNING_KEY')).to.equal('a-rotated-key');
      expect(config.saveCalls).to.equal(1);
      expect(axiosStub.requests).to.have.length(0);
    });

    it('does not persist when the re-provisioned signing key is unchanged', async () => {
      const config = makeConfig({ TENANT_SIGNING_KEY: 'an-old-key', CONNECTION: 'my-ad' });
      const signingKeys = new SigningKeys({
        configModule: config,
        axiosModule: makeAxios(() => { throw new Error('the JWKS endpoint must not be called in static key mode'); }),
        minRefreshIntervalMs: 0,
        // Reconnect with no rotation: the same key comes back, so there is nothing to persist.
        configureConnectionFn: async () => ({ serverUrl: 'https://connector.example.com', certThumbprint: 'aa:bb', tenantSigningKey: 'an-old-key' })
      });

      const refreshed = await signingKeys.refreshOnReconnect();

      expect(refreshed).to.equal(true);
      expect(config.get('TENANT_SIGNING_KEY')).to.equal('an-old-key');
      expect(config.saveCalls).to.equal(0);
    });

    it('switches to JWKS mode when the provisioning ticket stops returning a signing key', async () => {
      const config = makeConfig({ TENANT_SIGNING_KEY: 'an-old-key', CONNECTION: 'my-ad' });
      const signingKeys = new SigningKeys({
        configModule: config,
        axiosModule: makeAxios(() => Promise.resolve({ data: { keys: [] } })),
        minRefreshIntervalMs: 0,
        // Simulates the tenant leaving the deprecated behaviour: no signingKey comes back.
        configureConnectionFn: async () => ({ serverUrl: 'https://connector.example.com', certThumbprint: 'aa:bb', tenantSigningKey: '' })
      });

      expect(signingKeys.useJwks()).to.equal(false);
      await signingKeys.refreshOnReconnect();

      expect(signingKeys.useJwks()).to.equal(true);
    });

    it('does not throw when the JWKS endpoint is unreachable', async () => {
      const signingKeys = new SigningKeys({
        configModule: makeConfig(),
        axiosModule: makeAxios(() => Promise.reject(new Error('ECONNREFUSED'))),
        configureConnectionFn: makeTicket(''),
        minRefreshIntervalMs: 0
      });

      const refreshed = await signingKeys.refreshOnReconnect();

      expect(refreshed).to.equal(false);
    });

    it('does not throw when the provisioning ticket process fails', async () => {
      const signingKeys = new SigningKeys({
        configModule: makeConfig({ TENANT_SIGNING_KEY: 'an-old-key' }),
        minRefreshIntervalMs: 0,
        configureConnectionFn: async () => {
          throw new Error('Unexpected status while configuring connection: 500');
        }
      });

      const refreshed = await signingKeys.refreshOnReconnect();

      expect(refreshed).to.equal(false);
    });

    it('keeps the last known good key after a failed reconnect refresh', async () => {
      const key = generateKey('kid-1');
      let shouldFail = false;
      const signingKeys = new SigningKeys({
        configModule: makeConfig(),
        axiosModule: makeAxios(() => shouldFail
          ? Promise.reject(new Error('ECONNREFUSED'))
          : jwksResponse([key])),
        configureConnectionFn: makeTicket(''),
        minRefreshIntervalMs: 0
      });

      await signingKeys.refreshOnReconnect();
      shouldFail = true;
      await signingKeys.refreshOnReconnect();

      const payload = await new Promise((resolve, reject) => {
        signingKeys.verify(sign(key), (err, p) => err ? reject(err) : resolve(p));
      });
      expect(payload.username).to.equal('jsmith');
    });

    it('throttles refreshes so a reconnect loop cannot hammer the tenant', async () => {
      const key = generateKey('kid-1');
      const axiosStub = makeAxios(() => jwksResponse([key]));
      const signingKeys = new SigningKeys({
        configModule: makeConfig(),
        axiosModule: axiosStub,
        configureConnectionFn: makeTicket(''),
        minRefreshIntervalMs: 60 * 1000
      });

      await signingKeys.refreshOnReconnect();
      await signingKeys.refreshOnReconnect();
      await signingKeys.refreshOnReconnect();

      expect(axiosStub.requests).to.have.length(1);
    });

    it('re-reads the provisioning ticket and the JWKS document on every reconnect in JWKS mode', async () => {
      const key = generateKey('kid-1');
      const ticket = makeTicket('');
      const axiosStub = makeAxios(() => jwksResponse([key]));
      const signingKeys = new SigningKeys({
        configModule: makeConfig({ CONNECTION: 'my-ad' }),
        axiosModule: axiosStub,
        configureConnectionFn: ticket,
        minRefreshIntervalMs: 0
      });

      const refreshed = await signingKeys.refreshOnReconnect();

      expect(refreshed).to.equal(true);
      expect(ticket.calls).to.have.length(1);
      expect(axiosStub.requests).to.have.length(1);
      expect(signingKeys.useJwks()).to.equal(true);
    });

    it('returns to static mode when the provisioning ticket sends a signing key again', async () => {
      const globalClientKey = generateKey('unused');
      const config = makeConfig({ CONNECTION: 'my-ad' });
      const signingKeys = new SigningKeys({
        configModule: config,
        axiosModule: makeAxios(() => { throw new Error('the JWKS endpoint must not be called in static key mode'); }),
        configureConnectionFn: makeTicket(globalClientKey.publicPem),
        minRefreshIntervalMs: 0
      });
      expect(signingKeys.useJwks()).to.equal(true);

      await signingKeys.refreshOnReconnect();

      expect(signingKeys.useJwks()).to.equal(false);
      expect(config.get('TENANT_SIGNING_KEY')).to.equal(globalClientKey.publicPem);
      expect(config.saveCalls).to.equal(1);
      const payload = await new Promise((resolve, reject) => {
        signingKeys.verify(signWithoutKid(globalClientKey), (err, p) => err ? reject(err) : resolve(p));
      });
      expect(payload.username).to.equal('jsmith');
    });

    it('follows the server across a toggle that is switched off and back on', async () => {
      const globalClientKey = generateKey('unused');
      const tenantKey = generateKey('kid-tsk');
      // The server answers with the global client key, then with nothing, then with the global client key again.
      const ticket = makeTicket(globalClientKey.publicPem, '', globalClientKey.publicPem);
      const signingKeys = new SigningKeys({
        configModule: makeConfig({ CONNECTION: 'my-ad', TENANT_SIGNING_KEY: globalClientKey.publicPem }),
        axiosModule: makeAxios(() => jwksResponse([tenantKey])),
        configureConnectionFn: ticket,
        minRefreshIntervalMs: 0
      });
      const modes = [];

      await signingKeys.refreshOnReconnect();
      modes.push(signingKeys.useJwks());
      await signingKeys.refreshOnReconnect();
      modes.push(signingKeys.useJwks());
      await signingKeys.refreshOnReconnect();
      modes.push(signingKeys.useJwks());

      expect(modes).to.deep.equal([false, true, false]);
      expect(ticket.calls).to.have.length(3);
    });

    it('keeps refreshing the JWKS document when the provisioning ticket cannot be reached in JWKS mode', async () => {
      const key = generateKey('kid-1');
      const axiosStub = makeAxios(() => jwksResponse([key]));
      const signingKeys = new SigningKeys({
        configModule: makeConfig(),
        axiosModule: axiosStub,
        configureConnectionFn: makeTicket(new Error('Unexpected status while configuring connection: 503')),
        minRefreshIntervalMs: 0
      });

      const refreshed = await signingKeys.refreshOnReconnect();

      expect(refreshed).to.equal(true);
      expect(axiosStub.requests).to.have.length(1);
      expect(signingKeys.useJwks()).to.equal(true);
    });

    it('throttles the provisioning ticket separately from the JWKS document', async () => {
      const key = generateKey('kid-1');
      const ticket = makeTicket('');
      const axiosStub = makeAxios(() => jwksResponse([key]));
      const signingKeys = new SigningKeys({
        configModule: makeConfig(),
        axiosModule: axiosStub,
        configureConnectionFn: ticket,
        minRefreshIntervalMs: 60 * 1000
      });

      await signingKeys.refreshOnReconnect();
      await signingKeys.refreshOnReconnect();
      await signingKeys.refreshOnReconnect();

      expect(ticket.calls).to.have.length(1);
      expect(axiosStub.requests).to.have.length(1);
    });
  });

  describe('verify when the message does not match the current mode', () => {
    function build({ ticket, startingKey = '', jwksKeys = [], minRefreshIntervalMs = 0 }) {
      const config = makeConfig({ CONNECTION: 'my-ad', TENANT_SIGNING_KEY: startingKey });
      const axiosStub = makeAxios(() => jwksResponse(jwksKeys));
      const signingKeys = new SigningKeys({
        configModule: config,
        axiosModule: axiosStub,
        configureConnectionFn: ticket,
        minRefreshIntervalMs
      });
      return { signingKeys, config, axiosStub };
    }

    const verifyAsync = (signingKeys, token) => new Promise((resolve) => {
      signingKeys.verify(token, (err, payload) => resolve({ err, payload }));
    });

    it('returns to static mode and verifies a message signed with the global client key (no kid) while in JWKS mode', async () => {
      const globalClientKey = generateKey('unused');
      const tenantKeys = [generateKey('kid-a'), generateKey('kid-b')];
      const ticket = makeTicket(globalClientKey.publicPem);
      const { signingKeys } = build({ ticket, jwksKeys: tenantKeys });

      const { err, payload } = await verifyAsync(signingKeys, signWithoutKid(globalClientKey));

      expect(err).to.equal(null);
      expect(payload.username).to.equal('jsmith');
      expect(ticket.calls).to.have.length(1);
      expect(signingKeys.useJwks()).to.equal(false);
    });

    it('switches to JWKS mode and verifies a message signed with a tenant signing key (kid) while in static mode', async () => {
      const globalClientKey = generateKey('unused');
      const tenantKey = generateKey('kid-tsk');
      const ticket = makeTicket('');
      const { signingKeys } = build({ ticket, startingKey: globalClientKey.publicPem, jwksKeys: [tenantKey] });

      const { err, payload } = await verifyAsync(signingKeys, sign(tenantKey));

      expect(err).to.equal(null);
      expect(payload.username).to.equal('jsmith');
      expect(ticket.calls).to.have.length(1);
      expect(signingKeys.useJwks()).to.equal(true);
    });

    it('returns the original error, after a single ticket call, when the server still sends the same key', async () => {
      const forger = generateKey('unused');
      const ticket = makeTicket('');
      const { signingKeys } = build({ ticket, jwksKeys: [generateKey('kid-a'), generateKey('kid-b')] });

      const { err } = await verifyAsync(signingKeys, signWithoutKid(forger));

      expect(err.message).to.contain('ambiguous');
      expect(ticket.calls).to.have.length(1);
      expect(signingKeys.useJwks()).to.equal(true);
    });

    it('does not contact the provisioning ticket for a token that carries the expected kid but a bad signature', async () => {
      const published = generateKey('kid-a');
      const forged = generateKey('kid-a');
      const ticket = makeTicket('');
      const { signingKeys } = build({ ticket, jwksKeys: [published] });

      const { err } = await verifyAsync(signingKeys, sign(forged));

      expect(err.message).to.equal('invalid signature');
      expect(ticket.calls).to.have.length(0);
    });

    it('returns the original error when the provisioning ticket cannot be reached', async () => {
      const globalClientKey = generateKey('unused');
      const ticket = makeTicket(new Error('Unexpected status while configuring connection: 503'));
      const { signingKeys } = build({ ticket, jwksKeys: [generateKey('kid-a'), generateKey('kid-b')] });

      const { err } = await verifyAsync(signingKeys, signWithoutKid(globalClientKey));

      expect(err.message).to.contain('no kid');
      expect(signingKeys.useJwks()).to.equal(true);
    });

    it('limits how often a failed verification can re-read the provisioning ticket', async () => {
      const forger = generateKey('unused');
      const ticket = makeTicket('');
      const { signingKeys } = build({ ticket, jwksKeys: [generateKey('kid-a'), generateKey('kid-b')], minRefreshIntervalMs: 60 * 1000 });

      await verifyAsync(signingKeys, signWithoutKid(forger));
      await verifyAsync(signingKeys, signWithoutKid(forger));
      await verifyAsync(signingKeys, signWithoutKid(forger));

      expect(ticket.calls).to.have.length(1);
    });

    it('shares one provisioning ticket call between concurrent failed verifications', async () => {
      const globalClientKey = generateKey('unused');
      const ticket = makeTicket(globalClientKey.publicPem);
      const { signingKeys } = build({ ticket, jwksKeys: [generateKey('kid-a'), generateKey('kid-b')], minRefreshIntervalMs: 60 * 1000 });

      const results = await Promise.all([1, 2, 3].map(() => verifyAsync(signingKeys, signWithoutKid(globalClientKey))));

      expect(results.map((r) => r.err)).to.deep.equal([null, null, null]);
      expect(ticket.calls).to.have.length(1);
    });
  });
});
