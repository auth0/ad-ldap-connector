require('colors');

const { expect } = require('chai');
const crypto = require('crypto');
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
        minRefreshIntervalMs: 60 * 1000
      });

      await signingKeys.refreshOnReconnect();
      await signingKeys.refreshOnReconnect();
      await signingKeys.refreshOnReconnect();

      expect(axiosStub.requests).to.have.length(1);
    });
  });
});
