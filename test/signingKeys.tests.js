require('colors');

const { expect } = require('chai');
const crypto = require('crypto');
const http = require('http');
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

const servers = [];

/**
 * Serves a JWKS document over http on an ephemeral port, so the tests exercise the real request
 * path. `keys` is what the document lists, `failing` makes the endpoint answer 503, `body` replaces
 * the document, and `delayMs` slows the answer down. `requests` records the path of every request.
 */
async function serveJwks(keys = []) {
  const server = {
    keys,
    failing: false,
    body: null,
    delayMs: 0,
    requests: []
  };

  const httpServer = http.createServer((req, res) => {
    server.requests.push(req.url);
    setTimeout(() => {
      if (server.failing) {
        res.statusCode = 503;
        return res.end('unavailable');
      }
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify(server.body || { keys: server.keys.map((k) => k.jwk) }));
    }, server.delayMs);
  });

  await new Promise((resolve) => httpServer.listen(0, '127.0.0.1', resolve));
  servers.push(httpServer);

  server.origin = 'http://127.0.0.1:' + httpServer.address().port;
  server.ticket = server.origin + '/p/ad/abc123';
  server.jwksUri = server.origin + '/.well-known/jwks.json';
  server.close = () => new Promise((resolve) => httpServer.close(resolve));
  return server;
}

/**
 * A server nothing listens on: the port is taken and released again.
 */
async function unreachableServer() {
  const server = await serveJwks();
  await server.close();
  return server;
}

afterEach(async () => {
  while (servers.length) {
    const httpServer = servers.pop();
    httpServer.closeAllConnections();
    if (httpServer.listening) {
      await new Promise((resolve) => httpServer.close(resolve));
    }
  }
});

/**
 * Builds a SigningKeys that reads the JWKS document from `server`.
 */
function forServer(server, { config = {}, ...options } = {}) {
  return new SigningKeys({
    configModule: makeConfig(Object.assign({ PROVISIONING_TICKET: server.ticket }, config)),
    ...options
  });
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
    const verifyAsync = (signingKeys, token) => new Promise((resolve, reject) => {
      signingKeys.verify(token, (err, payload) => err ? reject(err) : resolve(payload));
    });
    const verifyError = (signingKeys, token) => new Promise((resolve) => {
      signingKeys.verify(token, (err) => resolve(err));
    });

    it('verifies a token signed with a key from the JWKS document', async () => {
      const key = generateKey('kid-1');
      const server = await serveJwks([key]);
      const signingKeys = forServer(server);

      const payload = await verifyAsync(signingKeys, sign(key));

      expect(payload.username).to.equal('jsmith');
      expect(server.requests).to.deep.equal(['/.well-known/jwks.json']);
    });

    it('selects the key matching the kid when several are published', async () => {
      const keyOne = generateKey('kid-1');
      const keyTwo = generateKey('kid-2');
      const signingKeys = forServer(await serveJwks([keyOne, keyTwo]));

      // Signed with the second key, so selection by kid is what makes this pass.
      const payload = await verifyAsync(signingKeys, sign(keyTwo));

      expect(payload.username).to.equal('jsmith');
    });

    it('rejects a token whose kid is not published', async () => {
      const published = generateKey('kid-1');
      const rogue = generateKey('kid-unknown');
      const signingKeys = forServer(await serveJwks([published]));

      const err = await verifyError(signingKeys, sign(rogue));

      expect(err).to.be.ok;
      expect(err.message).to.match(/kid-unknown/);
    });

    it('rejects a token signed by a different key with a published kid', async () => {
      const published = generateKey('kid-1');
      // Same kid, different key material - a forged token.
      const forged = generateKey('kid-1');
      const signingKeys = forServer(await serveJwks([published]));

      const err = await verifyError(signingKeys, sign(forged));

      expect(err).to.be.ok;
      expect(err.message).to.match(/invalid signature/i);
    });

    it('rejects an HS256 token forged with the published public key as the secret', async () => {
      const key = generateKey('kid-1');
      const signingKeys = forServer(await serveJwks([key]));

      // Classic algorithm confusion attack: sign with HMAC using the public key as the secret.
      const forged = jwt.sign({ username: 'attacker' }, key.publicPem, {
        algorithm: 'HS256',
        keyid: 'kid-1'
      });

      const err = await verifyError(signingKeys, forged);

      expect(err).to.be.ok;
      expect(err.message).to.match(/invalid algorithm/i);
    });

    it('rejects an unsigned token', async () => {
      const key = generateKey('kid-1');
      const signingKeys = forServer(await serveJwks([key]));
      const header = Buffer.from(JSON.stringify({ alg: 'none', kid: 'kid-1' })).toString('base64url');
      const body = Buffer.from(JSON.stringify({ username: 'attacker' })).toString('base64url');

      const err = await verifyError(signingKeys, `${header}.${body}.`);

      expect(err).to.be.ok;
    });

    it('falls back to the single published key when the token carries no kid', async () => {
      const key = generateKey('kid-1');
      const signingKeys = forServer(await serveJwks([key]));

      const payload = await verifyAsync(signingKeys, signWithoutKid(key));

      expect(payload.username).to.equal('jsmith');
    });

    it('refuses to guess when the token has no kid and several keys are published', async () => {
      const keyOne = generateKey('kid-1');
      const keyTwo = generateKey('kid-2');
      const signingKeys = forServer(await serveJwks([keyOne, keyTwo]));

      const err = await verifyError(signingKeys, signWithoutKid(keyOne));

      expect(err).to.be.ok;
      expect(err.message).to.match(/more than 1 key/);
    });

    // Runs `fn` with console.log captured, and returns what it logged.
    async function loggedDuring(fn) {
      const lines = [];
      const original = console.log;
      console.log = (...args) => lines.push(args.join(' '));
      try {
        await fn();
      } finally {
        console.log = original;
      }
      return lines;
    }

    it('logs the fetch that an unknown kid causes, like the fetch on a refresh', async () => {
      const oldKey = generateKey('kid-old');
      const newKey = generateKey('kid-new');
      const server = await serveJwks([oldKey]);
      const signingKeys = forServer(server, { cacheMaxAgeMs: 60 * 60 * 1000, minRefreshIntervalMs: 0 });
      await verifyAsync(signingKeys, sign(oldKey));
      server.keys = [newKey];

      const lines = await loggedDuring(() => verifyAsync(signingKeys, sign(newKey)));

      expect(lines.filter((line) => /^(Fetching|Loaded) /.test(line))).to.deep.equal([
        'Fetching tenant signing keys from ' + server.jwksUri,
        'Loaded 1 tenant signing key(s).'
      ]);
    });

    it('logs the key id, and only that, when the key that verifies a message changes', async () => {
      const oldKey = generateKey('kid-old');
      const newKey = generateKey('kid-new');
      const server = await serveJwks([oldKey]);
      const signingKeys = forServer(server, { cacheMaxAgeMs: 60 * 60 * 1000, minRefreshIntervalMs: 0 });

      const lines = await loggedDuring(async () => {
        await verifyAsync(signingKeys, sign(oldKey));
        await verifyAsync(signingKeys, sign(oldKey));
        server.keys = [newKey];
        await verifyAsync(signingKeys, sign(newKey));
        await verifyAsync(signingKeys, sign(newKey));
      });

      expect(lines.filter((line) => /^Verified /.test(line))).to.deep.equal([
        'Verified a hub message with a new tenant signing key (kid kid-new); the previous one was kid-old.'
      ]);
      expect(lines.join('\n')).to.not.match(/BEGIN|PRIVATE|"n":/);
    });

    it('does not log a key id for a message that fails verification', async () => {
      const published = generateKey('kid-1');
      const rogue = generateKey('kid-rogue');
      const server = await serveJwks([published]);
      const signingKeys = forServer(server);
      await verifyAsync(signingKeys, sign(published));

      const lines = await loggedDuring(() => verifyError(signingKeys, sign(rogue)));

      expect(lines.filter((line) => /^Verified /.test(line))).to.deep.equal([]);
    });

    it('re-fetches on an unknown kid even while the cached keys are still fresh', async () => {
      const oldKey = generateKey('kid-old');
      const newKey = generateKey('kid-new');
      const server = await serveJwks([oldKey]);
      // Long freshness window, no rate limit: rotation must still be picked up.
      const signingKeys = forServer(server, { cacheMaxAgeMs: 60 * 60 * 1000, minRefreshIntervalMs: 0 });

      await verifyAsync(signingKeys, sign(oldKey));

      // The tenant rotates to a new kid without the cache having expired.
      server.keys = [newKey];
      const payload = await verifyAsync(signingKeys, sign(newKey));

      expect(payload.username).to.equal('jsmith');
      expect(server.requests).to.have.length(2);
    });

    it('caches the keys across verifications', async () => {
      const key = generateKey('kid-1');
      const server = await serveJwks([key]);
      const signingKeys = forServer(server);

      await verifyAsync(signingKeys, sign(key));
      await verifyAsync(signingKeys, sign(key));
      await verifyAsync(signingKeys, sign(key));

      expect(server.requests).to.have.length(1);
    });

    it('fetches the JWKS document again once the cached key is no longer fresh', async () => {
      const key = generateKey('kid-1');
      const server = await serveJwks([key]);
      const signingKeys = forServer(server, { cacheMaxAgeMs: 20, minRefreshIntervalMs: 0 });

      await verifyAsync(signingKeys, sign(key));
      await new Promise((resolve) => setTimeout(resolve, 60));
      await verifyAsync(signingKeys, sign(key));

      expect(server.requests).to.have.length(2);
    });

    it('limits how often unknown kids can trigger a fetch', async () => {
      const key = generateKey('kid-1');
      const server = await serveJwks([key]);
      // One request per minute.
      const signingKeys = forServer(server, { minRefreshIntervalMs: 60 * 1000 });

      await verifyAsync(signingKeys, sign(key));
      const err = await verifyError(signingKeys, sign(generateKey('kid-unknown')));

      expect(err).to.be.ok;
      expect(err.message).to.match(/Too many requests/);
      expect(server.requests).to.have.length(1);
      // The key that is cached keeps working.
      const payload = await verifyAsync(signingKeys, sign(key));
      expect(payload.username).to.equal('jsmith');
    });

    it('shares a single request between concurrent verifications of the same kid', async () => {
      const key = generateKey('kid-1');
      const server = await serveJwks([key]);
      server.delayMs = 50;
      const signingKeys = forServer(server);

      await Promise.all([1, 2, 3].map(() => verifyAsync(signingKeys, sign(key))));

      expect(server.requests).to.have.length(1);
    });

    it('shares a single request between concurrent refreshes', async () => {
      const key = generateKey('kid-1');
      const server = await serveJwks([key]);
      server.delayMs = 50;
      const signingKeys = forServer(server);

      await Promise.all([signingKeys.refresh(), signingKeys.refresh()]);

      expect(server.requests).to.have.length(1);
    });
  });

  describe('verify in static key mode', () => {
    it('verifies against the key the server sent, without touching the JWKS endpoint', async () => {
      const key = generateKey('kid-1');
      const server = await serveJwks([key]);
      const signingKeys = forServer(server, { config: { TENANT_SIGNING_KEY: key.publicPem } });

      const payload = await new Promise((resolve, reject) => {
        signingKeys.verify(sign(key), (err, p) => err ? reject(err) : resolve(p));
      });

      expect(payload.username).to.equal('jsmith');
      expect(server.requests).to.have.length(0);
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
    const verifyAsync = (signingKeys, token) => new Promise((resolve, reject) => {
      signingKeys.verify(token, (err, payload) => err ? reject(err) : resolve(payload));
    });
    const verifyError = (signingKeys, token) => new Promise((resolve) => {
      signingKeys.verify(token, (err) => resolve(err));
    });

    it('surfaces a verification error when the JWKS endpoint answers with an error', async () => {
      const key = generateKey('kid-1');
      const server = await serveJwks([key]);
      server.failing = true;
      const signingKeys = forServer(server);

      const err = await verifyError(signingKeys, sign(key));

      expect(err).to.be.ok;
      expect(err.name).to.equal('JsonWebTokenError');
    });

    it('surfaces a verification error when the JWKS endpoint cannot be reached', async () => {
      const key = generateKey('kid-1');
      const signingKeys = forServer(await unreachableServer());

      const err = await verifyError(signingKeys, sign(key));

      expect(err).to.be.ok;
      expect(err.message).to.match(/ECONNREFUSED/);
    });

    it('gives up on a JWKS endpoint that does not answer in time', async () => {
      const key = generateKey('kid-1');
      const server = await serveJwks([key]);
      server.delayMs = 500;
      const signingKeys = forServer(server, { requestTimeoutMs: 50 });

      const err = await verifyError(signingKeys, sign(key));

      expect(err).to.be.ok;
    });

    it('rejects a JWKS document without a keys array', async () => {
      const server = await serveJwks();
      server.body = {};
      const signingKeys = forServer(server);

      let error;
      await signingKeys.refresh().catch((err) => { error = err; });

      expect(error).to.be.ok;
      expect(error.message).to.match(/did not contain any keys/);
    });

    it('rejects a JWKS document with no usable keys', async () => {
      const unusable = generateKey('kid-1');
      unusable.jwk.kty = 'oct';
      const signingKeys = forServer(await serveJwks([unusable]));

      let error;
      await signingKeys.refresh().catch((err) => { error = err; });

      expect(error).to.be.ok;
      expect(error.message).to.match(/did not contain any signing keys/);
    });

    it('keeps serving previously cached keys when a later fetch fails', async () => {
      const key = generateKey('kid-1');
      const server = await serveJwks([key]);
      const signingKeys = forServer(server, { cacheMaxAgeMs: 20, minRefreshIntervalMs: 0 });

      await verifyAsync(signingKeys, sign(key));
      server.failing = true;
      await new Promise((resolve) => setTimeout(resolve, 60));

      // The cached key is no longer fresh and the fetch fails, so the last good key is used.
      const payload = await verifyAsync(signingKeys, sign(key));
      expect(payload.username).to.equal('jsmith');
      expect(server.requests).to.have.length(2);
    });

    it('does not accept a key that was never fetched while the endpoint is down', async () => {
      const cached = generateKey('kid-1');
      const other = generateKey('kid-2');
      const server = await serveJwks([cached, other]);
      const signingKeys = forServer(server, { minRefreshIntervalMs: 0 });

      await verifyAsync(signingKeys, sign(cached));
      server.failing = true;

      const err = await verifyError(signingKeys, sign(other));
      expect(err).to.be.ok;
    });

    it('skips entries that are not signature keys', async () => {
      const sigKey = generateKey('kid-sig');
      const encKey = generateKey('kid-enc');
      encKey.jwk.use = 'enc';
      const signingKeys = forServer(await serveJwks([sigKey, encKey]));

      await signingKeys.refresh();

      // The encryption key was dropped, so a token signed with it cannot be verified.
      const err = await verifyError(signingKeys, sign(encKey));
      expect(err).to.be.ok;
      expect(err.message).to.match(/kid-enc/);
    });

    it('uses the JWKS address of the current provisioning ticket', async () => {
      const key = generateKey('kid-1');
      const first = await serveJwks([]);
      const second = await serveJwks([key]);
      const config = makeConfig({ PROVISIONING_TICKET: first.ticket });
      const signingKeys = new SigningKeys({ configModule: config, minRefreshIntervalMs: 0 });

      await verifyError(signingKeys, sign(key));
      config.set('PROVISIONING_TICKET', second.ticket);
      const payload = await verifyAsync(signingKeys, sign(key));

      expect(payload.username).to.equal('jsmith');
      expect(first.requests).to.have.length(1);
      expect(second.requests).to.have.length(1);
    });
  });

  describe('refreshOnReconnect', () => {
    const verifyAsync = (signingKeys, token) => new Promise((resolve, reject) => {
      signingKeys.verify(token, (err, payload) => err ? reject(err) : resolve(payload));
    });
    const verifyError = (signingKeys, token) => new Promise((resolve) => {
      signingKeys.verify(token, (err) => resolve(err));
    });

    it('re-reads the JWKS document when the server sent no signing key', async () => {
      const server = await serveJwks([generateKey('kid-1')]);
      const signingKeys = forServer(server, {
        configureConnectionFn: makeTicket(''),
        minRefreshIntervalMs: 0
      });

      const refreshed = await signingKeys.refreshOnReconnect();

      expect(refreshed).to.equal(true);
      expect(server.requests).to.deep.equal(['/.well-known/jwks.json']);
    });

    it('picks up a rotated key on reconnect', async () => {
      const oldKey = generateKey('kid-old');
      const newKey = generateKey('kid-new');
      const server = await serveJwks([oldKey]);
      const signingKeys = forServer(server, {
        configureConnectionFn: makeTicket(''),
        minRefreshIntervalMs: 0
      });

      await signingKeys.refreshOnReconnect();

      // The tenant rotates its signing key while the socket is down.
      server.keys = [newKey];
      await signingKeys.refreshOnReconnect();

      const payload = await verifyAsync(signingKeys, sign(newKey));
      expect(payload.username).to.equal('jsmith');
    });

    it('stops using a key that the tenant removed while the socket was down', async () => {
      const oldKey = generateKey('kid-old');
      const newKey = generateKey('kid-new');
      const server = await serveJwks([oldKey]);
      const signingKeys = forServer(server, {
        configureConnectionFn: makeTicket(''),
        minRefreshIntervalMs: 0
      });
      await verifyAsync(signingKeys, sign(oldKey));

      server.keys = [newKey];
      await signingKeys.refreshOnReconnect();

      const err = await verifyError(signingKeys, sign(oldKey));
      expect(err).to.be.ok;
    });

    it('re-runs the provisioning ticket process when the server sent a signing key', async () => {
      const server = await serveJwks();
      const config = { TENANT_SIGNING_KEY: 'an-old-key', CONNECTION: 'my-ad', PROVISIONING_TICKET: PROVISIONING_TICKET };
      const calls = [];
      const signingKeys = forServer(server, {
        config,
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
      expect(server.requests).to.have.length(0);
    });

    it('persists the re-provisioned signing key when it changed', async () => {
      const config = makeConfig({ TENANT_SIGNING_KEY: 'an-old-key', CONNECTION: 'my-ad' });
      const signingKeys = new SigningKeys({
        configModule: config,
        minRefreshIntervalMs: 0,
        configureConnectionFn: makeTicket('a-rotated-key')
      });

      await signingKeys.refreshOnReconnect();

      expect(config.get('TENANT_SIGNING_KEY')).to.equal('a-rotated-key');
      expect(config.saveCalls).to.equal(1);
    });

    it('does not persist when the re-provisioned signing key is unchanged', async () => {
      const config = makeConfig({ TENANT_SIGNING_KEY: 'an-old-key', CONNECTION: 'my-ad' });
      const signingKeys = new SigningKeys({
        configModule: config,
        minRefreshIntervalMs: 0,
        // Reconnect with no rotation: the same key comes back, so there is nothing to persist.
        configureConnectionFn: makeTicket('an-old-key')
      });

      const refreshed = await signingKeys.refreshOnReconnect();

      expect(refreshed).to.equal(true);
      expect(config.get('TENANT_SIGNING_KEY')).to.equal('an-old-key');
      expect(config.saveCalls).to.equal(0);
    });

    it('switches to JWKS mode when the provisioning ticket stops returning a signing key', async () => {
      const server = await serveJwks([generateKey('kid-1')]);
      const signingKeys = forServer(server, {
        config: { TENANT_SIGNING_KEY: 'an-old-key', CONNECTION: 'my-ad' },
        minRefreshIntervalMs: 0,
        // Simulates the tenant leaving the deprecated behaviour: no signingKey comes back.
        configureConnectionFn: makeTicket('')
      });

      expect(signingKeys.useJwks()).to.equal(false);
      await signingKeys.refreshOnReconnect();

      expect(signingKeys.useJwks()).to.equal(true);
      expect(server.requests).to.have.length(1);
    });

    it('does not throw when the JWKS endpoint is unreachable', async () => {
      const signingKeys = forServer(await unreachableServer(), {
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
      const server = await serveJwks([key]);
      const signingKeys = forServer(server, {
        configureConnectionFn: makeTicket(''),
        minRefreshIntervalMs: 0
      });

      await verifyAsync(signingKeys, sign(key));
      server.failing = true;
      const refreshed = await signingKeys.refreshOnReconnect();

      expect(refreshed).to.equal(false);
      const payload = await verifyAsync(signingKeys, sign(key));
      expect(payload.username).to.equal('jsmith');
    });

    it('throttles refreshes so a reconnect loop cannot hammer the tenant', async () => {
      const server = await serveJwks([generateKey('kid-1')]);
      const signingKeys = forServer(server, {
        configureConnectionFn: makeTicket(''),
        minRefreshIntervalMs: 60 * 1000
      });

      await signingKeys.refreshOnReconnect();
      await signingKeys.refreshOnReconnect();
      await signingKeys.refreshOnReconnect();

      expect(server.requests).to.have.length(1);
    });

    it('re-reads the provisioning ticket and the JWKS document on every reconnect in JWKS mode', async () => {
      const ticket = makeTicket('');
      const server = await serveJwks([generateKey('kid-1')]);
      const signingKeys = forServer(server, {
        config: { CONNECTION: 'my-ad' },
        configureConnectionFn: ticket,
        minRefreshIntervalMs: 0
      });

      const refreshed = await signingKeys.refreshOnReconnect();

      expect(refreshed).to.equal(true);
      expect(ticket.calls).to.have.length(1);
      expect(server.requests).to.have.length(1);
      expect(signingKeys.useJwks()).to.equal(true);
    });

    it('returns to static mode when the provisioning ticket sends a signing key again', async () => {
      const globalClientKey = generateKey('unused');
      const server = await serveJwks();
      const config = makeConfig({ CONNECTION: 'my-ad', PROVISIONING_TICKET: server.ticket });
      const signingKeys = new SigningKeys({
        configModule: config,
        configureConnectionFn: makeTicket(globalClientKey.publicPem),
        minRefreshIntervalMs: 0
      });
      expect(signingKeys.useJwks()).to.equal(true);

      await signingKeys.refreshOnReconnect();

      expect(signingKeys.useJwks()).to.equal(false);
      expect(config.get('TENANT_SIGNING_KEY')).to.equal(globalClientKey.publicPem);
      expect(config.saveCalls).to.equal(1);
      const payload = await verifyAsync(signingKeys, signWithoutKid(globalClientKey));
      expect(payload.username).to.equal('jsmith');
      expect(server.requests).to.have.length(0);
    });

    it('follows the server across a toggle that is switched off and back on', async () => {
      const globalClientKey = generateKey('unused');
      const tenantKey = generateKey('kid-tsk');
      // The server answers with the global client key, then with nothing, then with the global client key again.
      const ticket = makeTicket(globalClientKey.publicPem, '', globalClientKey.publicPem);
      const signingKeys = forServer(await serveJwks([tenantKey]), {
        config: { CONNECTION: 'my-ad', TENANT_SIGNING_KEY: globalClientKey.publicPem },
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
      const server = await serveJwks([generateKey('kid-1')]);
      const signingKeys = forServer(server, {
        configureConnectionFn: makeTicket(new Error('Unexpected status while configuring connection: 503')),
        minRefreshIntervalMs: 0
      });

      const refreshed = await signingKeys.refreshOnReconnect();

      expect(refreshed).to.equal(true);
      expect(server.requests).to.have.length(1);
      expect(signingKeys.useJwks()).to.equal(true);
    });

    it('throttles the provisioning ticket separately from the JWKS document', async () => {
      const ticket = makeTicket('');
      const server = await serveJwks([generateKey('kid-1')]);
      const signingKeys = forServer(server, {
        configureConnectionFn: ticket,
        minRefreshIntervalMs: 60 * 1000
      });

      await signingKeys.refreshOnReconnect();
      await signingKeys.refreshOnReconnect();
      await signingKeys.refreshOnReconnect();

      expect(ticket.calls).to.have.length(1);
      expect(server.requests).to.have.length(1);
    });
  });

  describe('verify when the message does not match the current mode', () => {
    async function build({ ticket, startingKey = '', jwksKeys = [], minRefreshIntervalMs = 0 }) {
      const server = await serveJwks(jwksKeys);
      const signingKeys = forServer(server, {
        config: { CONNECTION: 'my-ad', TENANT_SIGNING_KEY: startingKey },
        configureConnectionFn: ticket,
        minRefreshIntervalMs
      });
      return { signingKeys, server };
    }

    const verifyAsync = (signingKeys, token) => new Promise((resolve) => {
      signingKeys.verify(token, (err, payload) => resolve({ err, payload }));
    });

    it('returns to static mode and verifies a message signed with the global client key (no kid) while in JWKS mode', async () => {
      const globalClientKey = generateKey('unused');
      const tenantKeys = [generateKey('kid-a'), generateKey('kid-b')];
      const ticket = makeTicket(globalClientKey.publicPem);
      const { signingKeys } = await build({ ticket, jwksKeys: tenantKeys });

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
      const { signingKeys } = await build({ ticket, startingKey: globalClientKey.publicPem, jwksKeys: [tenantKey] });

      const { err, payload } = await verifyAsync(signingKeys, sign(tenantKey));

      expect(err).to.equal(null);
      expect(payload.username).to.equal('jsmith');
      expect(ticket.calls).to.have.length(1);
      expect(signingKeys.useJwks()).to.equal(true);
    });

    it('returns the original error, after a single ticket call, when the server still sends the same key', async () => {
      const forger = generateKey('unused');
      const ticket = makeTicket('');
      const { signingKeys } = await build({ ticket, jwksKeys: [generateKey('kid-a'), generateKey('kid-b')] });

      const { err } = await verifyAsync(signingKeys, signWithoutKid(forger));

      expect(err.message).to.contain('more than 1 key');
      expect(ticket.calls).to.have.length(1);
      expect(signingKeys.useJwks()).to.equal(true);
    });

    it('does not contact the provisioning ticket for a token that carries the expected kid but a bad signature', async () => {
      const published = generateKey('kid-a');
      const forged = generateKey('kid-a');
      const ticket = makeTicket('');
      const { signingKeys } = await build({ ticket, jwksKeys: [published] });

      const { err } = await verifyAsync(signingKeys, sign(forged));

      expect(err.message).to.equal('invalid signature');
      expect(ticket.calls).to.have.length(0);
    });

    it('returns the original error when the provisioning ticket cannot be reached', async () => {
      const globalClientKey = generateKey('unused');
      const ticket = makeTicket(new Error('Unexpected status while configuring connection: 503'));
      const { signingKeys } = await build({ ticket, jwksKeys: [generateKey('kid-a'), generateKey('kid-b')] });

      const { err } = await verifyAsync(signingKeys, signWithoutKid(globalClientKey));

      expect(err.message).to.contain('more than 1 key');
      expect(signingKeys.useJwks()).to.equal(true);
    });

    it('limits how often a failed verification can re-read the provisioning ticket', async () => {
      const forger = generateKey('unused');
      const ticket = makeTicket('');
      const { signingKeys } = await build({ ticket, jwksKeys: [generateKey('kid-a'), generateKey('kid-b')], minRefreshIntervalMs: 60 * 1000 });

      await verifyAsync(signingKeys, signWithoutKid(forger));
      await verifyAsync(signingKeys, signWithoutKid(forger));
      await verifyAsync(signingKeys, signWithoutKid(forger));

      expect(ticket.calls).to.have.length(1);
    });

    it('shares one provisioning ticket call between concurrent failed verifications', async () => {
      const globalClientKey = generateKey('unused');
      const ticket = makeTicket(globalClientKey.publicPem);
      const { signingKeys } = await build({ ticket, jwksKeys: [generateKey('kid-a'), generateKey('kid-b')], minRefreshIntervalMs: 60 * 1000 });

      const results = await Promise.all([1, 2, 3].map(() => verifyAsync(signingKeys, signWithoutKid(globalClientKey))));

      expect(results.map((r) => r.err)).to.deep.equal([null, null, null]);
      expect(ticket.calls).to.have.length(1);
    });
  });
});
