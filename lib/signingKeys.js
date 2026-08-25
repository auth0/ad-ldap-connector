const crypto = require('crypto');
const axios = require('axios');
const jwt = require('jsonwebtoken');

const config = require('./config');
const { configureConnection } = require('./configureConnection');

/**
 * Relative path of the tenant JWKS document.
 *
 * The tenant segment of the route is optional and ignored by the server
 * (`/:tenant_ignore?/.well-known/jwks.json`), so the document is resolved against the origin of
 * the provisioning ticket.
 */
const JWKS_PATH = '/.well-known/jwks.json';

/**
 * How long a successfully fetched JWKS document is considered fresh.
 */
const DEFAULT_CACHE_MAX_AGE_MS = 10 * 60 * 1000;

/**
 * Lower bound between two fetch attempts. Reconnects are driven by WS_RECONNECT_INTERVAL_MS
 * (10 seconds by default), so without a floor a reconnect loop would hammer the tenant.
 */
const DEFAULT_MIN_REFRESH_INTERVAL_MS = 30 * 1000;

const DEFAULT_REQUEST_TIMEOUT_MS = 10 * 1000;

/**
 * Asymmetric algorithms we are willing to verify hub messages with when the key came from a JWKS
 * document. `none` and the HMAC family are deliberately excluded: JWKS keys are public, so
 * accepting an HMAC algorithm would let a published public key be used as a shared secret.
 */
const JWKS_ALGORITHMS = [
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512'
];

const SUPPORTED_KEY_TYPES = ['RSA', 'EC'];

/**
 * Resolves the signing key used to verify messages coming from the hub.
 *
 * There are two modes, decided by what `auth0-server` returned during the provisioning ticket
 * process (see `lib/configureConnection.js`):
 *
 *  - JWKS mode - the server did not return a `signingKey`, because this connector advertised the
 *    `useJWKS` capability and the tenant is no longer on the deprecated behaviour. The key is
 *    read from the tenant JWKS document and selected by `kid`.
 *  - Static mode - the server returned a `signingKey` (a global client key or a tenant signing
 *    key), so the tenant is still on some variation of the deprecated behaviour. The key is read
 *    from `TENANT_SIGNING_KEY`, exactly as it was before this module existed. This is the path an
 *    older `auth0-server` that ignores `capabilities` will always take.
 */
class SigningKeys {
  #config;
  #axios;
  #jwt;
  #configureConnectionFn;
  #cacheMaxAgeMs;
  #minRefreshIntervalMs;
  #requestTimeoutMs;

  // kid -> PEM encoded public key. Empty until the first successful fetch.
  #keys;
  // Timestamp of the last *successful* fetch, used for freshness.
  #fetchedAt;
  // Timestamp of the last fetch *attempt*, used for the cooldown.
  #lastAttemptAt;
  // Shared promise so concurrent verifications trigger a single fetch.
  #inFlight;

  /**
   * @param configModule config module
   * @param axiosModule axios module
   * @param jwtModule jsonwebtoken module
   * @param configureConnectionFn override for the provisioning ticket function (used by tests);
   *   defaults to the shared `lib/configureConnection` implementation.
   * @param cacheMaxAgeMs how long a fetched JWKS document stays fresh
   * @param minRefreshIntervalMs minimum delay between two fetch attempts
   * @param requestTimeoutMs timeout applied to the JWKS request
   */
  constructor({
    configModule = config,
    axiosModule = axios,
    jwtModule = jwt,
    configureConnectionFn = null,
    cacheMaxAgeMs = DEFAULT_CACHE_MAX_AGE_MS,
    minRefreshIntervalMs = DEFAULT_MIN_REFRESH_INTERVAL_MS,
    requestTimeoutMs = DEFAULT_REQUEST_TIMEOUT_MS
  } = {}) {
    this.#config = configModule;
    this.#axios = axiosModule;
    this.#jwt = jwtModule;
    this.#configureConnectionFn = configureConnectionFn;
    this.#cacheMaxAgeMs = cacheMaxAgeMs;
    this.#minRefreshIntervalMs = minRefreshIntervalMs;
    this.#requestTimeoutMs = requestTimeoutMs;

    this.#keys = {};
    this.#fetchedAt = 0;
    this.#lastAttemptAt = 0;
    this.#inFlight = null;
  }

  /**
   * True when this connector is responsible for fetching the signing key itself.
   *
   * The provisioning ticket process stores `response.data.signingKey || ''`, so an absent or empty
   * `TENANT_SIGNING_KEY` means the server chose not to send one down.
   *
   * @return {boolean}
   */
  useJwks() {
    const staticKey = this.#config.get('TENANT_SIGNING_KEY');
    return !staticKey || staticKey.trim() === '';
  }

  /**
   * Absolute URL of the tenant JWKS document, derived from the provisioning ticket origin.
   *
   * @return {string}
   */
  jwksUri() {
    const provisioningTicket = this.#config.get('PROVISIONING_TICKET');
    if (!provisioningTicket) {
      throw new Error('Cannot resolve the JWKS endpoint because PROVISIONING_TICKET is not set.');
    }

    const ticketUrl = new URL(provisioningTicket);
    if (ticketUrl.protocol !== 'https:') {
      console.warn(
        ('The provisioning ticket is not using https, so the JWKS document will be fetched over ' +
          ticketUrl.protocol.replace(':', '') + '.').yellow
      );
    }

    return new URL(JWKS_PATH, ticketUrl.origin).toString();
  }

  /**
   * Verifies a token received from the hub, resolving the signing key according to the current
   * mode. Signature is intentionally the same shape as `jwt.verify`.
   *
   * @param {string} token
   * @param {function} callback called with (err, payload)
   */
  verify(token, callback) {
    if (!this.useJwks()) {
      // Deprecated behaviour, unchanged: verify against the key the server sent us. No algorithm
      // allow list is applied here so that existing deployments keep verifying exactly as before.
      return this.#jwt.verify(token, this.#config.get('TENANT_SIGNING_KEY'), callback);
    }

    this.#jwt.verify(
      token,
      (header, done) => this.#resolveKey(header, done),
      { algorithms: JWKS_ALGORITHMS },
      callback
    );
  }

  /**
   * Key resolver handed to `jwt.verify`. Looks the `kid` up in the cache, fetching the JWKS
   * document when the cache is cold, stale, or does not contain the requested key.
   */
  #resolveKey(header, done) {
    const kid = header && header.kid;

    const lookup = () => {
      const key = this.#selectKey(kid);
      if (!key) {
        return done(new Error(
          kid
            ? `No signing key matching kid "${kid}" was found in ${this.#safeJwksUri()}.`
            : `The message has no kid and ${Object.keys(this.#keys).length} signing keys are available, so the key is ambiguous.`
        ));
      }
      done(null, key);
    };

    // A cache hit on a fresh document is the common case and needs no network call.
    if (this.#isFresh() && this.#selectKey(kid)) {
      return lookup();
    }

    // We only get here on a stale document or an unknown kid, and an unknown kid most likely means
    // the tenant rotated its keys since the last fetch. Forcing the fetch means rotation is picked
    // up even inside the freshness window; the cooldown still prevents hammering the tenant. If the
    // refresh fails we still run the lookup, so the caller gets a verification error rather than a
    // dangling callback.
    this.refresh({ force: true })
      .then(lookup, (err) => {
        console.error('Could not fetch the tenant signing keys: ' + err.message);
        lookup();
      });
  }

  /**
   * Picks a key by `kid`. When the message carries no `kid`, this only succeeds if the document
   * contains exactly one key, since anything else would be a guess.
   *
   * @return {string|null} PEM encoded public key
   */
  #selectKey(kid) {
    if (kid) {
      return this.#keys[kid] || null;
    }

    const available = Object.keys(this.#keys);
    return available.length === 1 ? this.#keys[available[0]] : null;
  }

  #isFresh() {
    return this.#fetchedAt > 0 && (Date.now() - this.#fetchedAt) < this.#cacheMaxAgeMs;
  }

  #withinCooldown() {
    return this.#lastAttemptAt > 0 && (Date.now() - this.#lastAttemptAt) < this.#minRefreshIntervalMs;
  }

  #safeJwksUri() {
    try {
      return this.jwksUri();
    } catch (err) {
      return 'the JWKS endpoint';
    }
  }

  /**
   * Fetches the JWKS document and replaces the cache. Concurrent callers share a single request.
   *
   * A failed fetch never clears a previously cached document. Continuing to verify with keys that
   * may be outdated is safe: these are public keys, so a stale key can only make verification
   * fail, never make an invalid signature pass.
   *
   * @param {boolean} force ignore the freshness window (the cooldown still applies)
   * @return {Promise<void>}
   */
  refresh({ force = false } = {}) {
    if (!force && this.#isFresh()) {
      return Promise.resolve();
    }

    if (this.#inFlight) {
      return this.#inFlight;
    }

    if (this.#withinCooldown()) {
      return Promise.resolve();
    }

    this.#lastAttemptAt = Date.now();
    this.#inFlight = this.#fetchJwks()
      .finally(() => {
        this.#inFlight = null;
      });

    return this.#inFlight;
  }

  async #fetchJwks() {
    const uri = this.jwksUri();
    console.log('Fetching tenant signing keys from ' + uri);

    // The request deliberately relies on the process wide https configuration so that the
    // HTTP_PROXY tunnel installed by lib/setupProxy and the CA bundle injected by lib/add_certs
    // both apply, and so that Node's default minimum TLS version is honoured.
    const response = await this.#axios.get(uri, { timeout: this.#requestTimeoutMs });

    const keys = response && response.data && response.data.keys;
    if (!Array.isArray(keys)) {
      throw new Error(`Unexpected JWKS document at ${uri}: no "keys" array.`);
    }

    const parsed = {};
    keys.forEach((jwk) => {
      const pem = this.#jwkToPem(jwk);
      if (pem) {
        parsed[jwk.kid] = pem;
      }
    });

    if (Object.keys(parsed).length === 0) {
      throw new Error(`No usable signing keys found in the JWKS document at ${uri}.`);
    }

    this.#keys = parsed;
    this.#fetchedAt = Date.now();
    console.log('Loaded ' + Object.keys(parsed).length + ' tenant signing key(s).');
  }

  /**
   * Converts a JWK into a PEM encoded public key, skipping anything we cannot or should not use.
   *
   * @return {string|null}
   */
  #jwkToPem(jwk) {
    if (!jwk || !jwk.kid) {
      console.warn('Skipping a JWKS entry without a kid.'.yellow);
      return null;
    }

    // `use` is optional, but when present it must mark the key as a signature key.
    if (jwk.use && jwk.use !== 'sig') {
      return null;
    }

    if (!SUPPORTED_KEY_TYPES.includes(jwk.kty)) {
      console.warn(`Skipping JWKS entry "${jwk.kid}" with unsupported key type "${jwk.kty}".`.yellow);
      return null;
    }

    if (jwk.alg && !JWKS_ALGORITHMS.includes(jwk.alg)) {
      console.warn(`Skipping JWKS entry "${jwk.kid}" with unsupported algorithm "${jwk.alg}".`.yellow);
      return null;
    }

    try {
      return crypto
        .createPublicKey({ key: jwk, format: 'jwk' })
        .export({ type: 'spki', format: 'pem' })
        .toString();
    } catch (err) {
      console.warn(`Skipping unreadable JWKS entry "${jwk.kid}": ${err.message}`.yellow);
      return null;
    }
  }

  /**
   * Re-fetches the tenant signing key because the connector is (re)connecting to the hub.
   *
   * The hub may have started signing with a different key while the socket was down, so the key
   * captured at setup time can no longer be assumed current.
   *
   * Failures are logged and swallowed: the connector must still attempt to connect with whatever
   * key it already has rather than wedge itself into a permanently broken state.
   *
   * @return {Promise<boolean>} true when a key was actually refreshed
   */
  async refreshOnReconnect() {
    if (this.#withinCooldown()) {
      return false;
    }

    try {
      if (this.useJwks()) {
        await this.refresh({ force: true });
        return true;
      }

      await this.#refreshViaProvisioningTicket();
      return true;
    } catch (err) {
      console.error('Could not refresh the tenant signing key: ' + err.message);
      return false;
    }
  }

  /**
   * Runs the provisioning ticket process again to pick up the current signing key.
   *
   * This re-sends the `useJWKS` capability, so a tenant that stopped using the deprecated
   * behaviour since setup will now respond without a `signingKey` and this connector will switch
   * itself over to JWKS mode.
   */
  async #refreshViaProvisioningTicket() {
    this.#lastAttemptAt = Date.now();

    const provisioningTicket = this.#config.get('PROVISIONING_TICKET');
    if (!provisioningTicket) {
      throw new Error('PROVISIONING_TICKET is not set.');
    }

    console.log('Refreshing the tenant signing key through the provisioning ticket.');

    const configureConnection = this.#configureConnection();
    const { serverUrl, certThumbprint, tenantSigningKey } = await configureConnection({
      provisioningTicket,
      connectionName: this.#config.get('CONNECTION')
    });

    // configureConnection no longer writes config itself (it returns the values), so persist them
    // here, the same way server.js does after the initial setup.
    this.#config.set('SERVER_URL', serverUrl);
    this.#config.set('LAST_SENT_THUMBPRINT', certThumbprint);
    this.#config.set('TENANT_SIGNING_KEY', tenantSigningKey);

    // Persist the refreshed key so a restart does not need another round trip.
    await this.#config.save();
  }

  #configureConnection() {
    return this.#configureConnectionFn || configureConnection;
  }
}

const signingKeys = new SigningKeys();

module.exports = signingKeys;
module.exports.SigningKeys = SigningKeys;
module.exports.JWKS_ALGORITHMS = JWKS_ALGORITHMS;
