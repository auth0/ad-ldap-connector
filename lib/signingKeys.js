const { callbackify, promisify } = require('util');
const jwksRsa = require('jwks-rsa');
const jwt = require('jsonwebtoken');

const config = require('./config');
const { configureConnection } = require('./configureConnection');

/**
 * Relative path of the tenant JWKS document.
 *
 * The document is resolved against the origin of the provisioning ticket.
 */
const JWKS_PATH = '/.well-known/jwks.json';

/**
 * How long a fetched signing key is considered fresh.
 */
const DEFAULT_CACHE_MAX_AGE_MS = 10 * 60 * 1000;

/**
 * Lower bound between two fetch attempts. Reconnects are driven by WS_RECONNECT_INTERVAL_MS
 * (10 seconds by default), so without a floor a reconnect loop would hammer the tenant.
 */
const DEFAULT_MIN_REFRESH_INTERVAL_MS = 30 * 1000;

const DEFAULT_REQUEST_TIMEOUT_MS = 10 * 1000;

/**
 * How long past its freshness window a signing key may still be used when the JWKS endpoint cannot
 * be reached. These are public keys, so a stale key can only make verification fail, never make an
 * invalid signature pass.
 */
const STALE_KEY_FALLBACK_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * Upper bound of distinct keys kept in the cache. A tenant publishes only a handful.
 */
const MAX_CACHED_KEYS = 10;

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

/**
 * Resolves the signing key used to verify messages coming from the hub.
 *
 * There are two modes, decided by what the Auth0 server returned during the provisioning ticket
 * process (see `lib/configureConnection.js`):
 *
 *  - JWKS mode - the server did not return a `signingKey`, because this connector advertised the
 *    `useJWKS` capability and the tenant is no longer on the deprecated behaviour. The key is
 *    read from the tenant JWKS document and selected by `kid`.
 *  - Static mode - the server returned a `signingKey` (a global client key or a tenant signing
 *    key), so the tenant is still on some variation of the deprecated behaviour. The key is read
 *    from `TENANT_SIGNING_KEY`, exactly as it was before this module existed. This is the path an
 *    older Auth0 server that ignores `capabilities` will always take.
 *
 * The mode is not permanent. It always follows the latest answer of the provisioning ticket
 * process, which is re-run on every reconnect and when a message from the hub does not match the
 * current mode, so a tenant can move between the two (for example when the deprecated behaviour
 * is switched off and later back on) without restarting the connector.
 */
class SigningKeys {
  #config;
  #jwt;
  #configureConnectionFn;
  #cacheMaxAgeMs;
  #minRefreshIntervalMs;
  #requestTimeoutMs;

  // `jwks-rsa` client for `#jwksUri`. It owns fetching, caching, `kid` selection and the conversion
  // of keys to PEM. Created on first use, and replaced when the connector reconnects.
  #jwks;
  #jwksUri;
  // Timestamp of the last attempt to re-read the JWKS document, used for the cooldown.
  #lastAttemptAt;
  // Shared promise so concurrent refreshes trigger a single fetch.
  #inFlight;
  // Timestamp of the last provisioning ticket *attempt*, used for its own cooldown so that re-reading
  // the ticket never delays the JWKS refresh that follows it.
  #lastTicketAttemptAt;
  // Timestamp of the last attempt to recover from a message that does not match the current mode.
  #lastRecoveryAt;
  // Shared promise so concurrent failed verifications trigger a single recovery.
  #recovery;

  /**
   * @param configModule config module
   * @param jwtModule jsonwebtoken module
   * @param configureConnectionFn override for the provisioning ticket function (used by tests);
   *   defaults to the shared `lib/configureConnection` implementation.
   * @param cacheMaxAgeMs how long a fetched signing key stays fresh
   * @param minRefreshIntervalMs minimum delay between two fetch attempts; 0 disables the limit
   * @param requestTimeoutMs timeout applied to the JWKS request
   */
  constructor({
    configModule = config,
    jwtModule = jwt,
    configureConnectionFn = null,
    cacheMaxAgeMs = DEFAULT_CACHE_MAX_AGE_MS,
    minRefreshIntervalMs = DEFAULT_MIN_REFRESH_INTERVAL_MS,
    requestTimeoutMs = DEFAULT_REQUEST_TIMEOUT_MS
  } = {}) {
    this.#config = configModule;
    this.#jwt = jwtModule;
    this.#configureConnectionFn = configureConnectionFn;
    this.#cacheMaxAgeMs = cacheMaxAgeMs;
    this.#minRefreshIntervalMs = minRefreshIntervalMs;
    this.#requestTimeoutMs = requestTimeoutMs;

    this.#jwks = null;
    this.#jwksUri = null;
    this.#lastAttemptAt = 0;
    this.#inFlight = null;
    this.#lastTicketAttemptAt = 0;
    this.#lastRecoveryAt = 0;
    this.#recovery = null;
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
   * If verification fails and the token does not look like it belongs to the current mode, the
   * provisioning ticket is read again (at most once per cooldown) and the verification is retried
   * once. This covers a tenant that switched modes since the last reconnect: the connector learns
   * about it from the first message it cannot verify instead of staying out of step until it is
   * restarted.
   *
   * @param {string} token
   * @param {function} callback called with (err, payload)
   */
  verify(token, callback) {
    callbackify(() => this.#verifyWithRecovery(token))(callback);
  }

  async #verifyWithRecovery(token) {
    const keyBefore = this.#storedSigningKey();

    try {
      return await this.#verifyOnce(token);
    } catch (err) {
      // Another message may have triggered the recovery while this one was being verified. Its
      // result is already stored, so this message is verified again without asking the server again.
      const keyChanged = this.#storedSigningKey() !== keyBefore;
      if (!keyChanged && !this.#looksLikeModeMismatch(token)) {
        throw err;
      }

      const recovered = keyChanged || await this.#recoverFromModeMismatch();
      if (!recovered) {
        throw err;
      }

      return this.#verifyOnce(token);
    }
  }

  async #verifyOnce(token) {
    const verify = promisify(this.#jwt.verify.bind(this.#jwt));

    if (!this.useJwks()) {
      // Deprecated behaviour: verify against the key the server sent us. The key is always
      // asymmetric (a global client key or a tenant signing key), so we constrain verification to
      // the same asymmetric allow list as JWKS mode. This rejects the algorithm-confusion attack
      // where a token forged with the (public) key as an HMAC secret would otherwise verify, since
      // `jsonwebtoken` accepts any algorithm when none is specified.
      return verify(token, this.#config.get('TENANT_SIGNING_KEY'), { algorithms: JWKS_ALGORITHMS });
    }

    // `jsonwebtoken` expects a callback style key resolver.
    const resolveKey = callbackify((header) => this.#resolveKey(header));
    return verify(token, resolveKey, { algorithms: JWKS_ALGORITHMS });
  }

  /**
   * True when the token header suggests the hub signed with the other kind of key than the one this
   * connector currently expects: a token without a `kid` is signed with a global client key, which
   * is never published on the JWKS endpoint, and a token with a `kid` is signed with a tenant signing
   * key.
   *
   * The header is not authenticated, so this is only a hint to ask the server again. It is never used
   * to decide whether a token is valid.
   */
  #looksLikeModeMismatch(token) {
    const decoded = this.#jwt.decode(token, { complete: true });
    if (!decoded || !decoded.header) {
      return false;
    }

    const hasKid = Boolean(decoded.header.kid);
    return this.useJwks() ? !hasKid : hasKid;
  }

  /**
   * Re-runs the provisioning ticket process after a message that does not match the current mode.
   *
   * Concurrent callers share a single run, and runs are spaced by the minimum refresh interval, so
   * a stream of unverifiable messages cannot hammer the server.
   *
   * @return {Promise<boolean>} true when the stored signing key changed, so verifying again can succeed
   */
  async #recoverFromModeMismatch() {
    if (this.#recovery) {
      return this.#recovery;
    }

    if (this.#lastRecoveryAt > 0 && (Date.now() - this.#lastRecoveryAt) < this.#minRefreshIntervalMs) {
      return false;
    }

    this.#lastRecoveryAt = Date.now();
    this.#recovery = this.#rerunProvisioningTicket()
      .finally(() => {
        this.#recovery = null;
      });

    return this.#recovery;
  }

  async #rerunProvisioningTicket() {
    const previousKey = this.#storedSigningKey();

    try {
      await this.#refreshViaProvisioningTicket();
    } catch (err) {
      console.error('Could not refresh the tenant signing key through the provisioning ticket: ' + err.message);
      return false;
    }

    return this.#storedSigningKey() !== previousKey;
  }

  #storedSigningKey() {
    return (this.#config.get('TENANT_SIGNING_KEY') || '').trim();
  }

  /**
   * Key resolver handed to `jwt.verify`. Asks the `jwks-rsa` client for the key with the `kid` of the
   * message.
   *
   * The client keeps each key for the cache window and fetches the JWKS document when a key is not
   * cached, so an unknown `kid` (most likely a tenant that rotated its keys) is looked up again right
   * away. Those fetches are rate limited by the client. When the message has no `kid`, the client only
   * returns a key if the document holds exactly one, since anything else would be a guess. When the
   * document cannot be fetched, a key that was fetched earlier is still used.
   */
  async #resolveKey(header) {
    const signingKey = await this.#client().getSigningKey(header && header.kid);
    return signingKey.getPublicKey();
  }

  #client() {
    const uri = this.jwksUri();
    if (!this.#jwks || this.#jwksUri !== uri) {
      this.#jwks = this.#createClient(uri);
      this.#jwksUri = uri;
    }

    return this.#jwks;
  }

  #createClient(uri) {
    // The request deliberately relies on the process wide https configuration so that the
    // HTTP_PROXY tunnel installed by lib/setupProxy and the CA bundle injected by lib/add_certs
    // both apply, and so that Node's default minimum TLS version is honoured.
    const rateLimited = this.#minRefreshIntervalMs > 0;

    return jwksRsa({
      jwksUri: uri,
      timeout: this.#requestTimeoutMs,
      cache: true,
      cacheMaxAge: this.#cacheMaxAgeMs,
      cacheMaxEntries: MAX_CACHED_KEYS,
      cacheMaxAgeFallback: STALE_KEY_FALLBACK_MS,
      onStaleCacheFallback: (err, kid) => {
        console.error(`Could not fetch the tenant signing keys, using the last known key "${kid}": ${err.message}`);
      },
      rateLimit: rateLimited,
      // The client counts requests per minute, so the minimum delay between two requests is turned
      // into a rate.
      jwksRequestsPerMinute: rateLimited ? Math.max(1, Math.floor(60 * 1000 / this.#minRefreshIntervalMs)) : undefined
    });
  }

  #withinCooldown() {
    return this.#lastAttemptAt > 0 && (Date.now() - this.#lastAttemptAt) < this.#minRefreshIntervalMs;
  }

  #withinTicketCooldown() {
    return this.#lastTicketAttemptAt > 0 && (Date.now() - this.#lastTicketAttemptAt) < this.#minRefreshIntervalMs;
  }

  /**
   * Reads the JWKS document again and starts over with a new `jwks-rsa` client, so keys that were
   * removed from the document stop being used. Concurrent callers share a single request.
   *
   * A failed fetch never replaces the current client, so the keys it has cached stay usable. The
   * cooldown applies: inside it this resolves without fetching.
   *
   * @return {Promise<boolean>} true when the document was fetched
   */
  async refresh() {
    if (this.#inFlight) {
      return this.#inFlight;
    }

    if (this.#withinCooldown()) {
      return false;
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

    const candidate = this.#createClient(uri);
    const signingKeys = await candidate.getSigningKeys();

    this.#jwks = candidate;
    this.#jwksUri = uri;
    console.log('Loaded ' + signingKeys.length + ' tenant signing key(s).');
    return true;
  }

  /**
   * Re-fetches the tenant signing key because the connector is (re)connecting to the hub.
   *
   * The hub may have started signing with a different key while the socket was down, so the key
   * captured at setup time can no longer be assumed current. The provisioning ticket process is
   * always re-run, in either mode, because it is the server's current answer that decides the mode:
   * a connector in JWKS mode must be able to go back to a static key (and the other way around). In
   * JWKS mode the JWKS document is then read again, so rotated keys are picked up.
   *
   * Failures are logged and swallowed: the connector must still attempt to connect with whatever
   * key it already has rather than wedge itself into a permanently broken state. An unreachable
   * provisioning ticket keeps the current mode.
   *
   * @return {Promise<boolean>} true when the key for the resulting mode was actually refreshed
   */
  async refreshOnReconnect() {
    let ticketRefreshed = false;

    if (!this.#withinTicketCooldown()) {
      try {
        await this.#refreshViaProvisioningTicket();
        ticketRefreshed = true;
      } catch (err) {
        console.error('Could not refresh the tenant signing key through the provisioning ticket: ' + err.message);
      }
    }

    if (!this.useJwks()) {
      return ticketRefreshed;
    }

    try {
      return await this.refresh();
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
   * itself over to JWKS mode. A tenant that went back to the deprecated behaviour responds with a
   * `signingKey` again and this connector switches back to static mode.
   */
  async #refreshViaProvisioningTicket() {
    this.#lastTicketAttemptAt = Date.now();

    const provisioningTicket = this.#config.get('PROVISIONING_TICKET');
    if (!provisioningTicket) {
      throw new Error('PROVISIONING_TICKET is not set.');
    }

    console.log('Refreshing the tenant signing key through the provisioning ticket.');

    const previousKey = this.#config.get('TENANT_SIGNING_KEY');

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

    // Persist only when the key actually changed. Reconnects happen on every network blip, so an
    // unconditional save would write to disk each time even though the key is usually unchanged.
    if (tenantSigningKey !== previousKey) {
      await this.#config.save();
    }
  }

  #configureConnection() {
    return this.#configureConnectionFn || configureConnection;
  }
}

const signingKeys = new SigningKeys();

module.exports = signingKeys;
module.exports.SigningKeys = SigningKeys;
module.exports.JWKS_ALGORITHMS = JWKS_ALGORITHMS;
