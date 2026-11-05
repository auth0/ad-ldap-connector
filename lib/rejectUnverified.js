const jwt = require('jsonwebtoken');

/**
 * Error code put in the reply to the hub when a request could not be verified.
 */
const INVALID_SIGNATURE = 'invalid_signature';

/**
 * Tells the hub that a request was rejected because its signature could not be verified.
 *
 * Verification happens before anything is run, so the hub knows the request was not executed and can
 * send it again signed with a newer key. Without this reply the hub only finds out when its own request
 * times out.
 *
 * The reply is addressed with the `pid` from the token before it is verified. That is safe because the
 * `pid` only routes the reply back to the hub and is never trusted for anything else.
 *
 * The reply says why in `reason`, the name of the verification error (for example `JsonWebTokenError`,
 * `TokenExpiredError` or `NotBeforeError`), so the hub can tell a key problem from a clock problem and
 * decide what to try next. No reply is sent when the token has no `pid`.
 *
 * @param {string} token the request token that failed verification
 * @param {Error} verifyError the error `jwt.verify` or the signing key module returned
 * @param {string} replyEventSuffix the suffix of the reply event for this request, appended to the `pid`
 * @param {function(string, object): void} send sends an event to the hub
 * @return {boolean} true when a reply was sent
 */
function rejectUnverified(token, verifyError, replyEventSuffix, send) {
  const decoded = jwt.decode(token);
  const pid = decoded && decoded.pid;
  if (!pid) {
    return false;
  }

  const err = {
    code: INVALID_SIGNATURE,
    // The text of the verification error is not sent: it can name the tenant's JWKS address.
    message: 'The connector could not verify the signature of the request.'
  };

  // Only the name of the error is sent, so the reply stays free of addresses and key details.
  if (verifyError && typeof verifyError.name === 'string') {
    err.reason = verifyError.name;
  }

  send(pid + replyEventSuffix, { err });

  return true;
}

/**
 * The feature the hub announces in its `authenticated` event when it understands the `invalid_signature`
 * reply. A connector only sends the reply to a hub that announced it, so a hub that does not know the
 * reply (or does not use it for this tenant) sees the same silence as before.
 */
const INVALID_SIGNATURE_REPLY = 'invalid_signature_reply';

/**
 * @param {*} payload the payload of the hub's `authenticated` event
 * @return {boolean} true when the hub announced that it understands the `invalid_signature` reply
 */
function hubAnnouncesReply(payload) {
  return Boolean(payload && Array.isArray(payload.features) && payload.features.includes(INVALID_SIGNATURE_REPLY));
}

module.exports = { rejectUnverified, hubAnnouncesReply, INVALID_SIGNATURE, INVALID_SIGNATURE_REPLY };
