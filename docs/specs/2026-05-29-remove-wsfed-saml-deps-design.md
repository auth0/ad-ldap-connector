# Remove `wsfed` and `saml` dependencies — design

**Date:** 2026-05-29
**Status:** Draft
**Owner:** Charles Rea

## Background

`ad-ldap-connector` depends on the npm package `wsfed`, which in turn depends on `saml`. This document specifies how we remove both dependencies by ingesting the relevant code into this repository.

The connector only ever uses a small subset of these packages:

- `wsfed.auth({ issuer, cert, key, getPostURL, audience?, plain_form?, wctx? })` — produces a SAML 1.1 signed assertion wrapped in a WS-Trust `RequestSecurityTokenResponse` and renders it inside an HTML form.
- `wsfed.metadata({ cert, issuer })` — emits the WS-Federation metadata XML.

Within the SAML 1.1 path the connector does not exercise: JWT signed assertions, encryption, custom `formTemplate`, custom `responseHandler`, SAML 2.0, `federationServerService`, or `sendError`.

## Goals

- Remove the `wsfed` direct dependency and the transitive `saml` dependency from `package.json` and the lockfile.
- Preserve byte-for-byte the HTTP responses emitted by `/wsfed`, `/wsfed/direct`, and `/wsfed/FederationMetadata/2007-06/FederationMetadata.xml`.
- Land the change in a way that is easy to review.
- Add test coverage for the ingested code so future changes are safe.

## Non-goals

- Replace `Math.random()` AssertionID generation with `crypto.randomBytes` (out of scope; not security-sensitive — the AssertionID is a document-local identifier, not a token nonce).
- Modernize Express 4 legacy `res.send(status, body)` call sites.
- Bump the `passport` major version.
- Maintain compatibility with the deleted features (encryption, JWT, SAML 2.0, etc.) — these were never used by the connector.

## Approach

### Layout

The ingested code is split into two folders mirroring the upstream package boundary. Vendoring is byte-identical to upstream's filesystem layout — so `templates/` lives as a sibling of the JS files inside `lib/wsfed/`, and `lib/wsfed/templates.js`'s `require('../templates')` keeps working without modification:

```
ad-ldap-connector/
  lib/
    wsfed/
      index.js               exports { auth, metadata }
      wsfed.js               auth middleware
      metadata.js
      encoders.js            removeHeaders helper
      templates.js           EJS loader (loads ../templates)
      utils.js
      claims/
        PassportProfileMapper.js
      templates/
        form.ejs, form_el.ejs, metadata.ejs
    saml/
      index.js               exports { Saml11 }
      saml11.js
      saml11.template
      sign.js
      utils.js
    wsfederation-responses.js
  test/
    wsfed/
      auth.tests.js
      metadata.tests.js
      profile-mapper.tests.js
      fixtures/
        key.pem, cert.pem
        expected-assertion.xml
        expected-metadata.xml
    saml/
      saml11.tests.js
      fixtures/                (trimmed copy of upstream fixtures)
```

File names are kept faithful to the upstream packages (e.g. `wsfed.js`, `claims/PassportProfileMapper.js`) so that the trim commit shows clean line-level diffs against the verbatim vendoring commits, with no rename detection noise.

### What is dropped

In `lib/saml/`:

- `saml20.js`, `saml20.template` — SAML 2.0, unused.
- `xml/encrypt.js` — encryption support, unused.
- The `xml/` subfolder is collapsed; `sign.js` moves up to `lib/saml/sign.js`.
- In `saml11.js`: the encryption code path (xml-encryption import, `holder-of-key` flow, `addSubjectConfirmation`, `async.waterfall`). `createUnsignedAssertion` is also removed.
- Any unused exports from `utils.js` after the encryption branch is gone.

In `lib/wsfed/`:

- `federationServerService.js` and the `federationServerService*.ejs` templates — unused (ADFS WSDL endpoint).
- `sendError.js` and `soapFault.ejs` — unused.
- `interpolate.js` — needed only by removed paths (`formTemplate`, `sendError`).
- In `wsfed.js`: the `options.jwt` branch, `extendJWT`, `jwtAlgorithm`, `jwtAllowInsecureKeySizes`, `jwtAllowInvalidAsymmetricKeyTypes`, `encryptionPublicKey`, `encryptionCert`, `encryptionAlgorithm`, `disallowEncryptionWithInsecureAlgorithm`, `warnOnInsecureEncryptionAlgorithm`, custom `responseHandler`, custom `formTemplate`.

### What is preserved

- `saml11.create(options, callback)` keeps its `(err, assertion)` callback signature. Internally the encryption branch is gone, collapsing the body to `signXml(doc, callback)` (one async step, no `async.waterfall`), but the external contract is unchanged.
- The PEM-formatting fallback in `sign.js` — if the first sign attempt throws, retry with `utils.fixPemFormatting(key)`. The connector loads keys from secure storage and we don't want to regress on tolerant PEM handling.
- `utils.uid` AssertionID generation — verbatim, including the use of `Math.random()`.
- The exact wire format of every XML output, including the `RequestSecurityTokenResponse` wrap, the `Context=` HTML escaping (which escapes only `& < > "`, not `'`), and EJS template rendering of the form/metadata responses.
- All upstream error-path behavior (see Error handling below).

### Dependency changes

`package.json`:

- Add: `xml-crypto` (`^2.1.3`), `@xmldom/xmldom` (`^0.7.4`), `moment` (`^2.29.4`) — pinned to the versions `node-saml@4.0.0` uses today.
- Remove: `wsfed`.

Transitive dependencies that disappear from the lockfile after the change:

- `wsfed`, `saml`, `xml-encryption`, `valid-url`, `xml-name-validator`, `xpath`.

Already-direct dependencies of the connector that remain in use: `ejs`, `jsonwebtoken` (still used elsewhere in the connector), `xtend`, `@auth0/thumbprint`, `async`.

## Data flow (preserved)

### `GET /wsfed` and `POST /wsfed`

```
endpoints.js
  → wsfederationResponses.token  (cached middleware from initialize())
    → lib/wsfed/wsfed.js
      → options.getPostURL(wtrealm, wreply, req, cb)
      → PassportProfileMapper(req.user).getClaims()
      → PassportProfileMapper(req.user).getNameIdentifier()
      → saml11.create({ issuer, audiences, attributes, nameIdentifier,
                         cert, key,
                         lifetimeInSeconds: 60*60*8 },
                       (err, assertion) => …)
        → newSaml11Document() (from saml11.template)
        → fill AssertionID/Issuer/IssueInstant/Conditions/Audience/
               Attributes/NameIdentifier/AuthenticationStatement
        → sign.fromSignXmlOptions({ key, cert,
                                     xpathToNodeBeforeSignature,
                                     signatureIdAttribute: 'AssertionID' })(doc, cb)
          → xml-crypto SignedXml: enveloped + exc-c14n, X509 KeyInfo
        → callback(null, signedXml)
      → wrap in <t:RequestSecurityTokenResponse Context="…">…</t:RequestSecurityTokenResponse>
      → templates.form (auto-posting HTML form) renders → res.send(html)
```

### `POST /wsfed/direct`

Same as above, except `wsfederationResponses.tokenDirect` passes `plain_form: true`, `wctx: JSON.stringify(...)`, and a precomputed `audience`. `plain_form: true` selects `templates.form_el` (form fragment, no auto-submit script).

### `GET /wsfed/FederationMetadata/2007-06/FederationMetadata.xml`

```
endpoints.js
  → wsfederationResponses.metadata()
    → lib/wsfed/metadata.js
      → claimTypes from PassportProfileMapper.prototype.metadata
      → encoders.removeHeaders(cert)  (strip PEM markers)
      → templates.metadata({ claimTypes, pem, issuer, endpoint, mexEndpoint:'' })
        → strip newlines → res.send
```

## Behavioral invariants

1. **Wire format of the signed assertion.** Same XML template, same `xml-crypto` config (signature alg `rsa-sha256`, digest `sha256`, enveloped + exc-c14n, X509 KeyInfo block, signature placed after the `AuthenticationStatement` xpath, `idAttribute: 'AssertionID'`). The `X509Certificate` value is the cert with PEM headers stripped and newlines removed (via `utils.pemToCert`).
2. **`RequestSecurityTokenResponse` wrap.** Identical literal: `<t:RequestSecurityTokenResponse Context="<escaped wctx>" xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"><t:RequestedSecurityToken>…</t:RequestedSecurityToken></t:RequestSecurityTokenResponse>`. `wctx` HTML-escaped via `utils.escape` (escapes `& < > "` only).
3. **`audience` resolution.** `options.audience || req.query.wtrealm || req.query.wreply`, then `asResource()` prefixes `urn:` if not already a URL or URN.
4. **`getPostURL` callback contract.** `(wtrealm, wreply, req, cb)`; `cb(null, postUrl)` to render, `cb()` (no postUrl) → `res.send(400, 'postUrl is required')`.
5. **Form rendering.** Default uses `form.ejs` (auto-posts via `setTimeout`); `plain_form: true` uses `form_el.ejs`. EJS values render with EJS's default HTML-escape `<%= %>`.
6. **Metadata XML.** Identical template, including the conditional `mexEndpoint` block (always empty in our use). Newlines stripped after rendering.
7. **Error propagation.** Errors from `saml11.create` and `getPostURL` are passed to `next(err)`; nothing is swallowed.
8. **Lifetime default.** 8 hours (`60 * 60 * 8`).
9. **Express 4 legacy `res.send` signatures.** `res.send(401)` and `res.send(400, body)` are mirrored verbatim.

## Error handling

| Source | Behavior |
|---|---|
| `getPostURL` callback returns err | `next(err)` |
| `getPostURL` callback returns no postUrl | `res.send(400, 'postUrl is required')` |
| no `audience` (none of `options.audience`/`wtrealm`/`wreply`) | `next(new Error('audience is required'))` |
| `getUserFromRequest(req)` returns falsy | `res.send(401)` |
| `PassportProfileMapper` cannot derive a nameIdentifier | `next(new Error('No attribute was found to generate the nameIdentifier'))` |
| `saml11.create` callback err (template parse, sign failure, bad PEM) | `next(err)` |
| Metadata middleware: missing `issuer` or `cert` at construction | throws synchronously (caught by `wsfederationResponses.initialize`) |

## Migration risks

- **Byte-level XML drift breaks downstream consumers (Auth0 tenant verifying the assertion).** Mitigated by the byte-equality `expected-assertion.xml` test against a frozen clock + fixed cert/key.
- **`xml-crypto` version drift.** Pinned to `^2.1.3` (matches `node-saml@4.0.0`); no major bumps without a regenerated expected file.
- **`@xmldom/xmldom` version drift.** Pinned to `^0.7.4` — `0.8.x` has different namespace handling.

## Commit structure

The change lands as four commits to make review tractable. Commits 1 and 2 are pure vendoring (verbatim from upstream — reviewable via `diff -r`). Commit 3 rewires imports so the vendored code can be loaded by node and tests pass. Commit 4 is the line-level trim.

### Commit 1 — Vendor `node-wsfed` verbatim

- Copy `node-wsfed/lib/` and `node-wsfed/templates/` into `lib/wsfed/` exactly preserving upstream filesystem layout (`lib/wsfed/templates/` sits next to `lib/wsfed/templates.js`, mirroring upstream's `lib/` + `templates/` siblings).
- Copy `node-wsfed/test/` into `test/wsfed/` exactly as-is.
- Update `lib/wsfederation-responses.js` to `require('./wsfed')` instead of `require('wsfed')`.
- `lib/wsfed/wsfed.js` is left untouched in this commit — its `require('saml').Saml11` continues to resolve to the npm `saml` package, now a direct dep of the connector.
- `package.json`: add `xml-crypto` (`^2.1.3`), `@xmldom/xmldom` (`^0.7.4`), `moment` (`^2.29.4`); add `saml` (`^4.0.0`) as a direct dep so the require path resolves at this commit; remove `wsfed`. Regenerate `package-lock.json`.
- Add `.mocharc.cjs` excluding `test/wsfed/**` and `test/saml/**` from mocha. Vendored test files use `require('../lib/...')` paths that don't resolve from `test/wsfed/`; rather than edit the vendored files (which would break the verbatim invariant), we exclude them from mocha until commit 3 rewires them.
- After this commit, `node -e "require('./lib/wsfed')"` does NOT work — `lib/wsfed/templates.js` does `require('__dirname/../templates')`, which from `lib/wsfed/templates.js` resolves to `lib/templates/` (which doesn't exist; templates live at `lib/wsfed/templates/`). This is intentional — we accept a temporarily-non-loading state in exchange for a clean `diff -r` invariant. The connector's existing test suite doesn't exercise `lib/wsfed`, so `npm test` still passes.
- Commit message references the upstream `node-wsfed` commit hash so a reviewer can run `diff -r` against the source tree and see zero diff.

### Commit 2 — Vendor `node-saml` verbatim

- Copy `node-saml/lib/` into `lib/saml/` exactly as-is, preserving `xml/sign.js`, `xml/encrypt.js`, `saml11.js`, `saml20.js`, `saml11.template`, `saml20.template`, `utils.js`, `index.js`.
- Copy `node-saml/test/` into `test/saml/` exactly as-is.
- Update `lib/wsfed/wsfed.js` to `require('../saml').Saml11` instead of `require('saml').Saml11`. (This is the ONLY edit to vendored files in this commit.)
- `package.json`: remove `saml` (no longer needed as a direct dep). Regenerate `package-lock.json`.
- Commit message references `node-saml@4.0.0`.

After commits 1 and 2 the connector vendors both packages with zero diff vs upstream filesystem layout (modulo the single one-liner require swap in commit 2's `wsfed.js`). Both `wsfed` and `saml` are out of the npm dep tree.

### Commit 3 — Rewire imports

This commit makes the vendored code loadable by node and gets the vendored test suites passing. It is the first commit that introduces line-level edits to vendored files.

- Edit `lib/wsfed/templates.js` so its `__dirname/../templates` lookup resolves to `lib/wsfed/templates/`. (Either change to `__dirname/templates` or `path.join(__dirname, 'templates')`.)
- Edit any other vendored file whose relative require fails because the surrounding file structure changed (e.g. `lib/wsfed/wsfed.js`'s `require('../saml').Saml11` already happened in commit 2; check if anything else broke).
- Edit each vendored test file's `require('../lib/...')` paths to point at the new locations (`require('../../lib/wsfed/...')` or similar).
- Remove the `test/wsfed/**` and `test/saml/**` ignore entries from `.mocharc.cjs` (or delete the file if those were the only entries).
- Verify `npm test` runs the existing connector suite + the full vendored wsfed and saml suites and is green. Some tests for removed-in-commit-4 features (encryption, JWT, SAML 2.0) should still pass at this commit since the underlying code is still present.

### Commit 4 — Trim and tidy

This is the only commit reviewers need to read line-by-line.

In `lib/saml/`:

- Delete `saml20.js`, `saml20.template`, `xml/encrypt.js`.
- Reduce `index.js` to `module.exports.Saml11 = require('./saml11');` (or remove it and update `lib/wsfed/wsfed.js` to `require('../saml/saml11')` — equivalent for review).
- Trim `saml11.js`: drop the encryption branch (xml-encryption import, `holder-of-key` flow, `addSubjectConfirmation`, `async.waterfall`); drop `createUnsignedAssertion`.
- Move `xml/sign.js` to `saml/sign.js`; delete the empty `xml/` folder; update `saml11.js` import.
- Trim `utils.js` if unused exports remain after the encryption branch is gone.

In `lib/wsfed/`:

- Delete `federationServerService.js`, `sendError.js`, `interpolate.js`.
- Delete `templates/federationServerService*.ejs`, `templates/soapFault.ejs`.
- Trim `wsfed.js`: drop the JWT branch, encryption options, custom `formTemplate`, custom `responseHandler`.
- Update `index.js` to export only `auth` and `metadata`.

In tests:

- Trim `test/saml/` and `test/wsfed/` to drop tests for removed paths (encryption, JWT, SAML 2.0, `formTemplate`/`responseHandler`/`federationServerService`/`sendError`).
- Add `test/wsfed/fixtures/expected-assertion.xml` and `expected-metadata.xml` with byte-equality tests against frozen-clock outputs.

## Testing

### Test layout

```
test/
  wsfed/
    fixtures/
      key.pem                  test RSA private key (2048-bit, generated once, committed)
      cert.pem                 matching public cert (long expiry, committed)
      expected-assertion.xml   expected signed assertion (frozen clock, deterministic uid)
      expected-metadata.xml    expected metadata response
    auth.tests.js              wsfed.auth middleware behavior
    metadata.tests.js          wsfed.metadata middleware behavior
    profile-mapper.tests.js    PassportProfileMapper claim/nameId derivation
  saml/
    fixtures/
    saml11.tests.js            saml11.create builder behavior
```

### Determinism plumbing

`saml11.js` reads `moment.utc()` for `IssueInstant`/`NotBefore`/`NotOnOrAfter` and `utils.uid(32)` for the AssertionID. To produce stable output:

- `sinon.useFakeTimers` set to a fixed UTC instant.
- Stub `utils.uid` (or its random source) to return a fixed string, OR generate the expected file once with a freshly-signed assertion and re-use it for byte-equality comparison.

### Coverage

`saml/saml11.tests.js` (ported from `node-saml/test/saml11.tests.js`, dropping encryption tests):

- Builds an assertion with `issuer`, `lifetimeInSeconds`, single + multiple `audiences`, `attributes` (string + array values, undefined skipped), `nameIdentifier`, `nameIdentifierFormat`.
- Result parses as XML.
- `IssueInstant`, `NotBefore`, `NotOnOrAfter` formatted as `YYYY-MM-DDTHH:mm:ss.SSS[Z]`.
- `AssertionID` starts with `_`.
- Embedded `X509Certificate` matches input cert (header-stripped, newline-stripped).
- Signature verifies via `xml-crypto.SignedXml` using the embedded cert.
- Tampering with the assertion body invalidates the signature.
- `signatureAlgorithm: 'rsa-sha1'` → SignatureMethod URI is `…#rsa-sha1`; default → `…#rsa-sha256`.
- `digestAlgorithm` default → `…#sha256`.
- PEM-formatting fallback: a malformed-but-recoverable key still signs.
- Missing key/cert throws synchronously.

`wsfed/auth.tests.js` (ported from `node-wsfed/test/wsfed.tests.js`, dropping JWT and encryption tests):

- `auth({ getPostURL })` returns an Express middleware.
- Throws synchronously if `getPostURL` is not a function.
- `getPostURL` called with `(wtrealm, wreply, req, cb)` — verify args.
- `cb(null, postUrl)` → renders auto-posting form; HTML contains `action="<postUrl>"`, `name="wresult"` value, `name="wctx"` value (HTML-escaped).
- `cb()` (no postUrl) → 400.
- `cb(err)` → `next(err)`.
- `req.user` missing → 401.
- `audience` resolution: precedence `options.audience` > `req.query.wtrealm` > `req.query.wreply`.
- `audience` is `urn:`-prefixed when not already `http(s):`/`urn:`.
- Missing audience → `next(new Error('audience is required'))`.
- `plain_form: true` → response is form fragment (`form_el`), no auto-submit `<script>`.
- `RequestSecurityTokenResponse` wrap is exact, including `Context=` HTML-escaping and the `xmlns:t` namespace.
- `wctx` from `options.wctx` overrides `req.query.wctx`.
- `nameIdentifier` derivation failure → `next(error)`.
- Profile-mapper error path: empty profile → 'No attribute was found' error.

`wsfed/metadata.tests.js` (ported from `node-wsfed/test/metadata.tests.js`):

- Throws if `issuer` or `cert` missing.
- Sets `Content-Type: application/xml`.
- Output parses as XML.
- `entityID` matches issuer.
- `<X509Certificate>` matches header-stripped cert.
- Includes all five `auth:ClaimType` entries from `PassportProfileMapper.prototype.metadata`.
- `mexEndpoint` block omitted by default.
- No newlines in the output.

`wsfed/profile-mapper.tests.js`:

- Maps `id` → nameidentifier claim.
- Maps `emails[0].value` → emailaddress claim.
- Maps `displayName` → name claim.
- Maps `name.givenName`/`familyName` → givenname/surname claims.
- Custom keys flow through with `http://schemas.passportjs.com/<key>` namespace.
- `getNameIdentifier` falls back through nameId → name → emailaddress.

### Expected-file approach

One frozen end-to-end test per output (`expected-assertion.xml`, `expected-metadata.xml`) compares byte-for-byte (after the upstream `removeWhitespace` pass). Catches accidental drift in `xml-crypto` or `xmldom` updates. If the test fails after a deliberate dependency bump, the failure tells you exactly what changed and you regenerate the expected file.

### CI

`mocha --recursive` already runs everything under `test/`. The new directories are auto-picked up. No CI configuration changes.

## Out of scope

- Replacing `Math.random()` AssertionID with `crypto.randomBytes`.
- Modernizing legacy `res.send(status, body)` calls.
- Changing the `passport` major version.
- Any behavior change visible to clients of the WS-Fed endpoints.
