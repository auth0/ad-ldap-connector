const crypto = require('crypto');
const wsfed = require('./wsfed');
const xtend = require('xtend');
const config = require('./config');
const certificates = require('./certificates');
const secureStorage = require('./secureStorage');

// Produces an AES-256-GCM encrypted blob in the same wire format used by
// cookie-sessions: "<ciphertext>$<iv>$<authTag>" (all hex), wrapping the
// session data as { d: data, t: timestamp }.
function serializeSession(secret, data) {
  var payload = JSON.stringify({ d: data, t: Date.now() });
  var iv = crypto.randomBytes(16);
  var cipher = crypto.createCipheriv('aes-256-gcm', secret, iv);
  var ciphertext = cipher.update(payload, 'utf8', 'hex') + cipher.final('hex');
  return [ciphertext, iv.toString('hex'), cipher.getAuthTag().toString('hex')].join('$');
}

let issuer;
let audience;
const credentials = {};
let sessionSecret;

exports.initialize = async function() {
  issuer = config.get('WSFED_ISSUER');
  audience = config.get('REALM');
  sessionSecret = await secureStorage.get(secureStorage.keys.CONNECTOR_SESSION_SECRET);
  if (!sessionSecret) {
    throw new Error('Session secret not generated on startup.');
  }
  credentials.cert = certificates.getCertificate();
  credentials.key = certificates.getPrivateKey();

  exports.token = wsfed.auth({
    issuer: issuer,
    cert: credentials.cert,
    key: credentials.key,
    getPostURL:  function (wtrealm, wreply, req, callback) {
      var realmPostURLs = config.get(wtrealm || config.get('REALM'));
      if (realmPostURLs) {
        realmPostURLs = realmPostURLs.split(',');
        if (wreply && ~realmPostURLs.indexOf(wreply)) {
          return callback(null, wreply);
        }
        if(!wreply){
          return callback(null, realmPostURLs[0]);
        }
      }
      callback();
    }
  });

  exports.metadata = function () {
    return wsfed.metadata({
      cert:   credentials.cert,
      issuer: issuer
    });
  };
};

exports.tokenDirect = function (req, res, next) {

  var wctx = xtend({
    strategy: 'ad'
  }, req.body, {
    session: serializeSession(sessionSecret, req.session)
  });

  delete wctx.username;
  delete wctx.password;

  return wsfed.auth({
    issuer: issuer,
    cert: credentials.cert,
    key: credentials.key,
    audience: audience,
    plain_form: true,
    wctx: JSON.stringify(wctx),
    getPostURL:  function (wtrealm, wreply, req, callback) {
      var realmPostURLs = config.get(wtrealm || config.get('REALM'));
      if (realmPostURLs) {
        realmPostURLs = realmPostURLs.split(',');

        if (wreply && ~realmPostURLs.indexOf(wreply)) {
          return callback(null, wreply);
        }

        if (!wreply) {
          return callback(null, realmPostURLs[0]);
        }
      }

      callback();
    }
  })(req, res, next);
};
