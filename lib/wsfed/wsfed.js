var templates             = require('./templates');
var PassportProfileMapper = require('./claims/PassportProfileMapper');
var utils                 = require('./utils');
var saml11 = require('saml').Saml11;
var jwt                   = require('jsonwebtoken');
var interpolate           = require('./interpolate');
var xtend                 = require('xtend');

function asResource(res) {
  if(res.substr(0, 6) !== 'http:/' &&
      res.substr(0, 6) !== 'https:' &&
      res.substr(0, 4) !== 'urn:') {
    return 'urn:' + res;
  }
  return res;
}

/**
 * WSFederation middleware.
 *
 * This middleware creates a WSFed endpoint based on the user logged in identity.
 * 
 * @param {object} options
 * @param {function} options.getPostURL REQUIRED the function receives 4 parameters from the request (wtrealm, wreply, request, callback). It must return, via the callback,
 * the URL to post the result response to.
 * @param {function} options.getUserFromRequest the function receives one parameter, the request. It must return the user being authenticated, as an object. 
 * This object will be passed to the profile mapper to determine attributes of the response.
 * @param {PassportProfileMapper} options.profileMapper a ProfileMapper implementation to convert a user profile to claims  (PassportProfile).
 * @param {Buffer} options.cert The public key / certificate of the issuer, in PEM format.
 * @param {Buffer} options.key The private key of the issuer, used to sign the response, in PEM format.
 * @param {string} options.issuer the name of the issuer of the response.
 * @param {string} options.audience the name of the audience of the response.
 * @param {number} options.lifetime The lifetime of the response, in seconds. Default 8 hours.
 * @param {string} options.signatureAlgorithm signature algorithm, options: rsa-sha1, rsa-sha256. default rsa-sha256.
 * @param {string} options.digestAlgorithm digest algorithm, options: sha1, sha256. default sha256.
 * @param {boolean} options.jwt if true, uses a JWT token for the signed assertion. default false.
 * @param {object} options.extendJWT An object that, is passed, contains claims to be added to JWT signed assertion.
 * @param {boolean} options.jwtAlgorithm If using JWT signed assertion, indicates the algorithm to be applied. Default RS256.
 * @param {boolean} options.jwtAllowInsecureKeySizes Insecure and not recommended, for backward compatibility ONLY. If true, allows insecure key sizes to be used when signing with JWT. Default false.
 * @param {boolean} options.jwtAllowInvalidAsymmetricKeyTypes Insecure and not recommended, for backward compatibility ONLY. 
 * If true, allows a mismatch between JWT algorithm and the actual key type provided to sign.
 * @param {boolean} options.encryptionAlgorithm encryption algorithm to encrypt the assertion. default http://www.w3.org/2009/xmlenc11#aes256-gcm
 * @param {boolean} options.disallowEncryptionWithInsecureAlgorithm if true, disallows encryption with algorithms considered insecure. default true.
 * @param {boolean} options.warnOnInsecureEncryptionAlgorithm if true, logs a warning when using an insecure encryption algorithm. default true.
 * 
 * @return {function} An Express middleware that acts as a WsFed endpoint.
 */
module.exports = function(options) {
  options = options || {};
  options.profileMapper = options.profileMapper || PassportProfileMapper;
  options.getUserFromRequest = options.getUserFromRequest || function(req){ return req.user; };

  if(typeof options.getPostURL !== 'function') {
    throw new Error('getPostURL is required');
  }

  function renderResponse(res, postUrl, wctx, assertion) {
    res.set('Content-Type', 'text/html');
    var model = {
      callback:        postUrl,
      wctx:            wctx,
      wresult:         assertion
    };
    var form;

    if (options.formTemplate) {
      form = interpolate(options.formTemplate);
    } else {
      form = templates[(!options.plain_form ? 'form' : 'form_el')];
    }

    res.send(form(model));
  }

  var responseHandler = options.responseHandler || renderResponse;

  function execute (postUrl, req, res, next) {
    var audience =  options.audience ||
                    req.query.wtrealm ||
                    req.query.wreply;

    if(!audience){
      return next(new Error('audience is required'));
    }

    audience = asResource(audience);

    var user = options.getUserFromRequest(req);
    if(!user) return res.send(401);

    var ctx = options.wctx || req.query.wctx;
    if (!options.jwt) {
      var profileMap = options.profileMapper(user);
      var claims = profileMap.getClaims(options);
      var ni = profileMap.getNameIdentifier(options);
      if (!ni || !ni.nameIdentifier) {
        return next(new Error('No attribute was found to generate the nameIdentifier'));
      }

      saml11.create({
        signatureAlgorithm:                       options.signatureAlgorithm,
        digestAlgorithm:                          options.digestAlgorithm,
        cert:                                     options.cert,
        key:                                      options.key,
        issuer:                                   asResource(options.issuer),
        lifetimeInSeconds:                        options.lifetime || options.lifetimeInSeconds || (60 * 60 * 8),
        audiences:                                audience,
        attributes:                               claims,
        nameIdentifier:                           ni.nameIdentifier,
        nameIdentifierFormat:                     ni.nameIdentifierFormat || options.nameIdentifierFormat,
        encryptionPublicKey:                      options.encryptionPublicKey,
        encryptionCert:                           options.encryptionCert,
        encryptionAlgorithm:                      options.encryptionAlgorithm,
        disallowEncryptionWithInsecureAlgorithm:  options.disallowEncryptionWithInsecureAlgorithm,
        warnOnInsecureEncryptionAlgorithm:        options.warnOnInsecureEncryptionAlgorithm
      }, function(err, assertion) {
        if (err) return next(err);
        var escapedWctx = utils.escape(ctx); 
        assertion = '<t:RequestSecurityTokenResponse Context="'+ escapedWctx + '" xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"><t:RequestedSecurityToken>' + assertion + '</t:RequestedSecurityToken></t:RequestSecurityTokenResponse>';

        return responseHandler(res, postUrl, ctx, assertion);
      });

    } else {
      if (options.extendJWT && typeof options.extendJWT === 'object') {
        user = xtend(user, options.extendJWT);
      }

      jwt.sign(user, options.key.toString(), {
        expiresIn: options.lifetime || options.lifetimeInSeconds || (60 * 60 * 8),
        audience: audience,
        issuer: asResource(options.issuer),
        algorithm: options.jwtAlgorithm || 'RS256',
        allowInsecureKeySizes: options.jwtAllowInsecureKeySizes || false,
        allowInvalidAsymmetricKeyTypes: options.jwtAllowInvalidAsymmetricKeyTypes || false
      }, (error, signed) => {
        if (error) {
          return next(error);
        }

        return responseHandler(res, postUrl, ctx, signed);
      });
    }
  }

  return function (req, res, next) {
    options.getPostURL(req.query.wtrealm, req.query.wreply, req, function (err, postUrl) {
      if (err) return next(err);
      if (!postUrl) return res.send(400, 'postUrl is required');
      execute(postUrl, req, res, next);
    });
  };
};
