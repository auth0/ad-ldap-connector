var templates = require('./templates');
var PassportProfileMapper = require('./claims/PassportProfileMapper');
var saml11 = require('saml').Saml11;

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
 * options:
 * - profileMapper(profile) a ProfileMapper implementation to convert a user profile to claims  (PassportProfile).
 * - getUserFromRequest(req) a function that given a request returns the user. By default req.user
 * - validateAudience(clientId, callback) a function that given a client id (wtrealm) returns a client with key, cert and callbacks. Defaults all valid.
 * - issuer string
 * - cert the public certificate
 * - key the private certificate to sign all tokens
 * - callbackUrl
 * 
 * @param  {[type]} options [description]
 * @return {[type]}         [description]
 */
module.exports = function(options) {
  options = options || {};
  options.profileMapper = options.profileMapper || PassportProfileMapper;
  options.getUserFromRequest = options.getUserFromRequest || function(req){ return req.user; };
  options.validateAudience = options.validateAudience || function(aud, cb) { cb(null, aud); };

  return function (req, res) {
    var audience =  options.audience ||
                    req.query.wtrealm ||
                    req.query.wreply;
    
    audience = asResource(audience);

    var user = options.getUserFromRequest(req);
    
    if(!user) return res.send(401);
    var profileMap = options.profileMapper(user);

    var claims = profileMap.getClaims();
    var ni = profileMap.getNameIdentifier();
    
    var signedAssertion = saml11.create({  
      signatureAlgorithm:   options.signatureAlgorithm,
      digestAlgorithm:      options.digestAlgorithm,
      cert:                 options.cert,
      key:                  options.key,
      issuer:               asResource(options.issuer),
      lifetimeInSeconds:    3600,
      audiences:            audience,
      attributes:           claims,
      nameIdentifier:       ni.nameIdentifier,
      nameIdentifierFormat: ni.nameIdentifierFormat
    });
    
    res.set('Content-Type', 'text/html');

    res.send(templates.form({
      callback:        options.callbackUrl,
      wctx:            options.wctx || req.query.wctx,
      signedAssertion: signedAssertion
    }));

  };
};