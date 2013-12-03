var templates             = require('./templates');
var PassportProfileMapper = require('./claims/PassportProfileMapper');
var utils                 = require('./utils');
var saml11 = require('saml').Saml11;
var jwt                   = require('jsonwebtoken');

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
 * - issuer string
 * - cert the public certificate
 * - key the private certificate to sign all tokens
 * - postUrl function (wtrealm, wreply, request, callback)
 * 
 * @param  {[type]} options [description]
 * @return {[type]}         [description]
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
    res.send(templates[(!options.plain_form ? 'form' : 'form_el')]({
      callback:        postUrl,
      wctx:            wctx,
      wresult:         assertion
    }));
  }

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
      saml11.create({  
        signatureAlgorithm:   options.signatureAlgorithm,
        digestAlgorithm:      options.digestAlgorithm,
        cert:                 options.cert,
        key:                  options.key,
        issuer:               asResource(options.issuer),
        lifetimeInSeconds:    options.lifetime || (60 * 60 * 8),
        audiences:            audience,
        attributes:           claims,
        nameIdentifier:       ni.nameIdentifier,
        nameIdentifierFormat: ni.nameIdentifierFormat,
        encryptionPublicKey:  options.encryptionPublicKey,
        encryptionCert:       options.encryptionCert
      }, function(err, assertion) {
        if (err) return next(err);
        var escapedWctx = utils.escape(utils.escape(ctx)); // we need an escaped value for RequestSecurityTokenResponse.Context
        var escapedAssertion = utils.escape(assertion); // we need an escaped value for RequestSecurityTokenResponse.Context
        assertion = '<t:RequestSecurityTokenResponse Context="'+ escapedWctx + '" xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"><t:RequestedSecurityToken>' + escapedAssertion + '</t:RequestedSecurityToken></t:RequestSecurityTokenResponse>';

        return renderResponse(res, postUrl, ctx, assertion);
      });

    } else {
      var signed = jwt.sign(user, options.key.toString(), {
        expiresInMinutes: (options.lifetime || (60 * 60 * 8)) / 60,
        audience:         audience,
        issuer:           asResource(options.issuer),
        algorithm:        options.jwtAlgorithm || 'RS256'
      });

      return renderResponse(res, postUrl, ctx, signed);
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
