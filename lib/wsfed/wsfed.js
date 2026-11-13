var templates             = require('./templates');
var PassportProfileMapper = require('./claims/PassportProfileMapper');
var utils                 = require('./utils');
var saml11                = require('../saml').Saml11;

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
 * Renders a SAML 1.1 signed assertion wrapped in a WS-Trust
 * RequestSecurityTokenResponse, posted via an HTML form.
 *
 * @param {object} options
 * @param {function} options.getPostURL REQUIRED. (wtrealm, wreply, req, callback) -> postUrl.
 * @param {function} [options.getUserFromRequest] defaults to req.user.
 * @param {PassportProfileMapper} [options.profileMapper]
 * @param {Buffer} options.cert issuer cert (PEM)
 * @param {Buffer} options.key issuer private key (PEM)
 * @param {string} options.issuer
 * @param {string} [options.audience]
 * @param {number} [options.lifetime] seconds; default 8h
 * @param {string} [options.signatureAlgorithm] rsa-sha256 (default rsa-sha256)
 * @param {string} [options.digestAlgorithm] sha256 (default sha256)
 * @param {boolean} [options.plain_form] if true, render the form fragment without auto-submit
 * @param {string} [options.wctx] override req.query.wctx
 *
 * @return {function} An Express middleware.
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
    var form = templates[(!options.plain_form ? 'form' : 'form_el')];
    res.send(form(model));
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
    var profileMap = options.profileMapper(user);
    var claims = profileMap.getClaims(options);
    var ni = profileMap.getNameIdentifier(options);
    if (!ni || !ni.nameIdentifier) {
      return next(new Error('No attribute was found to generate the nameIdentifier'));
    }

    saml11.create({
      signatureAlgorithm:   options.signatureAlgorithm,
      digestAlgorithm:      options.digestAlgorithm,
      cert:                 options.cert,
      key:                  options.key,
      issuer:               asResource(options.issuer),
      lifetimeInSeconds:    options.lifetime || options.lifetimeInSeconds || (60 * 60 * 8),
      audiences:            audience,
      attributes:           claims,
      nameIdentifier:       ni.nameIdentifier,
      nameIdentifierFormat: ni.nameIdentifierFormat || options.nameIdentifierFormat
    }, function(err, assertion) {
      if (err) return next(err);
      var escapedWctx = utils.escape(ctx);
      assertion = '<t:RequestSecurityTokenResponse Context="'+ escapedWctx + '" xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"><t:RequestedSecurityToken>' + assertion + '</t:RequestedSecurityToken></t:RequestSecurityTokenResponse>';
      return renderResponse(res, postUrl, ctx, assertion);
    });
  }

  return function (req, res, next) {
    options.getPostURL(req.query.wtrealm, req.query.wreply, req, function (err, postUrl) {
      if (err) return next(err);
      if (!postUrl) return res.send(400, 'postUrl is required');
      execute(postUrl, req, res, next);
    });
  };
};
