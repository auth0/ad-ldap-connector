var saml11 = require('saml').Saml11;

exports.generate = function(audience, issuer, cert, key, claims, wctx){
   var options = {
      cert:      cert,
      key:       key,
      issuer:    'urn:' + issuer,
      lifetimeInSeconds: 3600,
      audiences: 'urn:' + audience,
      attributes: claims,
      nameIdentifier: claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'] ||
                      claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'] ||
                      claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']
    };
    
    var signedAssertion = saml11.create(options);
    return '<t:RequestSecurityTokenResponse Context="' + wctx + '" xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"><t:RequestedSecurityToken>' +
            signedAssertion +
           '</t:RequestedSecurityToken></t:RequestSecurityTokenResponse>';
};