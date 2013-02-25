var xmlCrypto = require('xml-crypto'),
    xmldom = require('xmldom');
    
exports.isValidSignature = function(assertion, cert) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  var signature = xmlCrypto.xpath.SelectNodes(doc, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
  var sig = new xmlCrypto.SignedXml(null, { idAttribute: 'AssertionID' });
  sig.keyInfoProvider = {
    getKeyInfo: function (key) {
      return "<X509Data></X509Data>";
    },
    getKey: function (keyInfo) {
      return cert;
    }
  };
  sig.loadSignature(signature.toString());
  return sig.checkSignature(assertion);
};

exports.getIssuer = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  return doc.documentElement.getAttribute('Issuer');
};

exports.getIssueInstant = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  return doc.documentElement.getAttribute('IssueInstant');
};

exports.getConditions = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  return doc.documentElement.getElementsByTagName('saml:Conditions');
};

exports.getAudiences = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  return doc.documentElement
            .getElementsByTagName('saml:Conditions')[0]
            .getElementsByTagName('saml:AudienceRestrictionCondition')[0]
            .getElementsByTagName('saml:Audience');
};

exports.getAttributes = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  return doc.documentElement
            .getElementsByTagName('saml:Attribute');
};

exports.getNameIdentifier = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  return doc.documentElement
            .getElementsByTagName('saml:NameIdentifier')[0];
};