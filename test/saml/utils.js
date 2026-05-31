var xmlCrypto = require('xml-crypto');
var xmldom = require('@xmldom/xmldom');

/**
 * @param {string} assertion
 * @param {Buffer} cert
 * @return {boolean}
 */
exports.isValidSignature = function(assertion, cert) {
  var signature = exports.getXmlSignatures(assertion)[0];
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

/**
 * @param {string} assertion
 * @return {Element[]}
 */
exports.getXmlSignatures = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  var signatures = xmlCrypto.xpath(doc, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']");

  return signatures;
}

exports.getIssuer = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  return doc.documentElement.getAttribute('Issuer');
};

exports.getAssertionID = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  return doc.documentElement.getAttribute('AssertionID');
};

exports.getIssueInstant = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  return doc.documentElement.getAttribute('IssueInstant');
};

exports.getAuthenticationInstant = function (assertion) {
  return exports.getAuthenticationStatement(assertion).getAttribute('AuthenticationInstant');
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

exports.getAuthenticationStatement = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  return doc.documentElement
            .getElementsByTagName('saml:AuthenticationStatement')[0];
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


//SAML2.0

exports.getNameID = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  return doc.documentElement
            .getElementsByTagName('saml:NameID')[0];
};

exports.getSaml2Issuer = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  return doc.documentElement
            .getElementsByTagName('saml:Issuer')[0];
};

exports.getAuthnContextClassRef = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  return doc.documentElement
            .getElementsByTagName('saml:AuthnContextClassRef')[0];
};

exports.getSubjectConfirmation = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion);
  return doc.documentElement
            .getElementsByTagName('saml:getSubjectConfirmation');
};

exports.getEncryptedData = function(encryptedAssertion) {
  var doc = new xmldom.DOMParser().parseFromString(encryptedAssertion);
  return doc.documentElement
            .getElementsByTagName('xenc:EncryptedData')[0];
};
