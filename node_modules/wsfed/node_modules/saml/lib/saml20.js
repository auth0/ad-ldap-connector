
var utils = require('./utils'),
    Parser = require('xmldom').DOMParser,
    SignedXml = require('xml-crypto').SignedXml,
    moment = require('moment');

var fs = require('fs');
var path = require('path');
var saml11 = fs.readFileSync(path.join(__dirname, 'saml20.template')).toString();

var NAMESPACE = 'urn:oasis:names:tc:SAML:2.0:assertion';

var algorithms = {
  signature: {
    'rsa-sha256': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    'rsa-sha1':  'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
  },
  digest: {
    'sha256': 'http://www.w3.org/2001/04/xmlenc#sha256',
    'sha1': 'http://www.w3.org/2000/09/xmldsig#sha1'
  }
};

exports.create = function(options) {
  if (!options.key)
    throw new Error('Expect a private key in pem format');

  if (!options.cert)
    throw new Error('Expect a public key cert in pem format');

  options.signatureAlgorithm = options.signatureAlgorithm || 'rsa-sha256';
  options.digestAlgorithm = options.digestAlgorithm || 'sha256';

  var cert = utils.pemToCert(options.cert);

  var sig = new SignedXml(null, { signatureAlgorithm: algorithms.signature[options.signatureAlgorithm], idAttribute: 'ID' });
  sig.addReference("//*[local-name(.)='Assertion']",
                  ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],
                  algorithms.digest[options.digestAlgorithm]);

  sig.signingKey = options.key;
  
  sig.keyInfoProvider = {
    getKeyInfo: function () {
      return "<X509Data><X509Certificate>" + cert + "</X509Certificate></X509Data>";
    }
  };

  var doc = new Parser().parseFromString(saml11.toString());
  doc.documentElement.setAttribute('ID', '_' + utils.uid(32));
  if (options.issuer) {
    var issuer = doc.documentElement.getElementsByTagName('saml:Issuer');
    issuer[0].textContent = options.issuer;
  }

  var now = moment.utc();
  doc.documentElement.setAttribute('IssueInstant', now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
  var conditions = doc.documentElement.getElementsByTagName('saml:Conditions');
  var confirmationData = doc.documentElement.getElementsByTagName('saml:SubjectConfirmationData');

  if (options.lifetimeInSeconds) {
    conditions[0].setAttribute('NotBefore', now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
    conditions[0].setAttribute('NotOnOrAfter', now.clone().add('seconds', options.lifetimeInSeconds).format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
  
    confirmationData[0].setAttribute('NotOnOrAfter', now.clone().add('seconds', options.lifetimeInSeconds).format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));  
  }
  
  if (options.audiences) {
    var audiences = options.audiences instanceof Array ? options.audiences : [options.audiences];
    audiences.forEach(function (audience) {
      var element = doc.createElementNS(NAMESPACE, 'saml:Audience');
      element.textContent = audience;
      var audienceCondition = conditions[0].getElementsByTagNameNS(NAMESPACE, 'AudienceRestriction')[0];
      audienceCondition.appendChild(element); 
    });
  }

  if (options.recipient)
    confirmationData[0].setAttribute('Recipient', options.recipient);

  if (options.inResponseTo)
    confirmationData[0].setAttribute('InResponseTo', options.inResponseTo);

  if (options.attributes) {
    var statement = doc.documentElement.getElementsByTagNameNS(NAMESPACE, 'AttributeStatement')[0];
    Object.keys(options.attributes).forEach(function(prop) {
      if(typeof options.attributes[prop] === 'undefined') return;
      // <saml:Attribute AttributeName="name" AttributeNamespace="http://schemas.xmlsoap.org/claims/identity">
      //    <saml:AttributeValue>Foo Bar</saml:AttributeValue>
      // </saml:Attribute>
      var attributeElement = doc.createElementNS(NAMESPACE, 'saml:Attribute');
      attributeElement.setAttribute('Name', prop);
      var values = options.attributes[prop] instanceof Array ? options.attributes[prop] : [options.attributes[prop]];
      values.forEach(function (value) {
        var valueElement = doc.createElementNS(NAMESPACE, 'saml:AttributeValue');
        valueElement.setAttribute('xsi:type', 'xs:anyType');
        valueElement.textContent = value;
        attributeElement.appendChild(valueElement);
      });

      statement.appendChild(attributeElement);
    });
  }

  doc.getElementsByTagName('saml:AuthnStatement')[0]
    .setAttribute('AuthnInstant', now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));

  var nameID = doc.documentElement.getElementsByTagNameNS(NAMESPACE, 'NameID')[0];
  
  if (options.nameIdentifier) {
    nameID.textContent = options.nameIdentifier;
  }

  if (options.nameIdentifierFormat) {
    nameID.setAttribute('Format', options.nameIdentifierFormat);
  }
  
  var token = doc.toString()
                .replace(/\r\n/g, '')
                .replace(/\n/g,'')
                .replace(/>(\s*)</g, '><') //unindent
                .trim();
  sig.computeSignature(token, options.xpathToNodeBeforeSignature || "//*[local-name(.)='Issuer']");
  var signed = sig.getSignedXml();

  return signed;
}; 

