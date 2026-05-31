var path = require('path');
var async = require('async');
var moment = require('moment');
var xmlNameValidator = require('xml-name-validator');
var is_uri = require('valid-url').is_uri;

var EncryptXml = require('./xml/encrypt');
var SignXml = require('./xml/sign');
var utils = require('./utils');

var newSaml20Document = utils.factoryForNode(path.join(__dirname, 'saml20.template'));

var NAMESPACE = 'urn:oasis:names:tc:SAML:2.0:assertion';

function getAttributeType(value){
  switch(typeof value) {
    case "string":
      return 'xs:string';
    case "boolean":
      return 'xs:boolean';
    case "number":
      // Maybe we should fine-grain this type and check whether it is an integer, float, double xsi:types
      return 'xs:double';
    default:
      return 'xs:anyType';
  }
}

function getNameFormat(name){
  if (is_uri(name)){
    return 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri';
  }

  //  Check that the name is a valid xs:Name -> https://www.w3.org/TR/xmlschema-2/#Name
  //  xmlNameValidate.name takes a string and will return an object of the form { success, error }, 
  //  where success is a boolean 
  //  if it is false, then error is a string containing some hint as to where the match went wrong.
  if (xmlNameValidator.name(name).success){
    return 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic';
  }

  // Default value
  return 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified';
}

function extractSaml20Options(opts) {
  return {
    uid: opts.uid,
    issuer: opts.issuer,
    lifetimeInSeconds: opts.lifetimeInSeconds,
    audiences: opts.audiences,
    recipient: opts.recipient,
    inResponseTo: opts.inResponseTo,
    attributes: opts.attributes,
    includeAttributeNameFormat: (typeof opts.includeAttributeNameFormat !== 'undefined') ? opts.includeAttributeNameFormat : true,
    typedAttributes: (typeof opts.typedAttributes !== 'undefined') ? opts.typedAttributes : true,
    sessionIndex: opts.sessionIndex,
    nameIdentifier: opts.nameIdentifier,
    nameIdentifierFormat: opts.nameIdentifierFormat,
    authnContextClassRef: opts.authnContextClassRef
  };
}

/**
 * Creates a signed SAML 2.0 assertion from the given options.
 *
 * @param options
 *
 * // SAML
 * @param [options.uid] {string}
 * @param [options.issuer] {string}
 * @param [options.lifetimeInSeconds] {number}
 * @param [options.audiences] {string|string[]}
 * @param [options.recipient] {string}
 * @param [options.inResponseTo] {string}
 * @param [options.attributes]
 * @param [options.includeAttributeNameFormat] {boolean}
 * @param [options.typedAttributes] {boolean}
 * @param [options.sessionIndex] {string}
 * @param [options.nameIdentifier] {string}
 * @param [options.nameIdentifierFormat] {string}
 * @param [options.authnContextClassRef] {string}
 *
 * // XML Dsig
 * @param options.key {Buffer}
 * @param options.cert {Buffer}
 * @param [options.signatureAlgorithm] {string}
 * @param [options.digestAlgorithm] {string}
 * @param [options.signatureNamespacePrefix] {string}
 * @param [options.xpathToNodeBeforeSignature] {string}
 * @param [options.signatureIdAttribute] {String}
 *
 * // XML encryption
 * @param [options.encryptionCert] {Buffer}
 * @param [options.encryptionPublicKey] {Buffer}
 * @param [options.encryptionAlgorithm] {string}
 * @param [options.keyEncryptionAlgorithm] {string}
 * @param [options.disallowEncryptionWithInsecureAlgorithm] {boolean}
 * @param [options.warnOnInsecureEncryptionAlgorithm] {boolean}
 *
 * @param {Function} [callback] required if encrypting
 * @return {*}
 */
exports.create = function createSignedAssertion(options, callback) {
  return createAssertion(extractSaml20Options(options), {
    signXml: SignXml.fromSignXmlOptions(Object.assign({
      xpathToNodeBeforeSignature: "//*[local-name(.)='Issuer']",
      signatureIdAttribute: 'ID'
    }, options)),
    encryptXml: EncryptXml.fromEncryptXmlOptions(options)
  }, callback);
};

/**
 * Creates an **unsigned** SAML 2.0 assertion from the given options.
 *
 * @param options
 *
 * // SAML
 * @param [options.uid] {string}
 * @param [options.issuer] {string}
 * @param [options.lifetimeInSeconds] {number}
 * @param [options.audiences] {string|string[]}
 * @param [options.recipient] {string}
 * @param [options.inResponseTo] {string}
 * @param [options.attributes]
 * @param [options.includeAttributeNameFormat] {boolean}
 * @param [options.typedAttributes] {boolean}
 * @param [options.sessionIndex] {string}
 * @param [options.nameIdentifier] {string}
 * @param [options.nameIdentifierFormat] {string}
 * @param [options.authnContextClassRef] {string}
 *
 * // XML encryption
 * @param [options.encryptionCert] {Buffer}
 * @param [options.encryptionPublicKey] {Buffer}
 * @param [options.encryptionAlgorithm] {string}
 * @param [options.keyEncryptionAlgorithm] {string}
 * @param [options.disallowEncryptionWithInsecureAlgorithm] {boolean}
 * @param [options.warnOnInsecureEncryptionAlgorithm] {boolean}
 *
 * @param {Function} [callback] required if encrypting
 * @return {*}
 */
exports.createUnsignedAssertion = function createUnsignedAssertion(options, callback) {
  return createAssertion(extractSaml20Options(options), {
    signXml: SignXml.unsigned,
    encryptXml: EncryptXml.fromEncryptXmlOptions(options)
  }, callback);
};

/**
 * @param options SAML options
 * @param strategies
 * @param strategies.signXml {Function} strategy to sign the assertion
 * @param strategies.encryptXml {Function} strategy to encrypt the assertion
 * @param callback
 * @return {*}
 */
function createAssertion(options, strategies, callback) {
  var doc = newSaml20Document();

  doc.documentElement.setAttribute('ID', '_' + (options.uid || utils.uid(32)));
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
    conditions[0].setAttribute('NotOnOrAfter', now.clone().add(options.lifetimeInSeconds, 'seconds').format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
  
    confirmationData[0].setAttribute('NotOnOrAfter', now.clone().add(options.lifetimeInSeconds, 'seconds').format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
  }
  
  if (options.audiences) {
    var audienceRestriction = doc.createElementNS(NAMESPACE, 'saml:AudienceRestriction');
    var audiences = options.audiences instanceof Array ? options.audiences : [options.audiences];
    audiences.forEach(function (audience) {
      var element = doc.createElementNS(NAMESPACE, 'saml:Audience');
      element.textContent = audience;
      audienceRestriction.appendChild(element);
    });

    conditions[0].appendChild(audienceRestriction); 
  }

  if (options.recipient)
    confirmationData[0].setAttribute('Recipient', options.recipient);

  if (options.inResponseTo)
    confirmationData[0].setAttribute('InResponseTo', options.inResponseTo);

  if (options.attributes) {
    var statement = doc.createElementNS(NAMESPACE, 'saml:AttributeStatement');
    statement.setAttribute('xmlns:xs', 'http://www.w3.org/2001/XMLSchema');
    statement.setAttribute('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance');
    doc.documentElement.appendChild(statement);
    Object.keys(options.attributes).forEach(function(prop) {
      if(typeof options.attributes[prop] === 'undefined') return;
      // <saml:Attribute AttributeName="name" AttributeNamespace="http://schemas.xmlsoap.org/claims/identity">
      //    <saml:AttributeValue>Foo Bar</saml:AttributeValue>
      // </saml:Attribute>
      var attributeElement = doc.createElementNS(NAMESPACE, 'saml:Attribute');
      attributeElement.setAttribute('Name', prop);

      if (options.includeAttributeNameFormat){
        attributeElement.setAttribute('NameFormat', getNameFormat(prop));        
      }

      var values = options.attributes[prop] instanceof Array ? options.attributes[prop] : [options.attributes[prop]];
      values.forEach(function (value) {
        // Check by type, becase we want to include false values
        if (typeof value !== 'undefined') {
          // Ignore undefined values in Array
          var valueElement = doc.createElementNS(NAMESPACE, 'saml:AttributeValue');
          valueElement.setAttribute('xsi:type', options.typedAttributes ? getAttributeType(value) : 'xs:anyType');
          valueElement.textContent = value;
          attributeElement.appendChild(valueElement);
        }
      });

      if (values && values.filter(function(i){ return typeof i !== 'undefined'; }).length > 0) {
        // saml:Attribute must have at least one saml:AttributeValue
        statement.appendChild(attributeElement);
      }
    });
  }

  doc.getElementsByTagName('saml:AuthnStatement')[0]
    .setAttribute('AuthnInstant', now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));

  if (options.sessionIndex) {
    doc.getElementsByTagName('saml:AuthnStatement')[0]
      .setAttribute('SessionIndex', options.sessionIndex);
  }

  var nameID = doc.documentElement.getElementsByTagNameNS(NAMESPACE, 'NameID')[0];
  
  if (options.nameIdentifier) {
    nameID.textContent = options.nameIdentifier;
  }

  if (options.nameIdentifierFormat) {
    nameID.setAttribute('Format', options.nameIdentifierFormat);
  }
  
  if( options.authnContextClassRef ) {
    var authnCtxClassRef = doc.getElementsByTagName('saml:AuthnContextClassRef')[0];
    authnCtxClassRef.textContent = options.authnContextClassRef;
  }

  var signed;
  try {
    signed = strategies.signXml(doc);
  } catch(err){
    return utils.reportError(err, callback);
  }

  if (strategies.encryptXml === EncryptXml.unencrypted) {
    return strategies.encryptXml(signed, callback);
  }

  async.waterfall([
    function (cb) {
      strategies.encryptXml(signed, cb)
    },
    function (encrypted, cb) {
      var assertion = '<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">' + encrypted + '</saml:EncryptedAssertion>';
      cb(null, utils.removeWhitespace(assertion));
    },
  ], callback);
}
