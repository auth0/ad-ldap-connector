var path = require('path');
var utils = require('./utils');
var moment = require('moment');

var SignXml = require('./sign');

var newSaml11Document = utils.factoryForNode(path.join(__dirname, 'saml11.template'));

var NAMESPACE = 'urn:oasis:names:tc:SAML:1.0:assertion';

function extractSaml11Options(opts) {
  return {
    uid: opts.uid,
    issuer: opts.issuer,
    lifetimeInSeconds: opts.lifetimeInSeconds,
    audiences: opts.audiences,
    attributes: opts.attributes,
    nameIdentifier: opts.nameIdentifier,
    nameIdentifierFormat: opts.nameIdentifierFormat
  };
}

/**
 * Creates a signed SAML 1.1 assertion from the given options.
 *
 * @param options
 *
 * // SAML
 * @param [options.uid] {string}
 * @param [options.issuer] {string}
 * @param [options.lifetimeInSeconds] {number}
 * @param [options.audiences] {string|string[]}
 * @param [options.attributes]
 * @param [options.nameIdentifier] {string}
 * @param [options.nameIdentifierFormat] {string}
 *
 * // XML Dsig
 * @param options.key {Buffer}
 * @param options.cert {Buffer}
 * @param [options.signatureAlgorithm] {string}
 * @param [options.digestAlgorithm] {string}
 * @param [options.signatureNamespacePrefix] {string}
 * @param [options.xpathToNodeBeforeSignature] {string}
 *
 * @param {Function} [callback]
 * @return {String|*}
 */
exports.create = function(options, callback) {
  return createAssertion(extractSaml11Options(options), {
    signXml: SignXml.fromSignXmlOptions(Object.assign({
      xpathToNodeBeforeSignature: "//*[local-name(.)='AuthenticationStatement']",
      signatureIdAttribute: 'AssertionID'
    }, options))
  }, callback);
};


function createAssertion(options, strategies, callback) {
  var doc;
  try {
    doc = newSaml11Document();
  } catch(err){
    return utils.reportError(err, callback);
  }

  doc.documentElement.setAttribute('AssertionID', '_' + (options.uid || utils.uid(32)));
  if (options.issuer)
    doc.documentElement.setAttribute('Issuer', options.issuer);

  var now = moment.utc();
  doc.documentElement.setAttribute('IssueInstant', now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
  var conditions = doc.documentElement.getElementsByTagName('saml:Conditions');

  if (options.lifetimeInSeconds) {
    conditions[0].setAttribute('NotBefore', now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
    conditions[0].setAttribute('NotOnOrAfter', moment(now).add(options.lifetimeInSeconds, 'seconds').format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
  }

  if (options.audiences) {
    var audiences = options.audiences instanceof Array ? options.audiences : [options.audiences];
    audiences.forEach(function (audience) {
      var element = doc.createElementNS(NAMESPACE, 'saml:Audience');
      element.textContent = audience;
      var audienceCondition = conditions[0].getElementsByTagNameNS(NAMESPACE, 'AudienceRestrictionCondition')[0];
      audienceCondition.appendChild(element);
    });
  }

  if (options.attributes) {
    var statement = doc.documentElement.getElementsByTagNameNS(NAMESPACE, 'AttributeStatement')[0];
    Object.keys(options.attributes).forEach(function(prop) {
      if(typeof options.attributes[prop] === 'undefined') return;

      // <saml:Attribute AttributeName="name" AttributeNamespace="http://schemas.xmlsoap.org/claims/identity">
      //    <saml:AttributeValue>Foo Bar</saml:AttributeValue>
      // </saml:Attribute>
      var name = prop.indexOf('/') > -1 ? prop.substring(prop.lastIndexOf('/') + 1) : prop;
      var namespace = prop.indexOf('/') > -1 ? prop.substring(0, prop.lastIndexOf('/')) : '';
      var attributeElement = doc.createElementNS(NAMESPACE, 'saml:Attribute');
      attributeElement.setAttribute('AttributeNamespace', namespace);
      attributeElement.setAttribute('AttributeName', name);
      var values = options.attributes[prop] instanceof Array ? options.attributes[prop] : [options.attributes[prop]];
      values.forEach(function (value) {
        var valueElement = doc.createElementNS(NAMESPACE, 'saml:AttributeValue');
        valueElement.textContent = value;
        attributeElement.appendChild(valueElement);
      });

      if (values && values.length > 0) {
        // saml:Attribute must have at least one saml:AttributeValue
        statement.appendChild(attributeElement);
      }
    });
  }

  doc.getElementsByTagName('saml:AuthenticationStatement')[0]
    .setAttribute('AuthenticationInstant', now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));

  var nameID = doc.documentElement.getElementsByTagNameNS(NAMESPACE, 'NameIdentifier')[0];

  if (options.nameIdentifier) {
    nameID.textContent = options.nameIdentifier;

    doc.getElementsByTagName('saml:AuthenticationStatement')[0]
      .getElementsByTagName('saml:NameIdentifier')[0]
      .textContent = options.nameIdentifier;
  }

  if (options.nameIdentifierFormat) {
    var nameIDs = doc.documentElement.getElementsByTagNameNS(NAMESPACE, 'NameIdentifier');
    nameIDs[0].setAttribute('Format', options.nameIdentifierFormat);
    nameIDs[1].setAttribute('Format', options.nameIdentifierFormat);
  }

  return strategies.signXml(doc, callback);
}
