var assert = require('chai').assert;
var fs = require('fs');
var utils = require('./utils');
var moment = require('moment');
var should = require('should');
var xmldom = require('@xmldom/xmldom');
var xmlenc = require('xml-encryption');
var sinon = require('sinon');

var saml = require('../lib/saml20');

describe('saml 2.0', function () {
  saml20TestSuite({
    createAssertion: 'create',
    assertSignature: Object.assign(function (assertion, options) {
        assert.isTrue(utils.isValidSignature(assertion, options.cert));
    }, {
      it: it
    })
  });

  saml20TestSuite({
    createAssertion: 'createUnsignedAssertion',
    assertSignature: Object.assign(function (assertion) {
        assert.isEmpty(utils.getXmlSignatures(assertion));
    }, {
      it: it.skip
    })
  });

  function saml20TestSuite(options) {
    var createAssertion = options.createAssertion;
    var assertSignature = options.assertSignature;

    describe('#' + createAssertion, function () {
      it('whole thing with default authnContextClassRef', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key'),
          issuer: 'urn:issuer',
          lifetimeInSeconds: 600,
          audiences: 'urn:myapp',
          attributes: {
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'foo@bar.com',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'Foo Bar'
          },
          nameIdentifier: 'foo',
          nameIdentifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'
        };

        var signedAssertion = saml[createAssertion](options);
        assertSignature(signedAssertion, options);

        var nameIdentifier = utils.getNameID(signedAssertion);
        assert.equal('foo', nameIdentifier.textContent);
        assert.equal('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified', nameIdentifier.getAttribute('Format'));

        var attributes = utils.getAttributes(signedAssertion);
        assert.equal(2, attributes.length);
        assert.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress', attributes[0].getAttribute('Name'));
        assert.equal('foo@bar.com', attributes[0].textContent);
        assert.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name', attributes[1].getAttribute('Name'));
        assert.equal('Foo Bar', attributes[1].textContent);

        assert.equal('urn:issuer', utils.getSaml2Issuer(signedAssertion).textContent);

        var conditions = utils.getConditions(signedAssertion);
        assert.equal(1, conditions.length);
        var notBefore = conditions[0].getAttribute('NotBefore');
        var notOnOrAfter = conditions[0].getAttribute('NotOnOrAfter');
        should.ok(notBefore);
        should.ok(notOnOrAfter);

        var lifetime = Math.round((moment(notOnOrAfter).utc() - moment(notBefore).utc()) / 1000);
        assert.equal(600, lifetime);

        var authnContextClassRef = utils.getAuthnContextClassRef(signedAssertion);
        assert.equal('urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified', authnContextClassRef.textContent);
      });

      it('should not error when cert is missing newlines', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key'),
          issuer: 'urn:issuer',
          lifetimeInSeconds: 600,
          audiences: 'urn:myapp',
          attributes: {
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'foo@bar.com',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'Foo Bar'
          },
          nameIdentifier: 'foo',
          nameIdentifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'
        };

        var signedAssertion = saml[createAssertion]({...options, cert: Buffer.from(options.cert.toString().replaceAll(/[\r\n]/g, ''))});
        assertSignature(signedAssertion, options);

        var nameIdentifier = utils.getNameID(signedAssertion);
        assert.equal('foo', nameIdentifier.textContent);
        assert.equal('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified', nameIdentifier.getAttribute('Format'));

        var attributes = utils.getAttributes(signedAssertion);
        assert.equal(2, attributes.length);
        assert.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress', attributes[0].getAttribute('Name'));
        assert.equal('foo@bar.com', attributes[0].textContent);
        assert.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name', attributes[1].getAttribute('Name'));
        assert.equal('Foo Bar', attributes[1].textContent);

        assert.equal('urn:issuer', utils.getSaml2Issuer(signedAssertion).textContent);

        var conditions = utils.getConditions(signedAssertion);
        assert.equal(1, conditions.length);
        var notBefore = conditions[0].getAttribute('NotBefore');
        var notOnOrAfter = conditions[0].getAttribute('NotOnOrAfter');
        should.ok(notBefore);
        should.ok(notOnOrAfter);

        var lifetime = Math.round((moment(notOnOrAfter).utc() - moment(notBefore).utc()) / 1000);
        assert.equal(600, lifetime);

        var authnContextClassRef = utils.getAuthnContextClassRef(signedAssertion);
        assert.equal('urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified', authnContextClassRef.textContent);
      });

      it('should not error when key is missing newlines', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key'),
          issuer: 'urn:issuer',
          lifetimeInSeconds: 600,
          audiences: 'urn:myapp',
          attributes: {
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'foo@bar.com',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'Foo Bar'
          },
          nameIdentifier: 'foo',
          nameIdentifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'
        };

        var signedAssertion = saml[createAssertion]({...options, key: Buffer.from(options.key.toString().replaceAll(/[\r\n]/g, ''))});
        assertSignature(signedAssertion, options);

        var nameIdentifier = utils.getNameID(signedAssertion);
        assert.equal('foo', nameIdentifier.textContent);
        assert.equal('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified', nameIdentifier.getAttribute('Format'));

        var attributes = utils.getAttributes(signedAssertion);
        assert.equal(2, attributes.length);
        assert.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress', attributes[0].getAttribute('Name'));
        assert.equal('foo@bar.com', attributes[0].textContent);
        assert.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name', attributes[1].getAttribute('Name'));
        assert.equal('Foo Bar', attributes[1].textContent);

        assert.equal('urn:issuer', utils.getSaml2Issuer(signedAssertion).textContent);

        var conditions = utils.getConditions(signedAssertion);
        assert.equal(1, conditions.length);
        var notBefore = conditions[0].getAttribute('NotBefore');
        var notOnOrAfter = conditions[0].getAttribute('NotOnOrAfter');
        should.ok(notBefore);
        should.ok(notOnOrAfter);

        var lifetime = Math.round((moment(notOnOrAfter).utc() - moment(notBefore).utc()) / 1000);
        assert.equal(600, lifetime);

        var authnContextClassRef = utils.getAuthnContextClassRef(signedAssertion);
        assert.equal('urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified', authnContextClassRef.textContent);
      });

      it('should set attributes', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key'),
          attributes: {
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'foo@bar.com',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'Foo Bar',
            'http://example.org/claims/testemptyarray': [], // should dont include empty arrays
            'http://example.org/claims/testaccent': 'fóo', // should supports accents
            'http://undefinedattribute/ws/com.com': undefined
          }
        };

        var signedAssertion = saml[createAssertion](options);
        assertSignature(signedAssertion, options);

        var attributes = utils.getAttributes(signedAssertion);
        assert.equal(3, attributes.length);
        assert.equal('saml:AttributeStatement', attributes[0].parentNode.nodeName);
        assert.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress', attributes[0].getAttribute('Name'));
        assert.equal('foo@bar.com', attributes[0].textContent);
        assert.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name', attributes[1].getAttribute('Name'));
        assert.equal('Foo Bar', attributes[1].textContent);
        assert.equal('http://example.org/claims/testaccent', attributes[2].getAttribute('Name'));
        assert.equal('fóo', attributes[2].textContent);
      });

      it('should set attributes with the correct attribute type', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key'),
          attributes: {
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'foo@bar.com',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'Foo Bar',
            'http://example.org/claims/testemptyarray': [], // should dont include empty arrays
            'http://example.org/claims/testaccent': 'fóo', // should supports accents
            'http://attributes/boolean': true,
            'http://attributes/booleanNegative': false,
            'http://attributes/number': 123,
            'http://undefinedattribute/ws/com.com': undefined
          }
        };

        var signedAssertion = saml[createAssertion](options);

        assertSignature(signedAssertion, options);

        var attributes = utils.getAttributes(signedAssertion);
        assert.equal(6, attributes.length);
        assert.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress', attributes[0].getAttribute('Name'));
        assert.equal('foo@bar.com', attributes[0].textContent);
        assert.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name', attributes[1].getAttribute('Name'));
        assert.equal('Foo Bar', attributes[1].textContent);
        assert.equal('http://example.org/claims/testaccent', attributes[2].getAttribute('Name'));
        assert.equal('xs:string', attributes[2].firstChild.getAttribute('xsi:type'));
        assert.equal('fóo', attributes[2].textContent);
        assert.equal('http://attributes/boolean', attributes[3].getAttribute('Name'));
        assert.equal('xs:boolean', attributes[3].firstChild.getAttribute('xsi:type'));
        assert.equal('true', attributes[3].textContent);
        assert.equal('http://attributes/booleanNegative', attributes[4].getAttribute('Name'));
        assert.equal('xs:boolean', attributes[4].firstChild.getAttribute('xsi:type'));
        assert.equal('false', attributes[4].textContent);
        assert.equal('http://attributes/number', attributes[5].getAttribute('Name'));
        assert.equal('xs:double', attributes[5].firstChild.getAttribute('xsi:type'));
        assert.equal('123', attributes[5].textContent);
      });

      it('should set attributes with the correct attribute type and NameFormat', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key'),
          attributes: {
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'foo@bar.com',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'Foo Bar',
            'http://example.org/claims/testemptyarray': [], // should dont include empty arrays
            'testaccent': 'fóo', // should supports accents
            'urn:test:1:2:3': true,
            '123~oo': 123,
            'http://undefinedattribute/ws/com.com': undefined
          }
        };

        var signedAssertion = saml[createAssertion](options);

        assertSignature(signedAssertion, options);

        var attributes = utils.getAttributes(signedAssertion);
        assert.equal(5, attributes.length);
        assert.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress', attributes[0].getAttribute('Name'));
        assert.equal('urn:oasis:names:tc:SAML:2.0:attrname-format:uri', attributes[0].getAttribute('NameFormat'));
        assert.equal('foo@bar.com', attributes[0].textContent);
        assert.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name', attributes[1].getAttribute('Name'));
        assert.equal('urn:oasis:names:tc:SAML:2.0:attrname-format:uri', attributes[1].getAttribute('NameFormat'));
        assert.equal('Foo Bar', attributes[1].textContent);
        assert.equal('testaccent', attributes[2].getAttribute('Name'));
        assert.equal('urn:oasis:names:tc:SAML:2.0:attrname-format:basic', attributes[2].getAttribute('NameFormat'));
        assert.equal('xs:string', attributes[2].firstChild.getAttribute('xsi:type'));
        assert.equal('fóo', attributes[2].textContent);
        assert.equal('urn:test:1:2:3', attributes[3].getAttribute('Name'));
        assert.equal('urn:oasis:names:tc:SAML:2.0:attrname-format:uri', attributes[3].getAttribute('NameFormat'));
        assert.equal('xs:boolean', attributes[3].firstChild.getAttribute('xsi:type'));
        assert.equal('true', attributes[3].textContent);
        assert.equal('123~oo', attributes[4].getAttribute('Name'));
        assert.equal('urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified', attributes[4].getAttribute('NameFormat'));
        assert.equal('xs:double', attributes[4].firstChild.getAttribute('xsi:type'));
        assert.equal('123', attributes[4].textContent);
      });

      it('should set attributes to anytpe when typedAttributes is false', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key'),
          typedAttributes: false,
          attributes: {
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'foo@bar.com',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'Foo Bar',
            'http://example.org/claims/testemptyarray': [], // should dont include empty arrays
            'http://example.org/claims/testaccent': 'fóo', // should supports accents
            'http://attributes/boolean': true,
            'http://attributes/number': 123,
            'http://undefinedattribute/ws/com.com': undefined
          }
        };

        var signedAssertion = saml[createAssertion](options);

        assertSignature(signedAssertion, options);

        var attributes = utils.getAttributes(signedAssertion);
        assert.equal(5, attributes.length);
        assert.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress', attributes[0].getAttribute('Name'));
        assert.equal('foo@bar.com', attributes[0].textContent);
        assert.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name', attributes[1].getAttribute('Name'));
        assert.equal('Foo Bar', attributes[1].textContent);
        assert.equal('http://example.org/claims/testaccent', attributes[2].getAttribute('Name'));
        assert.equal('xs:anyType', attributes[2].firstChild.getAttribute('xsi:type'));
        assert.equal('fóo', attributes[2].textContent);
        assert.equal('http://attributes/boolean', attributes[3].getAttribute('Name'));
        assert.equal('xs:anyType', attributes[3].firstChild.getAttribute('xsi:type'));
        assert.equal('true', attributes[3].textContent);
        assert.equal('http://attributes/number', attributes[4].getAttribute('Name'));
        assert.equal('xs:anyType', attributes[4].firstChild.getAttribute('xsi:type'));
        assert.equal('123', attributes[4].textContent);
      });

      it('should not set NameFormat in attributes when includeAttributeNameFormat is false', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key'),
          typedAttributes: false,
          includeAttributeNameFormat: false,
          attributes: {
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'foo@bar.com',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'Foo Bar',
            'http://example.org/claims/testemptyarray': [], // should dont include empty arrays
            'testaccent': 'fóo', // should supports accents
            'urn:test:1:2:3': true,
            '123~oo': 123,
            'http://undefinedattribute/ws/com.com': undefined
          }
        };

        var signedAssertion = saml[createAssertion](options);

        assertSignature(signedAssertion, options);

        var attributes = utils.getAttributes(signedAssertion);
        assert.equal(5, attributes.length);
        assert.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress', attributes[0].getAttribute('Name'));
        assert.equal('', attributes[0].getAttribute('NameFormat'));
        assert.equal('foo@bar.com', attributes[0].textContent);
        assert.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name', attributes[1].getAttribute('Name'));
        assert.equal('', attributes[1].getAttribute('NameFormat'));
        assert.equal('Foo Bar', attributes[1].textContent);
        assert.equal('testaccent', attributes[2].getAttribute('Name'));
        assert.equal('', attributes[2].getAttribute('NameFormat'));
        assert.equal('fóo', attributes[2].textContent);
        assert.equal('urn:test:1:2:3', attributes[3].getAttribute('Name'));
        assert.equal('', attributes[3].getAttribute('NameFormat'));
        assert.equal('true', attributes[3].textContent);
        assert.equal('123~oo', attributes[4].getAttribute('Name'));
        assert.equal('', attributes[4].getAttribute('NameFormat'));
        assert.equal('123', attributes[4].textContent);
      });

      it('should ignore undefined attributes in array', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key'),
          attributes: {
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'foo@bar.com',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'Foo Bar',
            'http://example.org/claims/testemptyarray': [], // should dont include empty arrays
            'arrayAttribute': [ 'foo', undefined, 'bar'],
            'urn:test:1:2:3': true,
            '123~oo': 123,
            'http://undefinedattribute/ws/com.com': undefined
          }
        };

        var signedAssertion = saml[createAssertion](options);

        assertSignature(signedAssertion, options);

        var attributes = utils.getAttributes(signedAssertion);
        assert.equal(5, attributes.length);
        assert.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress', attributes[0].getAttribute('Name'));
        assert.equal('urn:oasis:names:tc:SAML:2.0:attrname-format:uri', attributes[0].getAttribute('NameFormat'));
        assert.equal('foo@bar.com', attributes[0].textContent);
        assert.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name', attributes[1].getAttribute('Name'));
        assert.equal('urn:oasis:names:tc:SAML:2.0:attrname-format:uri', attributes[1].getAttribute('NameFormat'));
        assert.equal('Foo Bar', attributes[1].textContent);
        assert.equal('arrayAttribute', attributes[2].getAttribute('Name'));
        assert.equal('urn:oasis:names:tc:SAML:2.0:attrname-format:basic', attributes[2].getAttribute('NameFormat'));
        assert.equal('xs:string', attributes[2].firstChild.getAttribute('xsi:type'));
        assert.equal(2, attributes[2].childNodes.length);
        assert.equal('foo', attributes[2].childNodes[0].textContent);
        // undefined should not be here
        assert.equal('bar', attributes[2].childNodes[1].textContent);
        assert.equal('urn:test:1:2:3', attributes[3].getAttribute('Name'));
        assert.equal('urn:oasis:names:tc:SAML:2.0:attrname-format:uri', attributes[3].getAttribute('NameFormat'));
        assert.equal('xs:boolean', attributes[3].firstChild.getAttribute('xsi:type'));
        assert.equal('true', attributes[3].textContent);
        assert.equal('123~oo', attributes[4].getAttribute('Name'));
        assert.equal('urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified', attributes[4].getAttribute('NameFormat'));
        assert.equal('xs:double', attributes[4].firstChild.getAttribute('xsi:type'));
        assert.equal('123', attributes[4].textContent);
      });

      it('whole thing with specific authnContextClassRef', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key'),
          issuer: 'urn:issuer',
          lifetimeInSeconds: 600,
          audiences: 'urn:myapp',
          attributes: {
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'foo@bar.com',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'Foo Bar'
          },
          nameIdentifier:       'foo',
          nameIdentifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
          authnContextClassRef: 'specific'
        };

        var signedAssertion = saml[createAssertion](options);
        assertSignature(signedAssertion, options);

        var nameIdentifier = utils.getNameID(signedAssertion);
        assert.equal('foo', nameIdentifier.textContent);
        assert.equal('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified', nameIdentifier.getAttribute('Format'));

        var attributes = utils.getAttributes(signedAssertion);
        assert.equal(2, attributes.length);
        assert.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress', attributes[0].getAttribute('Name'));
        assert.equal('foo@bar.com', attributes[0].textContent);
        assert.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name', attributes[1].getAttribute('Name'));
        assert.equal('Foo Bar', attributes[1].textContent);

        assert.equal('urn:issuer', utils.getSaml2Issuer(signedAssertion).textContent);

        var conditions = utils.getConditions(signedAssertion);
        assert.equal(1, conditions.length);
        var notBefore = conditions[0].getAttribute('NotBefore');
        var notOnOrAfter = conditions[0].getAttribute('NotOnOrAfter');
        should.ok(notBefore);
        should.ok(notOnOrAfter);

        var lifetime = Math.round((moment(notOnOrAfter).utc() - moment(notBefore).utc()) / 1000);
        assert.equal(600, lifetime);

        var authnContextClassRef = utils.getAuthnContextClassRef(signedAssertion);
        assert.equal('specific', authnContextClassRef.textContent);
      });

      assertSignature.it('should place signature where specified', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key'),
          xpathToNodeBeforeSignature: "//*[local-name(.)='Conditions']",
          attributes: {
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'foo@bar.com',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'Foo Bar',
            'http://example.org/claims/testemptyarray': [], // should dont include empty arrays
            'http://example.org/claims/testaccent': 'fóo', // should supports accents
            'http://undefinedattribute/ws/com.com': undefined
          }
        };

        var signedAssertion = saml[createAssertion](options);

        assertSignature(signedAssertion, options);

        var doc = new xmldom.DOMParser().parseFromString(signedAssertion);
        var signature = doc.documentElement.getElementsByTagName('Signature');

        assert.equal('saml:Conditions', signature[0].previousSibling.nodeName);
      });

      assertSignature.it('should place signature with prefix where specified', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key'),
          xpathToNodeBeforeSignature: "//*[local-name(.)='Conditions']",
          signatureNamespacePrefix: 'anyprefix',
          attributes: {
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'foo@bar.com',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'Foo Bar',
            'http://example.org/claims/testemptyarray': [], // should dont include empty arrays
            'http://example.org/claims/testaccent': 'fóo', // should supports accents
            'http://undefinedattribute/ws/com.com': undefined
          }
        };

        var signedAssertion = saml[createAssertion](options);

        assertSignature(signedAssertion, options);

        var doc = new xmldom.DOMParser().parseFromString(signedAssertion);
        var signature = doc.documentElement.getElementsByTagName(options.signatureNamespacePrefix + ':Signature');
        assert.equal('saml:Conditions', signature[0].previousSibling.nodeName);
      });

      assertSignature.it('should place signature with prefix where specified (backwards compat)', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key'),
          xpathToNodeBeforeSignature: "//*[local-name(.)='Conditions']",
          prefix: 'anyprefix',
          attributes: {
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'foo@bar.com',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'Foo Bar',
            'http://example.org/claims/testemptyarray': [], // should dont include empty arrays
            'http://example.org/claims/testaccent': 'fóo', // should supports accents
            'http://undefinedattribute/ws/com.com': undefined
          }
        };

        var signedAssertion = saml[createAssertion](options);

        assertSignature(signedAssertion, options);

        var doc = new xmldom.DOMParser().parseFromString(signedAssertion);
        var signature = doc.documentElement.getElementsByTagName(options.prefix + ':Signature');
        assert.equal('saml:Conditions', signature[0].previousSibling.nodeName);
      });

      assertSignature.it('should ignore prefix if not a string', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key'),
          xpathToNodeBeforeSignature: "//*[local-name(.)='Conditions']",
          signatureNamespacePrefix: 123,
          attributes: {
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'foo@bar.com',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'Foo Bar',
            'http://example.org/claims/testemptyarray': [], // should dont include empty arrays
            'http://example.org/claims/testaccent': 'fóo', // should supports accents
            'http://undefinedattribute/ws/com.com': undefined
          }
        };

        var signedAssertion = saml[createAssertion](options);

        assertSignature(signedAssertion, options);

        var doc = new xmldom.DOMParser().parseFromString(signedAssertion);
        var signature = doc.documentElement.getElementsByTagName('Signature');
        assert.equal('saml:Conditions', signature[0].previousSibling.nodeName);
      });


      it('should not include AudienceRestriction when there are no audiences', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key'),
          xpathToNodeBeforeSignature: "//*[local-name(.)='Conditions']",
          signatureNamespacePrefix: 123,
          attributes: {
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'foo@bar.com',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'Foo Bar',
            'http://example.org/claims/testemptyarray': [], // should dont include empty arrays
            'http://example.org/claims/testaccent': 'fóo', // should supports accents
            'http://undefinedattribute/ws/com.com': undefined
          }
        };

        var signedAssertion = saml[createAssertion](options);

        assertSignature(signedAssertion, options);

        var doc = new xmldom.DOMParser().parseFromString(signedAssertion);
        var audienceRestriction = doc.documentElement.getElementsByTagName('saml:AudienceRestriction');
        assert.equal(audienceRestriction.length, 0);
      });

      it('should not include AttributeStatement when there are no attributes', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key'),
          xpathToNodeBeforeSignature: "//*[local-name(.)='Conditions']",
          signatureNamespacePrefix: 123
        };

        var signedAssertion = saml[createAssertion](options);

        assertSignature(signedAssertion, options);

        var doc = new xmldom.DOMParser().parseFromString(signedAssertion);
        var attributeStatement = doc.documentElement.getElementsByTagName('saml:AttributeStatement');
        assert.equal(attributeStatement.length, 0);
      });

      describe('encryption', function () {
        let consoleSpy = null;
        beforeEach(function() {
          consoleSpy = sinon.spy(console, 'warn');
        });

        afterEach(function() {
          consoleSpy.restore();
        });

        it('should create a saml 2.0 signed and encrypted assertion', function (done) {
          var options = {
            cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
            key: fs.readFileSync(__dirname + '/test-auth0.key'),
            encryptionPublicKey: fs.readFileSync(__dirname + '/test-auth0_rsa.pub'),
            encryptionCert: fs.readFileSync(__dirname + '/test-auth0.pem')
          };

          saml[createAssertion](options, function (err, encrypted) {
            if (err) return done(err);

            var encryptedData = utils.getEncryptedData(encrypted);

            xmlenc.decrypt(encryptedData.toString(), { key: fs.readFileSync(__dirname + '/test-auth0.key') }, function (err, decrypted) {
              if (err) return done(err);
              assertSignature(decrypted, options);
              done();
            });
          });
        });

        it('should not error when encryptionPublicKey is missing newline', function (done) {
          var options = {
            cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
            key: fs.readFileSync(__dirname + '/test-auth0.key'),
            encryptionPublicKey: Buffer.from(fs.readFileSync(__dirname + '/test-auth0_rsa.pub').toString().replaceAll(/[\r\n]/g, '')),
            encryptionCert: fs.readFileSync(__dirname + '/test-auth0.pem')
          };

          saml[createAssertion](options, function (err, encrypted) {
            if (err) return done(err);

            var encryptedData = utils.getEncryptedData(encrypted);

            xmlenc.decrypt(encryptedData.toString(), { key: fs.readFileSync(__dirname + '/test-auth0.key') }, function (err, decrypted) {
              if (err) return done(err);
              assertSignature(decrypted, options);
              done();
            });
          });
        });

        it('should not error when encryptionCert is missing newline', function (done) {
          var options = {
            cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
            key: fs.readFileSync(__dirname + '/test-auth0.key'),
            encryptionPublicKey: fs.readFileSync(__dirname + '/test-auth0_rsa.pub'),
            encryptionCert: Buffer.from(fs.readFileSync(__dirname + '/test-auth0.pem').toString().replaceAll(/[\r\n]/g, ''))
          };

          saml[createAssertion](options, function (err, encrypted) {
            if (err) return done(err);

            var encryptedData = utils.getEncryptedData(encrypted);

            xmlenc.decrypt(encryptedData.toString(), { key: fs.readFileSync(__dirname + '/test-auth0.key') }, function (err, decrypted) {
              if (err) return done(err);
              assertSignature(decrypted, options);
              done();
            });
          });
        });

        it('should set attributes', function (done) {
          var options = {
            cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
            key: fs.readFileSync(__dirname + '/test-auth0.key'),
            encryptionPublicKey: fs.readFileSync(__dirname + '/test-auth0_rsa.pub'),
            encryptionCert: fs.readFileSync(__dirname + '/test-auth0.pem'),
            attributes: {
              'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'foo@bar.com',
              'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'Foo Bar',
              'http://example.org/claims/testaccent': 'fóo', // should supports accents
              'http://undefinedattribute/ws/com.com': undefined
            }
          };

          saml[createAssertion](options, function (err, encrypted) {
            if (err) return done(err);

            var encryptedData = utils.getEncryptedData(encrypted);

            xmlenc.decrypt(encryptedData.toString(), { key: fs.readFileSync(__dirname + '/test-auth0.key') }, function (err, decrypted) {
              if (err) return done(err);

              assertSignature(decrypted, options);

              var attributes = utils.getAttributes(decrypted);
              assert.equal(3, attributes.length);
              assert.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress', attributes[0].getAttribute('Name'));
              assert.equal('foo@bar.com', attributes[0].textContent);
              assert.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name', attributes[1].getAttribute('Name'));
              assert.equal('Foo Bar', attributes[1].textContent);
              assert.equal('http://example.org/claims/testaccent', attributes[2].getAttribute('Name'));
              assert.equal('fóo', attributes[2].textContent);

              done();
            });
          });
        });

        it('should use aes256-gcm as the default encryption algorithm', function (done) { 
          var options = {
            cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
            key: fs.readFileSync(__dirname + '/test-auth0.key'),
            encryptionPublicKey: fs.readFileSync(__dirname + '/test-auth0_rsa.pub'),
            encryptionCert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          };

          saml[createAssertion](options, function (err, encrypted) {
            if (err) return done(err);
            var encryptedData = utils.getEncryptedData(encrypted);
            var encryptionMethod = encryptedData.getElementsByTagName('xenc:EncryptionMethod')[0];
            assert.equal('http://www.w3.org/2009/xmlenc11#aes256-gcm', encryptionMethod.getAttribute('Algorithm'));
            done();
          })
        });

        it('should allow aes256-cbc when disallowEncryptionWithInsecureAlgorithm is false', function (done) {
          var options = {
            cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
            key: fs.readFileSync(__dirname + '/test-auth0.key'),
            encryptionPublicKey: fs.readFileSync(__dirname + '/test-auth0_rsa.pub'),
            encryptionCert: fs.readFileSync(__dirname + '/test-auth0.pem'),
            encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
            disallowEncryptionWithInsecureAlgorithm: false,
            warnOnInsecureEncryptionAlgorithm: true,
          };

          saml[createAssertion](options, function (err, encrypted) {
            if (err) return done(err);
            var encryptedData = utils.getEncryptedData(encrypted);
            var encryptionMethod = encryptedData.getElementsByTagName('xenc:EncryptionMethod')[0];
            assert.equal('http://www.w3.org/2001/04/xmlenc#aes256-cbc', encryptionMethod.getAttribute('Algorithm'));
            assert.equal(consoleSpy.called, true);
            done();
          });
        });

        it('should not allow aes256-cbc when disallowEncryptionWithInsecureAlgorithm is true', function (done) {
          var options = {
            cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
            key: fs.readFileSync(__dirname + '/test-auth0.key'),
            encryptionPublicKey: fs.readFileSync(__dirname + '/test-auth0_rsa.pub'),
            encryptionCert: fs.readFileSync(__dirname + '/test-auth0.pem'),
            encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
            disallowEncryptionWithInsecureAlgorithm: true
          };

          saml[createAssertion](options, function (err, encrypted) {
            assert.ok(err);
            done();
          });
        });

      });
    });
  }
});
