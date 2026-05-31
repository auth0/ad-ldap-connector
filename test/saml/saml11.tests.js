var assert = require('chai').assert;
var fs = require('fs');
var moment = require('moment');
var should = require('should');
var xmldom = require('@xmldom/xmldom');
var xmlenc = require('xml-encryption');

var utils = require('./utils');
var saml11 = require('../lib/saml11');
var sinon = require('sinon');

describe('saml 1.1', function () {

  saml11TestSuite({
    createAssertion: 'create',
    assertSignature: Object.assign(function (assertion, options) {
      assert.isTrue(utils.isValidSignature(assertion, options.cert));
    }, {
      it: it
    })
  });

  saml11TestSuite({
    createAssertion: 'createUnsignedAssertion',
    assertSignature: Object.assign(function (assertion) {
      assert.isEmpty(utils.getXmlSignatures(assertion));
    }, {
      it: it.skip
    })
  });

  function saml11TestSuite(options) {
    var createAssertion = options.createAssertion;
    var assertSignature = options.assertSignature;

    describe('#' + createAssertion, function () {
      it('should create a saml 1.1 assertion', function () {
        // cert created with:
        // openssl req -x509 -new -newkey rsa:2048 -nodes -subj '/CN=auth0.auth0.com/O=Auth0 LLC/C=US/ST=Washington/L=Redmond' -keyout auth0.key -out auth0.pem

        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key')
        };

        var signedAssertion = saml11[createAssertion](options);
        assertSignature(signedAssertion, options);
      });

      it('should not error when cert is missing newlines', function () {
        // cert created with:
        // openssl req -x509 -new -newkey rsa:2048 -nodes -subj '/CN=auth0.auth0.com/O=Auth0 LLC/C=US/ST=Washington/L=Redmond' -keyout auth0.key -out auth0.pem

        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key')
        };

        var signedAssertion = saml11[createAssertion]({...options, cert: Buffer.from(options.cert.toString().replaceAll(/[\r\n]/g, ''))});
        assertSignature(signedAssertion, options);
      });

      it('should not error when key is missing newlines', function () {
        // cert created with:
        // openssl req -x509 -new -newkey rsa:2048 -nodes -subj '/CN=auth0.auth0.com/O=Auth0 LLC/C=US/ST=Washington/L=Redmond' -keyout auth0.key -out auth0.pem

        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key')
        };

        var signedAssertion = saml11[createAssertion]({...options, key: Buffer.from(options.key.toString().replaceAll(/[\r\n]/g, ''))});
        assertSignature(signedAssertion, options);
      });

      it('should support specifying Issuer property', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key'),
          issuer: 'urn:issuer'
        };

        var signedAssertion = saml11[createAssertion](options);
        assert.equal('urn:issuer', utils.getIssuer(signedAssertion));
      });

      it('should create IssueInstant property', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key')
        };

        var signedAssertion = saml11[createAssertion](options);
        // 2012-12-17T01:59:14.782Z
        var now = moment.utc();
        var issueInstant = moment(utils.getIssueInstant(signedAssertion)).utc();
        assert.equal(now.year(), issueInstant.year());
        assert.equal(now.month(), issueInstant.month());
        assert.equal(now.day(), issueInstant.day());
        assert.equal(now.hours(), issueInstant.hours());
        assert.equal(now.minutes(), issueInstant.minutes());
      });

      it('should create AssertionID and start with underscore', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key')
        };

        var signedAssertion = saml11[createAssertion](options);
        var id = utils.getAssertionID(signedAssertion);
        assert.equal('_', id[0]); // first char is underscore
      });

      it('should create NotBefore and NotOnOrAfter properties', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key'),
          lifetimeInSeconds: 600
        };

        var signedAssertion = saml11[createAssertion](options);
        var conditions = utils.getConditions(signedAssertion);
        assert.equal(1, conditions.length);
        var authenticationInstant = utils.getAuthenticationInstant(signedAssertion);
        var notBefore = conditions[0].getAttribute('NotBefore');
        var notOnOrAfter = conditions[0].getAttribute('NotOnOrAfter');

        should.ok(notBefore);
        should.ok(notOnOrAfter);
        should.equal(authenticationInstant, notBefore);

        var lifetime = Math.round((moment(notOnOrAfter).utc() - moment(notBefore).utc()) / 1000);
        assert.equal(600, lifetime);
      });

      it('should set audience restriction', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key'),
          audiences: 'urn:myapp'
        };

        var signedAssertion = saml11[createAssertion](options);
        var audiences = utils.getAudiences(signedAssertion);
        assert.equal(1, audiences.length);
        assert.equal('urn:myapp', audiences[0].textContent);
      });

      it('should set multiple audience restriction', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key'),
          audiences: ['urn:myapp', 'urn:myapp2']
        };

        var signedAssertion = saml11[createAssertion](options);
        var audiences = utils.getAudiences(signedAssertion);
        assert.equal(2, audiences.length);
        assert.equal('urn:myapp', audiences[0].textContent);
        assert.equal('urn:myapp2', audiences[1].textContent);
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

        var signedAssertion = saml11[createAssertion](options);

        assertSignature(signedAssertion, options);

        var attributes = utils.getAttributes(signedAssertion);
        assert.equal(3, attributes.length);
        assert.equal('emailaddress', attributes[0].getAttribute('AttributeName'));
        assert.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims', attributes[0].getAttribute('AttributeNamespace'));
        assert.equal('foo@bar.com', attributes[0].firstChild.textContent);
        assert.equal('name', attributes[1].getAttribute('AttributeName'));
        assert.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims', attributes[1].getAttribute('AttributeNamespace'));
        assert.equal('Foo Bar', attributes[1].firstChild.textContent);
        assert.equal('testaccent', attributes[2].getAttribute('AttributeName'));
        assert.equal('http://example.org/claims', attributes[2].getAttribute('AttributeNamespace'));
        assert.equal('fóo', attributes[2].firstChild.textContent);
      });

      it('should set attributes with multiple values', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key'),
          attributes: {
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role': ['admin','contributor']
          }
        };

        var signedAssertion = saml11[createAssertion](options);
        var attributes = utils.getAttributes(signedAssertion);
        assert.equal(1, attributes.length);
        assert.equal('role', attributes[0].getAttribute('AttributeName'));
        assert.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims', attributes[0].getAttribute('AttributeNamespace'));
        assert.equal('admin', attributes[0].childNodes[0].textContent);
        assert.equal('contributor', attributes[0].childNodes[1].textContent);
      });

      it('should set NameIdentifier', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key'),
          nameIdentifier: 'foo'
        };

        var signedAssertion = saml11[createAssertion](options);
        var nameIdentifier = utils.getNameIdentifier(signedAssertion);
        assert.equal('foo', nameIdentifier.textContent);
      });

      it('should not contains line breaks', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key'),
          nameIdentifier: 'foo'
        };

        var signedAssertion = saml11[createAssertion](options);
        assert.equal(-1, signedAssertion.indexOf('\n'));
      });

      it('should set AuthenticationInstant', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key'),
          nameIdentifier: 'foo'
        };

        var signedAssertion = saml11[createAssertion](options);
        var authenticationStatement = utils.getAuthenticationStatement(signedAssertion);
        assert.ok(!!authenticationStatement.getAttribute('AuthenticationInstant'));
      });

      it('should set AuthenticationStatement NameIdentifier', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key'),
          nameIdentifier: 'foo'
        };
        var signedAssertion = saml11[createAssertion](options);
        var nameIdentifier = utils.getAuthenticationStatement(signedAssertion)
        .getElementsByTagName('saml:NameIdentifier')[0]
          .textContent;
        assert.equal('foo', nameIdentifier);
      });

      it('should set AuthenticationStatement NameFormat', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key'),
          nameIdentifier: 'foo'
        };
        var signedAssertion = saml11[createAssertion](options);
        var format = utils.getAuthenticationStatement(signedAssertion)
        .getElementsByTagName('saml:NameIdentifier')[0]
        .getAttribute('Format');
        assert.equal('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified', format);
      });

      it('should set AttirubteStatement NameFormat', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key'),
          nameIdentifier: 'foo'
        };
        var signedAssertion = saml11[createAssertion](options);
        var format = utils.getNameIdentifier(signedAssertion)
        .getAttribute('Format');
        assert.equal('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified', format);
      });

      it('should override AttirubteStatement NameFormat', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key'),
          nameIdentifier: 'foo',
          nameIdentifierFormat: 'http://foo'
        };
        var signedAssertion = saml11[createAssertion](options);
        var format = utils.getAuthenticationStatement(signedAssertion)
        .getElementsByTagName('saml:NameIdentifier')[0]
        .getAttribute('Format');

        assert.equal('http://foo', format);
      });

      assertSignature.it('should place signature where specified', function () {
        var options = {
          cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
          key: fs.readFileSync(__dirname + '/test-auth0.key'),
          xpathToNodeBeforeSignature: "//*[local-name(.)='Conditions']"
        };
        var signedAssertion = saml11[createAssertion](options);
        var doc = new xmldom.DOMParser().parseFromString(signedAssertion);

        var signature = doc.documentElement.getElementsByTagName('Signature');

        assert.equal('saml:Conditions', signature[0].previousSibling.nodeName);
      });

      it('should test the whole thing', function () {
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
          nameIdentifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'
        };

        var signedAssertion = saml11[createAssertion](options);
        assertSignature(signedAssertion, options);

        var nameIdentifier = utils.getNameIdentifier(signedAssertion);
        assert.equal('foo', nameIdentifier.textContent);
        assert.equal('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified', nameIdentifier.getAttribute('Format'));

        var attributes = utils.getAttributes(signedAssertion);
        assert.equal(2, attributes.length);
        assert.equal('emailaddress', attributes[0].getAttribute('AttributeName'));
        assert.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims', attributes[0].getAttribute('AttributeNamespace'));
        assert.equal('foo@bar.com', attributes[0].firstChild.textContent);
        assert.equal('name', attributes[1].getAttribute('AttributeName'));
        assert.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims', attributes[1].getAttribute('AttributeNamespace'));
        assert.equal('Foo Bar', attributes[1].firstChild.textContent);

        assert.equal('urn:issuer', utils.getIssuer(signedAssertion));

        var conditions = utils.getConditions(signedAssertion);
        assert.equal(1, conditions.length);
        var notBefore = conditions[0].getAttribute('NotBefore');
        var notOnOrAfter = conditions[0].getAttribute('NotOnOrAfter');
        should.ok(notBefore);
        should.ok(notOnOrAfter);

        var lifetime = Math.round((moment(notOnOrAfter).utc() - moment(notBefore).utc()) / 1000);
        assert.equal(600, lifetime);

      });

      describe('encryption', function () {
        let consoleSpy = null;
        beforeEach(function() {
          consoleSpy = sinon.spy(console, 'warn');
        });

        afterEach(function() {
          consoleSpy.restore();
        });

        it('should create a saml 1.1 encrypted assertion', function (done) {
          var options = {
            cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
            key: fs.readFileSync(__dirname + '/test-auth0.key'),
            encryptionPublicKey: fs.readFileSync(__dirname + '/test-auth0_rsa.pub'),
            encryptionCert: fs.readFileSync(__dirname + '/test-auth0.pem')
          };

          saml11[createAssertion](options, function(err, encrypted) {
            if (err) return done(err);

            xmlenc.decrypt(encrypted, { key: fs.readFileSync(__dirname + '/test-auth0.key')}, function(err, decrypted) {
              if (err) return done(err);
              assertSignature(decrypted, options);
              done();
            });
          });
        });

        it('should not error when encryptionPublicKey is missing newlines', function (done) {
          var options = {
            cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
            key: fs.readFileSync(__dirname + '/test-auth0.key'),
            encryptionPublicKey: Buffer.from(fs.readFileSync(__dirname + '/test-auth0_rsa.pub').toString().replaceAll(/[\r\n]/g, '')),
            encryptionCert: fs.readFileSync(__dirname + '/test-auth0.pem')
          };

          saml11[createAssertion](options, function(err, encrypted) {
            if (err) return done(err);

            xmlenc.decrypt(encrypted, { key: fs.readFileSync(__dirname + '/test-auth0.key')}, function(err, decrypted) {
              if (err) return done(err);
              assertSignature(decrypted, options);
              done();
            });
          });
        });

        it('should not error when encryptionCert is missing newlines', function (done) {
          var options = {
            cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
            key: fs.readFileSync(__dirname + '/test-auth0.key'),
            encryptionPublicKey: fs.readFileSync(__dirname + '/test-auth0_rsa.pub'),
            encryptionCert: Buffer.from(fs.readFileSync(__dirname + '/test-auth0.pem').toString().replaceAll(/[\r\n]/g, ''))
          };

          saml11[createAssertion](options, function(err, encrypted) {
            if (err) return done(err);

            xmlenc.decrypt(encrypted, { key: fs.readFileSync(__dirname + '/test-auth0.key')}, function(err, decrypted) {
              if (err) return done(err);
              assertSignature(decrypted, options);
              done();
            });
          });
        });

        it('should support holder-of-key suject confirmationmethod', function (done) {
          var options = {
            cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
            key: fs.readFileSync(__dirname + '/test-auth0.key'),
            encryptionPublicKey: fs.readFileSync(__dirname + '/test-auth0_rsa.pub'),
            encryptionCert: fs.readFileSync(__dirname + '/test-auth0.pem'),
            subjectConfirmationMethod: 'holder-of-key'
          };

          saml11[createAssertion](options, function(err, encrypted, proofSecret) {
            if (err) return done(err);

            xmlenc.decrypt(encrypted, { key: fs.readFileSync(__dirname + '/test-auth0.key')}, function(err, decrypted) {
              if (err) return done(err);

              var doc = new xmldom.DOMParser().parseFromString(decrypted);
              var subjectConfirmationNodes = doc.documentElement.getElementsByTagName('saml:SubjectConfirmation');
              assert.equal(2, subjectConfirmationNodes.length);
              for (var i=0;i<subjectConfirmationNodes.length;i++) {
                var method = subjectConfirmationNodes[i].getElementsByTagName('saml:ConfirmationMethod')[0];
                assert.equal(method.textContent, 'urn:oasis:names:tc:SAML:1.0:cm:holder-of-key');

                var decryptedProofSecret = xmlenc.decryptKeyInfo(subjectConfirmationNodes[i], options);
                assert.equal(proofSecret.toString('base64'), decryptedProofSecret.toString('base64'));
              }

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

          saml11[createAssertion](options, function(err, encrypted) {
            if (err) return done(err);

            xmlenc.decrypt(encrypted, { key: fs.readFileSync(__dirname + '/test-auth0.key')}, function(err, decrypted) {
              if (err) return done(err);

              assertSignature(decrypted, options);

              var attributes = utils.getAttributes(decrypted);
              assert.equal(3, attributes.length);
              assert.equal('emailaddress', attributes[0].getAttribute('AttributeName'));
              assert.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims', attributes[0].getAttribute('AttributeNamespace'));
              assert.equal('foo@bar.com', attributes[0].firstChild.textContent);
              assert.equal('name', attributes[1].getAttribute('AttributeName'));
              assert.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims', attributes[1].getAttribute('AttributeNamespace'));
              assert.equal('Foo Bar', attributes[1].firstChild.textContent);
              assert.equal('testaccent', attributes[2].getAttribute('AttributeName'));
              assert.equal('http://example.org/claims', attributes[2].getAttribute('AttributeNamespace'));
              assert.equal('fóo', attributes[2].firstChild.textContent);

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

          saml11[createAssertion](options, function (err, encrypted) {
            if (err) return done(err);
            var doc = new xmldom.DOMParser().parseFromString(encrypted);
            var encryptionMethod = doc.getElementsByTagName('xenc:EncryptionMethod')[0];
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

          saml11[createAssertion](options, function (err, encrypted) {
            if (err) return done(err);
            var doc = new xmldom.DOMParser().parseFromString(encrypted);
            var encryptionMethod = doc.getElementsByTagName('xenc:EncryptionMethod')[0];
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

          saml11[createAssertion](options, function (err, encrypted) {
            assert.ok(err);
            done();
          });
        });
      });
    });
  }
});
