var fs = require('fs');
var path = require('path');
var expect = require('chai').expect;
var server = require('./fixture/server');
var request = require('request');
var cheerio = require('cheerio');
var xmlenc = require('xml-encryption');
var xmlhelper = require('./xmlhelper');

var credentials = {
  cert:     fs.readFileSync(path.join(__dirname, '/fixture/wsfed.test-cert.pem')),
  key:      fs.readFileSync(path.join(__dirname, '/fixture/wsfed.test-cert.key')),
  pkcs7:    fs.readFileSync(path.join(__dirname, '/fixture/wsfed.test-cert.pb7')),
  pub:    fs.readFileSync(path.join(__dirname, '/fixture/wsfed.test-cert.pub'))
};


describe('when dwdw encrypting the assertion', function () {
  before(function (done) {
    server.start({
      encryptionPublicKey: credentials.pub,
      encryptionCert:     credentials.cert
    }, done);
  });
  
  after(function (done) {
    server.close(done);
  });

  var body, $, encryptedAssertion;

  describe('when encrypting the assertion', function () {
    before(function (done) {
      request.get({
        jar: request.jar(), 
        uri: 'http://localhost:5050/wsfed?wa=wsignin1.0&wctx=123&wtrealm=urn:the-super-client-id'
      }, function (err, response, b){
        if(err) return done(err);
        body = b;
        $ = cheerio.load(body);
        var wresult = $('input[name="wresult"]').attr('value');        
        encryptedAssertion = /<t:RequestedSecurityToken>(.*)<\/t:RequestedSecurityToken>/.exec(wresult)[1];
        done();
      });
    });

    it('should contain a form in the result', function(){
      expect(body).to.match(/<form/);
    });

    it('should contain an encrypted xml', function(){
      expect(encryptedAssertion).to.match(/xenc:EncryptedData/);
    });

    it('should contain a valid encrypted xml with the assertion', function(done){
      xmlenc.decrypt(encryptedAssertion, { key: credentials.key }, function(err, decrypted) {

        var isValid = xmlhelper.verifySignature(decrypted, credentials.cert);
        expect(isValid).to.be.ok;

        var attributes = xmlhelper.getAttributes(decrypted);

        function validateAttribute(position, name, value) {
          expect(attributes[position].getAttribute('AttributeName'))
            .to.equal(name);
          expect(attributes[position].firstChild.textContent)
            .to.equal(value);
        }

        validateAttribute(0, 'nameidentifier', server.fakeUser.id);
        validateAttribute(1, 'emailaddress',   server.fakeUser.emails[0].value);
        validateAttribute(2, 'name',           server.fakeUser.displayName);
        validateAttribute(3, 'givenname',      server.fakeUser.name.givenName);
        validateAttribute(4, 'surname',        server.fakeUser.name.familyName);

        done();
      });
    });
  });

  describe('with aes256-cbc encryption algorithm', function () {
    var statusCode, body;

    before(function (done) {
      server.options.encryptionAlgorithm = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';
      request.get({
        jar: request.jar(), 
        uri: 'http://localhost:5050/wsfed?wa=wsignin1.0&wctx=123&wtrealm=urn:the-super-client-id'
      }, function (err, response, b){
        if(err) return done(err);
        statusCode = response.statusCode;
        body = b;
        done();
      });
    });

    it('should response with 400 status code and insecure algorithm error message', function(){
      expect(statusCode).to.equal(400);
      expect(body).to.equal('encryption algorithm http://www.w3.org/2001/04/xmlenc#aes256-cbc is not secure');
    });

  });

  describe('with aes256-gcm encryption algorithm', function () {
    var statusCode;

    before(function (done) {
      server.options.encryptionAlgorithm = 'http://www.w3.org/2009/xmlenc11#aes256-gcm';
      request.get({
        jar: request.jar(), 
        uri: 'http://localhost:5050/wsfed?wa=wsignin1.0&wctx=123&wtrealm=urn:the-super-client-id'
      }, function (err, response, body){
        if(err) return done(err);
        statusCode = response.statusCode;
        done();
      });
    });

    it('should response with 200 status code', function(){
      expect(statusCode).to.equal(200);
    });

  });

  describe('with aes256-cbc encryption algorithm and disallowEncryptionWithInsecureAlgorithm set to true', function () {
    var statusCode, body;

    before(function (done) {
      server.options.encryptionAlgorithm = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';
      server.options.disallowEncryptionWithInsecureAlgorithm = true;
      server.options.warnOnInsecureEncryptionAlgorithm = false;
      request.get({
        jar: request.jar(), 
        uri: 'http://localhost:5050/wsfed?wa=wsignin1.0&wctx=123&wtrealm=urn:the-super-client-id'
      }, function (err, response, b){
        if(err) return done(err);
        statusCode = response.statusCode;
        body = b;
        done();
      });
    });

    it('should response with 400 error', function(){
      expect(statusCode).to.equal(400);
      expect(body).to.equal('encryption algorithm http://www.w3.org/2001/04/xmlenc#aes256-cbc is not secure');
    });

  });

  describe('with aes256-cbc encryption algorithm and disallowEncryptionWithInsecureAlgorithm set to false', function () {
    var statusCode;

    before(function (done) {
      server.options.encryptionAlgorithm = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';
      server.options.disallowEncryptionWithInsecureAlgorithm = false;
      server.options.warnOnInsecureEncryptionAlgorithm = true;
      request.get({
        jar: request.jar(), 
        uri: 'http://localhost:5050/wsfed?wa=wsignin1.0&wctx=123&wtrealm=urn:the-super-client-id'
      }, function (err, response, body){
        if(err) return done(err);
        statusCode = response.statusCode;
        done();
      });
    });

    it('should response with 200 status code', function(){
      expect(statusCode).to.equal(200);
    });

  });
  
});

