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
        var isValid = xmlhelper.verifySignature(
                decrypted, 
                credentials.cert);
        expect(isValid).to.be.ok;
        done();
      });
    });
  });
  
});