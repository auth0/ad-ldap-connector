var expect = require('chai').expect;
var server = require('./fixture/server');
var request = require('request');
var cheerio = require('cheerio');
var xmlhelper = require('./xmlhelper');

describe('wsfed with sha1', function () {
  before(function (done) {
    server.start({
      signatureAlgorithm: 'rsa-sha1',
      digestAlgorithm: 'sha1'
    }, done);
  });
  
  after(function (done) {
    server.close(done);
  });

  describe('authorizing', function () {
    var body, $, signedAssertion, attributes;

    before(function (done) {
      request.get({
        jar: request.jar(), 
        uri: 'http://localhost:5050/wsfed?wa=wsignin1.0&wctx=123&wtrealm=urn:the-super-client-id'
      }, function (err, response, b){
        if(err) return done(err);
        body = b;
        $ = cheerio.load(body);
        var wresult = $('input[name="wresult"]').attr('value');
        signedAssertion = /<t:RequestedSecurityToken>(.*)<\/t:RequestedSecurityToken>/.exec(wresult)[1];
        attributes = xmlhelper.getAttributes(signedAssertion);
        done();
      });
    });

    it('should use sha1 as signature algorithm', function(){
      var algorithm = xmlhelper.getSignatureMethodAlgorithm(signedAssertion);
      expect(algorithm).to.equal('http://www.w3.org/2000/09/xmldsig#rsa-sha1');
    });

    it('should use sha1 as digest algorithm', function(){
      var algorithm = xmlhelper.getDigestMethodAlgorithm(signedAssertion);
      expect(algorithm).to.equal('http://www.w3.org/2000/09/xmldsig#sha1');
    });

  });
});