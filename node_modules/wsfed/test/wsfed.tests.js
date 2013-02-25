var expect = require('chai').expect;
var server = require('./fixture/server');
var request = require('request');
var cheerio = require('cheerio');
var utils = require('./utils');
var fs = require('fs');

describe('wsfed', function () {
  before(function (done) {
    server.start(done);
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
        attributes = utils.getAttributes(signedAssertion);
        done();
      });
    });

    it('should contain a form in the result', function(){
      expect(body).to.match(/<form/);
    });

    it('should contain the wctx input', function () {
      expect($('input[name="wctx"]').attr('value')).to.equal('123');
    });

    it('should contain a valid signal assertion', function(){
      var isValid = utils.isValidSignature(
                signedAssertion, 
                server.credentials.cert);
      expect(isValid).to.be.ok;
    });


    it('should map every attributes from profile', function(){
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
      validateAttribute(4, 'surname',         server.fakeUser.name.familyName);
    });

    it('should contains the issuer', function(){
      expect(utils.getIssuer(signedAssertion))
        .to.equal('urn:fixture-test');
    });

    it('should contains the audiences', function(){
      expect(utils.getAudiences(signedAssertion)[0].textContent)
        .to.equal('urn:the-super-client-id');
    });

    it('should contain the callback', function () {
      expect($('form').attr('action')).to.equal('http://office.google.com');
    });
  });
});