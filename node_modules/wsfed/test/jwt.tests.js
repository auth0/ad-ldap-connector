var fs = require('fs');
var path = require('path');
var expect = require('chai').expect;
var server = require('./fixture/server');
var request = require('request');
var cheerio = require('cheerio');
var xmlhelper = require('./xmlhelper');
var jwt = require('jsonwebtoken');

var credentials = {
  cert:     fs.readFileSync(path.join(__dirname, '/fixture/wsfed.test-cert.pem')),
  key:      fs.readFileSync(path.join(__dirname, '/fixture/wsfed.test-cert.key')),
  pkcs7:    fs.readFileSync(path.join(__dirname, '/fixture/wsfed.test-cert.pb7'))
};


describe('wsfed+jwt', function () {
  before(function (done) {
    server.start({
      jwt: true
    }, done);
  });
  
  after(function (done) {
    server.close(done);
  });

  describe('authorizing', function () {
    var body, $, signedAssertion, profile;

    before(function (done) {
      request.get({
        jar: request.jar(), 
        uri: 'http://localhost:5050/wsfed?wa=wsignin1.0&wctx=123&wtrealm=urn:the-super-client-id'
      }, function (err, response, b){
        if(err) return done(err);
        body = b;
        $ = cheerio.load(body);
        var signedAssertion = $('input[name="wresult"]').attr('value');
        jwt.verify(signedAssertion, credentials.cert.toString(), function (err, decoded) {
          if (err) return done(err);
          profile = decoded;
          done();
        });
      });
    });

    it('should have the attributes', function(){
      expect(profile).to.have.property('displayName');
      expect(profile.id).to.equal('12334444444');
    });

    it('should have jwt attributes', function(){
      expect(profile).to.have.property('aud');
      expect(profile).to.have.property('iss');
      expect(profile).to.have.property('iat');
    });

  });
});