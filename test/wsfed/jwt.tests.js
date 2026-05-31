var fs = require('fs');
var path = require('path');
var expect = require('chai').expect;
var server = require('./fixture/server');
var request = require('request');
var cheerio = require('cheerio');
var jwt = require('jsonwebtoken');

// RSA
var credentials = {
  cert:     fs.readFileSync(path.join(__dirname, '/fixture/wsfed.test-cert.pem')),
  key:      fs.readFileSync(path.join(__dirname, '/fixture/wsfed.test-cert.key')),
  pkcs7:    fs.readFileSync(path.join(__dirname, '/fixture/wsfed.test-cert.pb7'))
};

// 1024 bits RSA key
var insecure_credentials = {
  cert:     fs.readFileSync(path.join(__dirname, '/fixture/wsfed.test-insercure-key.pem')),
  key:      fs.readFileSync(path.join(__dirname, '/fixture/wsfed.test-insercure-key.key')),
  pkcs7:    fs.readFileSync(path.join(__dirname, '/fixture/wsfed.test-insercure-key.pb7')),
};

// DSA
var dsa_credentials = {
  cert:     fs.readFileSync(path.join(__dirname, '/fixture/wsfed.test-dsa-key.pem')),
  key:      fs.readFileSync(path.join(__dirname, '/fixture/wsfed.test-dsa-key.key')),
  pkcs7:    fs.readFileSync(path.join(__dirname, '/fixture/wsfed.test-dsa-key.pb7')),
};

describe('wsfed+jwt', function () {

  describe('authorizing', function () {
    var body, $, signedAssertion, profile;

    after(function (done) {
      server.close(done);
    });

    before(function (done) {
      server.start({
        jwt: true
      }, function(err) {
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

  describe('when using a key and an algorithm that do not match', function () {

    afterEach(function (done) {
      server.close(done);
    });

    describe('when not passing jwtAllowInvalidAsymmetricKeyTypes', function () {

      beforeEach(function (done) {
      
        server.start({
          jwt: true,
          // using RSA256 with a DSA key
          jwtAlgorithm: 'RS256',
          credentials: dsa_credentials
        }, function(err) {
          if (err) {
            done(err);
          }
  
          done();
        });
      });

      it('should error because of the mismatch between the key and the algorithm', function (done) {
      
        request.get({
          jar: request.jar(),
          uri: 'http://localhost:5050/wsfed?wa=wsignin1.0&wctx=123&wtrealm=urn:the-super-client-id'
        }, function (err, response, body) {
          if (err) return done(err);
          expect(response.statusCode).to.eql(400);
          expect(body).to.eql('Unknown key type "dsa".');
          done();
        });
  
      });
    });

    describe('when passing jwtAllowInvalidAsymmetricKeyTypes = true', function () {

      beforeEach(function (done) {
      
        server.start({
          jwt: true,
          // using RSA256 with a DSA key
          jwtAlgorithm: 'RS256',
          jwtAllowInvalidAsymmetricKeyTypes: true,
          credentials: dsa_credentials
        }, function(err) {
          if (err) {
            done(err);
          }
  
          done();
        });
      });

      it('should allow the mismatch between the key and the algorithm', function (done) {
      
        request.get({
          jar: request.jar(),
          uri: 'http://localhost:5050/wsfed?wa=wsignin1.0&wctx=123&wtrealm=urn:the-super-client-id'
        }, function (err, response, body) {
          if (err) return done(err);
          console.log(body);
          expect(response.statusCode).to.eql(200);
          done();
        });
  
      });
    });
  });

  describe('when using insecure key sizes', function () {

    afterEach(function (done) {
      server.close(done);
    });

    describe('when not passing jwtAllowInsecureKeySizes', function () {

      beforeEach(function (done) {
      
        server.start({
          jwt: true,
          credentials: insecure_credentials
        }, function(err) {
          if (err) {
            done(err);
          }
  
          done();
        });
      });

      it('should error because of the size of key', function (done) {
      
        request.get({
          jar: request.jar(),
          uri: 'http://localhost:5050/wsfed?wa=wsignin1.0&wctx=123&wtrealm=urn:the-super-client-id'
        }, function (err, response, body) {
          if (err) return done(err);
          expect(response.statusCode).to.eql(400);
          expect(body).to.eql('secretOrPrivateKey has a minimum key size of 2048 bits for RS256');
          done();
        });
  
      });
    });

    describe('when passing jwtAllowInsecureKeySizes = true', function () {

      beforeEach(function (done) {
      
        server.start({
          jwt: true,
          jwtAllowInsecureKeySizes: true,
          credentials: insecure_credentials
        }, function(err) {
          if (err) {
            done(err);
          }
  
          done();
        });
      });

      it('should allow the insecure key', function (done) {
      
        request.get({
          jar: request.jar(),
          uri: 'http://localhost:5050/wsfed?wa=wsignin1.0&wctx=123&wtrealm=urn:the-super-client-id'
        }, function (err, response, body) {
          if (err) return done(err);
          expect(response.statusCode).to.eql(200);
          done();
        });
  
      });
    });
  });

  describe('authorizing with extra claims', function () {
    var body, $, signedAssertion, profile;

    after(function (done) {
      server.close(done);
    });

    before(function (done) {
      server.start({
        jwt: true,
        extendJWT: { extra: 'claim' }
      }, function(err) {
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
    });

    it('should have the attributes', function(){
      expect(profile).to.have.property('displayName');
      expect(profile.id).to.equal('12334444444');
      expect(profile).to.have.property('extra');
      expect(profile.extra).to.equal('claim');
    });

    it('should have jwt attributes', function(){
      expect(profile).to.have.property('aud');
      expect(profile).to.have.property('iss');
      expect(profile).to.have.property('iat');
    });

  });
});
