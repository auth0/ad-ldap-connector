var assert = require('assert'),
    fs = require('fs'),
    xmlenc = require('../lib');

var crypto = require('crypto');

describe('encrypt', function() {

  it('should encrypt and decrypt xml', function (done) {
    // cert created with:
    // openssl req -x509 -new -newkey rsa:2048 -nodes -subj '/CN=auth0.auth0.com/O=Auth0 LLC/C=US/ST=Washington/L=Redmond' -keyout auth0.key -out auth0.pem
    // pub key extracted from (only the RSA public key between BEGIN PUBLIC KEY and END PUBLIC KEY)
    // openssl x509 -in "test-auth0.pem" -pubkey 

    var options = {
      rsa_pub: fs.readFileSync(__dirname + '/test-auth0_rsa.pub'),
      pem: fs.readFileSync(__dirname + '/test-auth0.pem'),
      encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
      keyEncryptionAlgorighm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
    };

    xmlenc.encrypt('content to encrypt', options, function(err, result) {        
        xmlenc.decrypt(result, { key: fs.readFileSync(__dirname + '/test-auth0.key')}, function(err, decrypted) {
          assert.equal(decrypted, 'content to encrypt');
          done();
        });
    });
  });

  it('should encrypt and decrypt keyinfo', function (done) {
    var options = {
      rsa_pub: fs.readFileSync(__dirname + '/test-auth0_rsa.pub'),
      pem: fs.readFileSync(__dirname + '/test-auth0.pem'),
      keyEncryptionAlgorighm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
    };

    crypto.randomBytes(32, function(err, randomBytes) {
      if (err) return done(err);
      xmlenc.encryptKeyInfo(randomBytes, options, function(err, result) { 
        if (err) return done(err);
        var decryptedRandomBytes = xmlenc.decryptKeyInfo(result, { key: fs.readFileSync(__dirname + '/test-auth0.key')});

        assert.equal(new Buffer(randomBytes).toString('base64'), new Buffer(decryptedRandomBytes).toString('base64'));
        done();
      });
    });
  });

});
