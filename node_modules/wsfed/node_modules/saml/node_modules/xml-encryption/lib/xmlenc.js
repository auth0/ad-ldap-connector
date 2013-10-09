var ursa = require('ursa'),
    crypto = require('crypto'),
    async = require('async'),
    xmldom = require('xmldom'),
    crypto = require('crypto'),
    xpath = require('xpath'),
    utils = require('./utils');

exports.encrypt = function(content, options, callback) {
  if (!options)
    return callback(new Error('must provide options'));
  if (!content)
    return callback(new Error('must provide content to encrypt'));
  if (!options.rsa_pub)
    return callback(new Error('rsa_pub option is mandatory and you should provide a valid RSA public key'));
  if (!options.pem)
    return callback(new Error('pem option is mandatory and you should provide a valid x509 certificate encoded as PEM'));

  async.waterfall([
    function generate_symmetric_key(cb) {
      // generate a symmetric random key 32 bytes length
      crypto.randomBytes(32, function(err, symmetricKey) {
        if (err) return cb(err);
        
        cb(null, symmetricKey);
      });
    },
    function encrypt_content(symmetricKey, cb) {
      switch (options.encryptionAlgorithm) {
        case 'http://www.w3.org/2001/04/xmlenc#aes256-cbc':
          encrypt_aes256cbc(symmetricKey, content, options.input_encoding, function(err, encryptedContent) {
            if (err) return cb(err);
            cb(null, symmetricKey, encryptedContent);
          });
            break;
        default:
          throw new Error('encryption algorithm not supported');
      }
    },
    function encrypt_key(symmetricKey, encryptedContent, cb) {
      if (!options.keyEncryptionAlgorighm)
        throw new Error('encryption without encrypted key is not supported yet');

      switch (options.keyEncryptionAlgorighm) {
        case 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p':
          var rsa_pub = ursa.createPublicKey(options.rsa_pub);
          // encrypt the symmetric key with the public key
          var encryptedKey = rsa_pub.encrypt(symmetricKey);

          var params = {
            encryptedKey: encryptedKey.toString('base64'), 
            encryptedContent: encryptedContent.toString('base64'),
            keyInfo: '<X509Data><X509Certificate>' + utils.pemToCert(options.pem.toString()) + '</X509Certificate></X509Data>', 
            contentEncryptionMethod: options.encryptionAlgorithm,
            keyEncryptionMethod: options.keyEncryptionAlgorighm
          };
          
          var result = utils.renderTemplate('encrypted-key', params);
          cb(null, result);
          break;
        default:
            throw new Error('encryption key algorithm not supported');
      }
    }
  ], callback);
};

exports.decrypt = function(xml, options, callback) {
  if (!options)
    callback(new Error('must provide options'));
  if (!xml)
    callback(Error('must provide XML to encrypt'));
  if (!options.key)
    callback(new Error('key option is mandatory and you should provide a valid RSA private key'));
    
  var doc = new xmldom.DOMParser().parseFromString(xml);
  
  var keyInfo = xpath.select("/*/*[local-name(.)='KeyInfo' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']", doc)[0];
  var keyEncryptionMethod = xpath.select("/*/*[local-name(.)='KeyInfo']/*[local-name(.)='EncryptedKey']/*[local-name(.)='EncryptionMethod']", doc)[0];
  var keyEncryptionAlgorighm = keyEncryptionMethod.getAttribute('Algorithm');

  var symmetricKey;
  switch (keyEncryptionAlgorighm) {
    case 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p':
      var encryptedKey = xpath.select("//*[local-name(.)='CipherValue']", keyInfo)[0];
      var key = new Buffer(encryptedKey.textContent, 'base64');
      var pk = ursa.createPrivateKey(options.key);
      symmetricKey = pk.decrypt(key);
      break;
    default:
      throw new Error('key encryption algorithm ' + keyEncryptionAlgorighm + ' not supported');
  }
  
  var encryptionMethod = xpath.select("/*[local-name(.)='EncryptedData']/*[local-name(.)='EncryptionMethod']", doc)[0];
  var encryptionAlgorithm = encryptionMethod.getAttribute('Algorithm');

  var decrypted;
  switch (encryptionAlgorithm) {
    case 'http://www.w3.org/2001/04/xmlenc#aes256-cbc':
      var encryptedContent = xpath.select("/*[local-name(.)='EncryptedData']/*[local-name(.)='CipherData']/*[local-name(.)='CipherValue']", doc)[0];
      
      var encrypted = new Buffer(encryptedContent.textContent, 'base64');

      var decipher = crypto.createDecipheriv('aes-256-cbc', symmetricKey, encrypted.slice(0, 16)); 
      decrypted = decipher.update(encrypted.slice(16), null, 'binary') + decipher.final();
      break;  
    default:
      throw new Error('encryption algorithm ' + encryptionAlgorithm + ' not supported');
  }
  
  callback(null, decrypted);
};

function encrypt_aes256cbc(symmetricKey, content, encoding, callback) {
  // create a random iv for aes-256-cbc
  crypto.randomBytes(16, function(err, iv) {
      if (err) return callback(err);
      
      var cipher = crypto.createCipheriv('aes-256-cbc', symmetricKey, iv); 
      // encrypted content
      var encrypted = cipher.update(content, encoding, 'binary') + cipher.final();
      return callback(null, Buffer.concat([iv, new Buffer(encrypted, 'binary')]));
  });
}