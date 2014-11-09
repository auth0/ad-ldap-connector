var crypto = require('crypto');
var fs = require('fs');

var algorithm = 'aes256'; // or any other algorithm supported by OpenSSL

exports.encrypt = function (text) {
  var key = fs.readFileSync(__dirname + '/../certs/cert.key');
  var cipher = crypto.createCipher(algorithm, key);
  var encrypted = cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
  return encrypted;
};

exports.decrypt = function (encrypted) {
  var key = fs.readFileSync(__dirname + '/../certs/cert.key');
  var decipher = crypto.createDecipher(algorithm, key);
  var decrypted = decipher.update(encrypted, 'hex', 'utf8') + decipher.final('utf8');
  return decrypted;
};