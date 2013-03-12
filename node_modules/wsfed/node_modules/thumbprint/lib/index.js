var crypto = require('crypto');

module.exports.calculate = function (cert) {
	var shasum = crypto.createHash('sha1');
	var der = new Buffer(cert, 'base64').toString('binary')
	shasum.update(der);
	return shasum.digest('hex');
}
