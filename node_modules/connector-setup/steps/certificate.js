var selfsigned = require('selfsigned');
var fs = require('fs');
var path = require('path');

var fileNames = {
  pem: path.join(process.cwd(), 'certs', 'cert.pem'),
  key: path.join(process.cwd(), 'certs', 'cert.key')
};

module.exports = function (workingPath, info, cb) {
  if (fs.existsSync(fileNames.key)) return cb();

  console.log('Generating a self-signed certificate.'.yellow);
  selfsigned.generate({subj: '/CN=' + info.connectionDomain }, function (err, selfSigned) {
    if (err) return cb(err);
    fs.writeFileSync(fileNames.pem, selfSigned.publicKey);
    fs.writeFileSync(fileNames.key, selfSigned.privateKey);
    console.log('Certificate generated.\n'.green);
    cb();
  });
};