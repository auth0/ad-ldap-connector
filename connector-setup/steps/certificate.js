var selfsigned  = require('selfsigned');
var fs          = require('fs');
var path        = require('path');
var nconf = require('nconf');

function getFileNames(workingPath) {
  return {
    pem: path.join(workingPath, 'certs', 'cert.pem'),
    key: path.join(workingPath, 'certs', 'cert.key')
  };
};

module.exports = function (workingPath, info, cb) {
  let fileNames = getFileNames(workingPath);
  if (fs.existsSync(fileNames.key) || nconf.get('AUTH_CERT')) {
    console.log('Certificates already exist, skipping certificate generation.');
    return cb();
  }

  // ensure certs folder
  var certs_folder = path.dirname(fileNames.key);
  if (!fs.existsSync(certs_folder)) {
    fs.mkdirSync(certs_folder);
  }

  console.log('Generating a self-signed certificate.'.yellow);
  var pems = selfsigned.generate([
        { shortName: 'CN', value: info.connectionName},
        { shortName: 'OU', value: info.connectionDomain},
        { shortName: 'O', value: 'auth0/ad-ldap-connector'}
      ], {
        days: 365,
        algorithm: 'sha256',
        keySize:2048
      });

  fs.writeFileSync(fileNames.pem, pems.cert);
  fs.writeFileSync(fileNames.key, pems.private);

  console.log('Certificate generated.\n'.green);
  cb();
};
