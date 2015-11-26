var selfsigned  = require('selfsigned');
var fs          = require('fs');
var path        = require('path');

var fileNames = {
  pem: path.join(process.cwd(), 'certs', 'cert.pem'),
  key: path.join(process.cwd(), 'certs', 'cert.key')
};

module.exports = function (workingPath, info, cb) {
  if (fs.existsSync(fileNames.key)) {
    console.log('Certificates already exist, skipping certificate generation.');
    return cb();
  }

  // ensure certs folder
  var certs_folder = path.dirname(fileNames.key);
  if (!fs.existsSync(certs_folder)) {
    fs.mkdirSync(certs_folder);
  }

  console.log('Generating a self-signed certificate.'.yellow);

  var selfsigned = require('selfsigned');
  var pems = selfsigned.generate({ subj: '/CN=' + info.connectionDomain , days: 365 });

  fs.writeFileSync(fileNames.pem, pems.cert);
  fs.writeFileSync(fileNames.key, pems.private);

  console.log('Certificate generated.\n'.green);
  cb();
};
