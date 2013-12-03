var ejs = require('ejs'),
    path = require('path'),
    fs = require('fs');

var templates = {
  'encrypted-key': fs.readFileSync(path.join(__dirname, 'templates', 'encrypted-key.tpl.xml'), 'utf8'),
  'keyinfo': fs.readFileSync(path.join(__dirname, 'templates', 'keyinfo.tpl.xml'), 'utf8')
};

function renderTemplate (file, data) {
  return ejs.render(templates[file], data);
}

function pemToCert(pem) {
  var cert = /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g.exec(pem);
  if (cert.length > 0) {
    return cert[1].replace(/[\n|\r\n]/g, '');
  }

  return null;
};


module.exports = {
  renderTemplate: renderTemplate,
  pemToCert: pemToCert
};