var tls = require('tls');

// Fixes the cert representation when subject is empty and altNames are present
// See https://github.com/nodejs/node/issues/11771 for details
function checkServerIdentity(host, cert) {
  // cert subject should be empty if altnames are defined
  if (cert && !cert.subject && /(IP|DNS|URL)/.test(cert.subjectaltname)) cert.subject = tls.parseCertString("");

  return tls.checkServerIdentity(host, cert);
}

module.exports = {
  checkServerIdentity: checkServerIdentity
};
