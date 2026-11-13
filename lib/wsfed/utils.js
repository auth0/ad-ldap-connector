
exports.escape = function(html) {
  return String(html)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
};

exports.getBaseUrl = function(req) {
  var protocol = req.headers['x-iisnode-https'] && req.headers['x-iisnode-https'] === 'on' ?
                 'https' :
                 (req.headers['x-forwarded-proto'] || req.protocol);
  var host = req.headers['x-forwarded-host'] || req.headers['host'];
  return protocol + '://' + host;
};
