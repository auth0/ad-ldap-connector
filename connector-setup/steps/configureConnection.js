var urlJoin    = require('url-join');
var request    = require('request');
var fs         = require('fs');
var path       = require('path');
var thumbprint = require('@auth0/thumbprint');
var nconf      = require('nconf');
var os         = require('os');

var pemToCert = function(pem) {
  var cert = /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g.exec(pem.toString());
  if (cert.length > 0) {
    return cert[1].replace(/[\n|\r\n]/g, '');
  }

  return null;
};

var getCurrentThumbprint = function (workingPath) {
  if (nconf.get('AUTH_CERT')) {
    return thumbprint.calculate(pemToCert(nconf.get('AUTH_CERT')));
  }

  var cert = pemToCert(fs.readFileSync(path.join(workingPath, 'certs', 'cert.pem')).toString());
  return thumbprint.calculate(cert);
};

module.exports = function (program, workingPath, connectionInfo, ticket, cb) {
  var serverUrl = nconf.get('SERVER_URL') ||
                  ('http://' + os.hostname() + ':' + (nconf.get('PORT') || 4000));

  var signInEndpoint = urlJoin(serverUrl, '/wsfed');
  var pem = nconf.get('AUTH_CERT') || fs.readFileSync(path.join(workingPath, 'certs', 'cert.pem')).toString();
  var cert = pemToCert(pem);

  console.log(('Configuring connection ' + connectionInfo.connectionName + '.').yellow);
  console.log(' > Posting certificates and signInEndpoint: ' + signInEndpoint);

  request.post({
    url: ticket,
    json: {
      certs:          [cert],
      signInEndpoint: signInEndpoint,
      agentMode:      nconf.get('AGENT_MODE'),
      agentVersion:   require('../../package').version
    }
  }, function (err, response, body) {
    if (err) {
      if (err.code === 'ECONNREFUSED') {
        console.log('Unable to reach Auth0 at ' + ticket);
      } else {
        console.log('Unexpected error while configuring connection: ' + (err.code || err.message));
      }
      return cb(err);
    }

    if (response.statusCode !== 200) {
      console.log('Unexpected status while configuring connection: ' + response.statusCode);
      return cb(new Error(body));
    }

    nconf.set('SERVER_URL', serverUrl);
    nconf.set('LAST_SENT_THUMBPRINT', getCurrentThumbprint(workingPath));
    nconf.set('TENANT_SIGNING_KEY', response.body.signingKey || '');

    console.log(('Connection ' + connectionInfo.connectionName + ' configured.').green);
    cb();
  });
};
