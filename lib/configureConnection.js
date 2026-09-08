const axios = require('axios');
const urlJoin = require('url-join');
const os = require('os');

const thumbprint = require('@auth0/thumbprint');
const config = require('./config');
const certificates = require('./certificates');

function pemToCert (pem) {
  var cert =
    /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g.exec(
      pem.toString()
    );
  if (cert && cert.length > 0) {
    return cert[1].replace(/[\n|\r\n]/g, '');
  }
  return null;
}

async function configureConnection({ provisioningTicket, connectionName }) {
  const serverUrl = config.get('SERVER_URL') || 'http://' + os.hostname() + ':' + (config.get('PORT') || 4000);
  const signInEndpoint = urlJoin(serverUrl, '/wsfed');
  const pem = certificates.getCertificate();
  const cert = pemToCert(pem);
  const certThumbprint = thumbprint.calculate(cert);

  console.log(' > Posting certificates and signInEndpoint: ' + signInEndpoint);

  try {
    const response = await axios.post(provisioningTicket, {
      certs: [cert],
      signInEndpoint: signInEndpoint,
      agentMode: config.get('AGENT_MODE'),
      agentVersion: require('../package').version,
    });
    console.log(('Connection ' + connectionName + ' configured.').green);

    return {
      serverUrl,
      certThumbprint,
      tenantSigningKey: response.data.signingKey || ''
    };
  } catch (err) {
    if (err.response && err.response.status !== 200) {
      throw new Error('Unexpected status while configuring connection: ' + err.response.status);
    }

    if (err.code === 'ECONNREFUSED') {
      throw new Error('Unable to reach Auth0 at ' + provisioningTicket);
    }

    throw new Error('Unexpected error while configuring connection: ' + (err.code || err.message));
  }
}

module.exports = { configureConnection };
