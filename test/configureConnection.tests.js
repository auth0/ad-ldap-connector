const { expect } = require('chai');
const proxyquire = require('proxyquire').noCallThru();

const FAKE_PEM = [
  '-----BEGIN CERTIFICATE-----',
  'MIIFAKECERTDATA',
  '-----END CERTIFICATE-----',
].join('\n');

// pemToCert strips newlines from the captured block, so the expected cert body is:
const FAKE_CERT = '\nMIIFAKECERTDATA\n'.replace(/[\n|\r\n]/g, '');
const FAKE_THUMBPRINT = 'aa:bb:cc:dd:ee';
const FAKE_SIGNING_KEY = 'tenant-signing-key-value';
const PROVISIONING_TICKET = 'https://auth0.example.com/provision/ticket-abc';
const CONNECTION_NAME = 'my-ldap-connection';

function makeStubs({
  serverUrl = 'https://myconnector.example.com',
  port = 4000,
  agentMode = true,
  certPem = FAKE_PEM,
  thumbprintResult = FAKE_THUMBPRINT,
  hostname = 'myhost',
  axiosResponse = { data: { signingKey: FAKE_SIGNING_KEY } },
  axiosError = null,
} = {}) {
  const configStub = {
    get: (key) => {
      if (key === 'SERVER_URL') return serverUrl;
      if (key === 'PORT') return port;
      if (key === 'AGENT_MODE') return agentMode;
      return null;
    },
  };

  const certificatesStub = {
    getCertificate: () => certPem,
  };

  const thumbprintStub = {
    calculate: () => thumbprintResult,
  };

  const osStub = {
    hostname: () => hostname,
  };

  const axiosCalls = [];
  const axiosStub = {
    post: async (url, body) => {
      axiosCalls.push({ url, body });
      if (axiosError) throw axiosError;
      return axiosResponse;
    },
    _calls: axiosCalls,
  };

  const packageStub = { version: '1.2.3' };

  return { configStub, certificatesStub, thumbprintStub, osStub, axiosStub, packageStub };
}

function loadModule(stubs) {
  const { configStub, certificatesStub, thumbprintStub, osStub, axiosStub, packageStub } = stubs;
  return proxyquire('../lib/configureConnection', {
    axios: axiosStub,
    './config': configStub,
    './certificates': certificatesStub,
    '@auth0/thumbprint': thumbprintStub,
    os: osStub,
    '../package': packageStub,
  });
}

describe('configureConnection', function () {
  describe('successful configuration', function () {
    it('returns serverUrl from config', async function () {
      const stubs = makeStubs({ serverUrl: 'https://myconnector.example.com' });
      const { configureConnection } = loadModule(stubs);

      const result = await configureConnection({ provisioningTicket: PROVISIONING_TICKET, connectionName: CONNECTION_NAME });

      expect(result.serverUrl).to.equal('https://myconnector.example.com');
    });

    it('builds serverUrl from hostname and PORT when SERVER_URL is not set', async function () {
      const stubs = makeStubs({ serverUrl: null, port: 4000, hostname: 'my-machine' });
      const { configureConnection } = loadModule(stubs);

      const result = await configureConnection({ provisioningTicket: PROVISIONING_TICKET, connectionName: CONNECTION_NAME });

      expect(result.serverUrl).to.equal('http://my-machine:4000');
    });

    it('defaults to port 4000 when SERVER_URL and PORT are both absent', async function () {
      const stubs = makeStubs({ serverUrl: null, port: null, hostname: 'my-machine' });
      const { configureConnection } = loadModule(stubs);

      const result = await configureConnection({ provisioningTicket: PROVISIONING_TICKET, connectionName: CONNECTION_NAME });

      expect(result.serverUrl).to.equal('http://my-machine:4000');
    });

    it('returns certThumbprint computed from the certificate', async function () {
      const stubs = makeStubs({ thumbprintResult: 'aa:bb:cc' });
      const { configureConnection } = loadModule(stubs);

      const result = await configureConnection({ provisioningTicket: PROVISIONING_TICKET, connectionName: CONNECTION_NAME });

      expect(result.certThumbprint).to.equal('aa:bb:cc');
    });

    it('returns tenantSigningKey from response data', async function () {
      const stubs = makeStubs({ axiosResponse: { data: { signingKey: 'my-signing-key' } } });
      const { configureConnection } = loadModule(stubs);

      const result = await configureConnection({ provisioningTicket: PROVISIONING_TICKET, connectionName: CONNECTION_NAME });

      expect(result.tenantSigningKey).to.equal('my-signing-key');
    });

    it('returns empty string for tenantSigningKey when response omits signingKey', async function () {
      const stubs = makeStubs({ axiosResponse: { data: {} } });
      const { configureConnection } = loadModule(stubs);

      const result = await configureConnection({ provisioningTicket: PROVISIONING_TICKET, connectionName: CONNECTION_NAME });

      expect(result.tenantSigningKey).to.equal('');
    });

    it('posts to the provisioning ticket URL', async function () {
      const stubs = makeStubs();
      const { configureConnection } = loadModule(stubs);

      await configureConnection({ provisioningTicket: PROVISIONING_TICKET, connectionName: CONNECTION_NAME });

      expect(stubs.axiosStub._calls[0].url).to.equal(PROVISIONING_TICKET);
    });

    it('posts the cert body extracted from the PEM', async function () {
      const stubs = makeStubs();
      const { configureConnection } = loadModule(stubs);

      await configureConnection({ provisioningTicket: PROVISIONING_TICKET, connectionName: CONNECTION_NAME });

      expect(stubs.axiosStub._calls[0].body.certs).to.deep.equal([FAKE_CERT]);
    });

    it('posts the signInEndpoint as serverUrl + /wsfed', async function () {
      const stubs = makeStubs({ serverUrl: 'https://myconnector.example.com' });
      const { configureConnection } = loadModule(stubs);

      await configureConnection({ provisioningTicket: PROVISIONING_TICKET, connectionName: CONNECTION_NAME });

      expect(stubs.axiosStub._calls[0].body.signInEndpoint).to.equal('https://myconnector.example.com/wsfed');
    });

    it('posts agentMode from config', async function () {
      const stubs = makeStubs({ agentMode: true });
      const { configureConnection } = loadModule(stubs);

      await configureConnection({ provisioningTicket: PROVISIONING_TICKET, connectionName: CONNECTION_NAME });

      expect(stubs.axiosStub._calls[0].body.agentMode).to.be.true;
    });

    it('posts agentVersion from package.json', async function () {
      const stubs = makeStubs();
      const { configureConnection } = loadModule(stubs);

      await configureConnection({ provisioningTicket: PROVISIONING_TICKET, connectionName: CONNECTION_NAME });

      expect(stubs.axiosStub._calls[0].body.agentVersion).to.equal('1.2.3');
    });

    it('reports the useJWKS capability regardless of the response', async function () {
      // Reported unconditionally so auth0-server can, depending on the tenant's deprecation status,
      // choose to stop sending a signing key down and let the connector read it from the JWKS
      // endpoint. The connector cannot inspect deprecation status itself.
      const withKey = makeStubs({ axiosResponse: { data: { signingKey: FAKE_SIGNING_KEY } } });
      await loadModule(withKey).configureConnection({ provisioningTicket: PROVISIONING_TICKET, connectionName: CONNECTION_NAME });
      expect(withKey.axiosStub._calls[0].body.capabilities).to.deep.equal({ useJWKS: true });

      const withoutKey = makeStubs({ axiosResponse: { data: {} } });
      await loadModule(withoutKey).configureConnection({ provisioningTicket: PROVISIONING_TICKET, connectionName: CONNECTION_NAME });
      expect(withoutKey.axiosStub._calls[0].body.capabilities).to.deep.equal({ useJWKS: true });
    });
  });

  describe('error handling', function () {
    it('throws with status message when axios response has non-200 status', async function () {
      const err = Object.assign(new Error('Bad Request'), { response: { status: 400 } });
      const stubs = makeStubs({ axiosError: err });
      const { configureConnection } = loadModule(stubs);

      try {
        await configureConnection({ provisioningTicket: PROVISIONING_TICKET, connectionName: CONNECTION_NAME });
        expect.fail('should have thrown');
      } catch (e) {
        expect(e.message).to.equal('Unexpected status while configuring connection: 400');
      }
    });

    it('throws with ECONNREFUSED message when Auth0 is unreachable', async function () {
      const err = Object.assign(new Error('ECONNREFUSED'), { code: 'ECONNREFUSED' });
      const stubs = makeStubs({ axiosError: err });
      const { configureConnection } = loadModule(stubs);

      try {
        await configureConnection({ provisioningTicket: PROVISIONING_TICKET, connectionName: CONNECTION_NAME });
        expect.fail('should have thrown');
      } catch (e) {
        expect(e.message).to.equal('Unable to reach Auth0 at ' + PROVISIONING_TICKET);
      }
    });

    it('throws a generic error message for other error codes', async function () {
      const err = Object.assign(new Error('something broke'), { code: 'ETIMEDOUT' });
      const stubs = makeStubs({ axiosError: err });
      const { configureConnection } = loadModule(stubs);

      try {
        await configureConnection({ provisioningTicket: PROVISIONING_TICKET, connectionName: CONNECTION_NAME });
        expect.fail('should have thrown');
      } catch (e) {
        expect(e.message).to.equal('Unexpected error while configuring connection: ETIMEDOUT');
      }
    });

    it('falls back to error message when code is absent', async function () {
      const err = new Error('network failure');
      const stubs = makeStubs({ axiosError: err });
      const { configureConnection } = loadModule(stubs);

      try {
        await configureConnection({ provisioningTicket: PROVISIONING_TICKET, connectionName: CONNECTION_NAME });
        expect.fail('should have thrown');
      } catch (e) {
        expect(e.message).to.equal('Unexpected error while configuring connection: network failure');
      }
    });
  });
});
