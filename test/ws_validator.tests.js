const { expect } = require('chai');
const proxyquire = require('proxyquire').noCallThru();
var jwt = require('jsonwebtoken');


let mockWebSocketInstance;

class MockWebSocket {

  constructor () {
    this.handlers = {};
    mockWebSocketInstance = this;
  }

  getHandlers (eventType) {
    this.handlers[eventType] = this.handlers[eventType] || [];

    return this.handlers[eventType];
  }

  on (eventType, handler) {
    this.getHandlers(eventType).push(handler);

    return this;
  }

  emit (eventType, event) {
    this.getHandlers(eventType).forEach((handler) => handler(event));
  }

  send (event) {
    this.emit('send', event)
  }

  reply () {}

  // mock terminate()
  terminate() {
    this.emit('mockTerminated')
  }

  // mock removeAllListeners()
  removeAllListeners() {

  }
}

class MockUsers {
  validate (username, password, options, callback) {
    callback(null, { username });
  }
}

// Records the calls ws_validator makes into the signing key module.
const mockSigningKeys = {
  refreshOnReconnectCalls: 0,
  verifyCalls: [],
  refreshOnReconnect: async function () {
    this.refreshOnReconnectCalls++;
    return true;
  },
  verify: function (token, callback) {
    this.verifyCalls.push(token);
    callback(null, { username: 'jsmith', pid: 'a-pid' });
  }
};

const mockConfig = {
  values: {},
  get: (key) => mockConfig.values[key],
  set: (key, value) => {
    mockConfig.values[key] = value;
  },
}

const cert = `-----BEGIN CERTIFICATE-----
MIIC1TCCAb2gAwIBAgIJAIbNqgTtQOiBMA0GCSqGSIb3DQEBBQUAMBoxGDAWBgNV
BAMTD3d3dy5leGFtcGxlLmNvbTAeFw0yMDA5MDgxNjE3MjVaFw0zMDA5MDYxNjE3
MjVaMBoxGDAWBgNVBAMTD3d3dy5leGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBALQXH/0vWagNLdXH30J7YjjbiLCrRTFX20JG878DXxM5
MhxU5UOqH53MrDl5M47ZMpKq2Vih0E62FxtkjlOhO1RotqUWhmM/z7fpk1Cf1GjG
jb4e9xRxSTP40ZDjrnGxBPTmyy6KxC1OnsdraxxaGg5p+63icaKtTx/Ofj2efmH4
OggY7MSb04jDvSmanTi9eTfCW0uiwMdiwtmFEoDrgEB5Xy1yOEo/+3i02M7Aub2H
RV5Utd22VGPjWsUlJ30PjzxrXCygGIQFmXUMgKR3QVJzT5XXEJa4wILcfqWCuPB1
8sepoxAGzIUMCDV7ReIiZCoPGcPb19e18tloLIJcpdkCAwEAAaMeMBwwGgYDVR0R
BBMwEYIPd3d3LmV4YW1wbGUuY29tMA0GCSqGSIb3DQEBBQUAA4IBAQBaWbAZ85s/
YLMbiXNnQCkSWKazCSyFax/mD9ymx1asiDHScNn2NwTwDoQaMzeDuQL36Cggt/Ty
ClJqvmkS2992sfmDQzWzMTD5zrSU4tODAT1S+riPl/gvELj6BAZ+phLLbR6cxQi8
C6uhavQZOgzIw3kD4XrrCOzexKqs2LxhxPgJ3ZqtQLFbmWhdj0yF3XiITPpyFNzR
xm+DIK8LwSOcoCLDkoyAV86uX8wJ2Xwg7CMVUZ57fXg8YOgNbcOJKEz4AHedxwN7
OB/Jb61nFebraXicZQEnI9/6jukU04M5nBuGMelHCtu+kS3eWGLwzuW99arJXyrJ
9NS1m6MEVq5Z
-----END CERTIFICATE-----
`;

const key = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAtBcf/S9ZqA0t1cffQntiONuIsKtFMVfbQkbzvwNfEzkyHFTl
Q6ofncysOXkzjtkykqrZWKHQTrYXG2SOU6E7VGi2pRaGYz/Pt+mTUJ/UaMaNvh73
FHFJM/jRkOOucbEE9ObLLorELU6ex2trHFoaDmn7reJxoq1PH85+PZ5+Yfg6CBjs
xJvTiMO9KZqdOL15N8JbS6LAx2LC2YUSgOuAQHlfLXI4Sj/7eLTYzsC5vYdFXlS1
3bZUY+NaxSUnfQ+PPGtcLKAYhAWZdQyApHdBUnNPldcQlrjAgtx+pYK48HXyx6mj
EAbMhQwINXtF4iJkKg8Zw9vX17Xy2Wgsglyl2QIDAQABAoIBAF959xqq1NSUkB1L
xuCfO1a7hP9s/dUIKBU+OpGlPu2ZICkHFTlHY1Wsog4iZKQyIG7Dp1EnEKH6Rcvf
Btntm9/HWDWz+HF77isp6VEQO3OE+La4AfRTjyS/oJM5Mk3SNLeF+GhnZ1RB30oI
eBPi7PeBVs48RFSjn1RUjHcspQJYzPHEGEonE6vKi8MDcXxS12eVKMwmSYedyVNR
1wjWVoIqsry6BEo/TEaL+TT+UgarWeIXz//707MZyBH7JxhCUv6bOxUYyAz97vmS
X8JZ5T7LcT/t4uTckdMr6//iXU1+L9YqryGiILwEVPGZEQOxiFausPA512aD38v1
4xWTK8UCgYEA2coUP8S7kAyVh4SkgTaWXfFevWsQY6ulD88z3mO0eK82v8n880jB
n2Lqx5vutmlAKOAaxyO/2AS8ZjlrwJQFGjnoswzA+vVjrPow+WcuxhsYP7Ufl/Vs
tWbQdTQ7c1TiuTJmjp7+u7DOfCA0QDx8yDYHWxe4VwMcXWyMZe+eXgMCgYEA06/P
EOhGE1JX9bGUyEIpyl07qEz2FYlhoxZ+x3nQFO/CoIM+zE1Gsr+PZ74uexh4HnMe
HiXtSv362W71QkBr/gotxOviWVIGE6bTtVuGGGCTDQYOeTTlZw5rC6lj4V4ZvU4R
o3sb5cjKRK5ARp6bQchQ3gf1vHbTZ7r2FhtlI/MCgYBNrOMX80SqFbLnCInbg+qR
StrtV9galEdkohPvx0PAn005jgLnihV0kUUHODglWtiFO5iRWdC8bMP8+ZHSt3gy
aGD0KyJQ32BTe1AoQ4LNKTC22BSSj/fbovXKN3zUn3vVbYJib5aOvnqGjr3UAz7F
8W8iMA2RCwz8zRAt8w5anQKBgBR40iuuauh/dCY8sEjVrTj230gdeUcH7Dtbd5NP
AoKj1Uy0pKQZbRboU7QSvmgFK8i2FVmRDWvNOC9C/dEUbd05mseKkG9W8WOBJMRL
P6Kn5FDEHy41oWHgERYloZUwBok6PZZz13TXgEg4Gds6h4VLHBb86hT54OQNPrNQ
nu1lAoGAC+EHr+9hBFNz6fQWuQivMMqmUYTkNHPgFupf5xTRyq7euMms/1RAcjaE
ifQQICxPn+sIprdshYSGD2xLa7LuY9KwI2WpenLxVFSEXizEwCwa+NquUa4C+fhk
xg2fno4Ifa9Qc7w5ywI7LpbyRXNfAbvcgUWlCGDbekS+SzgosEc=
-----END RSA PRIVATE KEY-----
`;

describe('ws_validator', () => {
  mockConfig.set('LDAP_URL', 'ldap://ds.example.com:389/dc=example,dc=com');
  mockConfig.set('LDAP_BIND_PASSWORD', 'abc123');
  mockConfig.set('AUTH_CERT_KEY', key);
  mockConfig.set('AUTH_CERT', cert);
  mockConfig.set('AD_HUB', 'http://test.io');
  mockConfig.set('CONNECTION', 'test-ad');
  mockConfig.set('REALM', 'urn:auth0:example');
  mockConfig.set('WS_RECONNECT_INTERVAL_MS', 1000);

  const wsValidator = proxyquire('../ws_validator', {
    'ws': MockWebSocket,
    './lib/config': mockConfig,
    './lib/users': MockUsers,
    './lib/signingKeys': mockSigningKeys,
    // ws_validator reads the connector's own key from disk via lib/certificates, so the in-memory
    // config above is not enough to let it sign the authenticate token.
    './lib/certificates': {
      getPrivateKey: () => key,
      getCertificate: () => cert,
    },
  });
  
  it('authenticate_connector', () => {
    const testStart = Math.floor(Date.now() / 1000);

    let authenticationEvent;

    mockWebSocketInstance.on('send', (event) => {
      authenticationEvent = JSON.parse(event);
    });

    mockWebSocketInstance.emit('open');

    expect(authenticationEvent).to.be.ok;
    expect(authenticationEvent.n).to.equal('authenticate');
    expect(authenticationEvent.p).to.be.ok;
    expect(authenticationEvent.p.jwt).to.be.ok;
    expect(authenticationEvent.p.jwt).to.be.ok;

    const decoded = jwt.decode(authenticationEvent.p.jwt)
    expect(decoded).to.be.ok;
    expect(decoded.exp).to.be.ok;
    expect(decoded.exp - testStart).to.equal(60);
  });

  it('re-fetches the tenant signing key on the initial connect', () => {
    // reconnect() runs at module load, so by now the refresh has already been requested.
    expect(mockSigningKeys.refreshOnReconnectCalls).to.be.at.least(1);
  });

  it('verifies hub messages through the signing key module', () => {
    const before = mockSigningKeys.verifyCalls.length;

    mockWebSocketInstance.emit('authenticate_user', { jwt: 'a-hub-token' });

    expect(mockSigningKeys.verifyCalls.length).to.equal(before + 1);
    expect(mockSigningKeys.verifyCalls[before]).to.equal('a-hub-token');
  });

  it('terminate socket on error', (done) => {
    mockWebSocketInstance.on('mockTerminated', () => {
      // terminate has been called on socket by the reconnection timer, all good.
      done();
    });

    // trigger error
    mockWebSocketInstance.emit('error', new Error('test'));
  });

  it('re-fetches the tenant signing key on reconnect', (done) => {
    const before = mockSigningKeys.refreshOnReconnectCalls;

    // The reconnection timer rebuilds the socket after WS_RECONNECT_INTERVAL_MS, which must
    // refresh the signing key before connecting again.
    setTimeout(() => {
      expect(mockSigningKeys.refreshOnReconnectCalls).to.be.above(before);
      done();
    }, 2500);
  });

});
