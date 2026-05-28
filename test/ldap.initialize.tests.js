'use strict';

const { expect } = require('chai');
const proxyquire = require('proxyquire').noCallThru();

describe('lib/ldap initialize()', function () {
  let ldapModule;
  let mockConfig;
  let mockSecureStorage;
  let secureStorageStoreCalls;
  let secureStorageGetCalls;
  let secureStorageGetResult;

  function buildLdapModule() {
    return proxyquire('../lib/ldap', {
      './config': mockConfig,
      './secureStorage': mockSecureStorage,
      // stub modules not under test so the module loads cleanly
      ldapjs: { createClient: function () { return { on: function () {} }; } },
      './exit': function () {},
      cb: function (fn) { return fn; },
      https: { globalAgent: { options: {} } },
      dns: {},
    });
  }

  beforeEach(function () {
    secureStorageStoreCalls = [];
    secureStorageGetCalls = [];
    secureStorageGetResult = 'keychain-password';

    mockConfig = {
      values: {},
      get: function (key) { return this.values[key]; },
      set: function (key, val) { this.values[key] = val; },
      clear: function (key) { delete this.values[key]; },
    };

    mockSecureStorage = {
      keys: {
        LDAP_BIND_PASSWORD: 'ldap-bind-password',
      },
      store: async function (key, value) {
        secureStorageStoreCalls.push({ key, value });
      },
      get: async function (key) {
        secureStorageGetCalls.push({ key });
        return secureStorageGetResult;
      },
    };

    ldapModule = buildLdapModule();
  });

  describe('when neither LDAP_BIND_PASSWORD nor LDAP_BIND_CREDENTIALS is present', function () {
    it('should fetch credentials from secure storage', async function () {
      await ldapModule.initialize();
      expect(secureStorageGetCalls).to.have.length(1);
      expect(secureStorageGetCalls[0].key).to.equal('ldap-bind-password');
    });

    it('should not store anything to secure storage', async function () {
      await ldapModule.initialize();
      expect(secureStorageStoreCalls).to.have.length(0);
    });
  });
});