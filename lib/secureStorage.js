const keychain = require('cross-keychain');

const keys = Object.freeze({
  ADMIN_CONSOLE_PASSWORD: 'admin-console-password',
  ADMIN_CONSOLE_SESSION_SECRET: 'admin-console-session-secret',
  CONNECTOR_SESSION_SECRET: 'connector-session-secret',
  LDAP_BIND_PASSWORD: 'ldap-bind-password',
  CUSTOM_SSL_PFX_PASSWORD: 'custom-ssl-pfx-password'
});

class SecureStorage {
  #keychain;

  constructor({ keychainModule = keychain } = {}) {
    this.#keychain = keychainModule;
  }

  async store(key, value) {
    await this.#keychain.setPassword('auth0-ad-ldap-connector', key, value);
  }

  async get(key) {
    return await this.#keychain.getPassword('auth0-ad-ldap-connector', key);
  }

  async clear(key) {
    await this.#keychain.deletePassword('auth0-ad-ldap-connector', key);
  }
}

const secureStorage = new SecureStorage();

module.exports = secureStorage;
module.exports.keys = keys;
module.exports.SecureStorage = SecureStorage;
