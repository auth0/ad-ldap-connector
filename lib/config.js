const fs = require('fs');
const nconf = require('nconf');
const process = require('node:process');

const defaults = {
  PORT:                                 4000,
  LDAP_SEARCH_QUERY:                    '(&(objectCategory=person)(anr={0}))',
  LDAP_SEARCH_RESULTS_OMIT_GROUPS:      true,
  LDAP_SEARCH_ALL_QUERY:                '(objectCategory=person)',
  LDAP_SEARCH_LIST_GROUPS_QUERY:        '(objectCategory=group)',
  LDAP_SEARCH_GROUPS:                   '(member:1.2.840.113556.1.4.1941:={0})',
  LDAP_USER_BY_NAME:                    '(sAMAccountName={0})',
  LDAP_NUMBER_OF_PARALLEL_BINDS:        1,
  LDAP_HEARTBEAT_SEARCH_QUERY:          '(&(objectclass=user)(|(sAMAccountName=foo)(UserPrincipalName=foo)))',
  WSFED_ISSUER:                         'urn:auth0',
  AGENT_MODE:                           true,
  GROUPS:                               true,
  LDAP_HEARTBEAT_SECONDS:               60,
  GROUPS_TIMEOUT_SECONDS:               20,
  GROUP_PROPERTY:                       'cn',
  GROUP_PROPERTIES:                     [],
  GROUPS_CACHE_SECONDS:                 600,
  GROUPS_DEREF_ALIASES:			0,
  ALLOW_PASSWORD_EXPIRED:               false,
  ALLOW_PASSWORD_CHANGE_REQUIRED:       false,
  SSL_CA_FILE:                          '.+.(pem|crt|cer)$',
  SSL_CA_PATH:                          false,
  SSL_OPENSSLDIR_PATTERN:               'OPENSSLDIR\\s*\\:\\s*\\"([^\\"]*)\\"',
  ENABLE_WRITE_BACK:                    false,
  ENABLE_ACTIVE_DIRECTORY_UNICODE_PASSWORD: false,
  PROFILE_MAPPING_MEMORY_LIMIT_MB: 16,
  PROFILE_MAPPING_TIMEOUT_MS: 10000,
};
const CONFIG_ALLOW_LIST = [
  'ANONYMOUS_SEARCH_ENABLED',
  'LDAP_URL',
  'LDAP_BASE',
  'LDAP_BIND_USER',
  'LDAP_SEARCH_QUERY',
  'LDAP_SEARCH_RESULTS_OMIT_GROUPS',
  'LDAP_SEARCH_ALL_QUERY',
  'LDAP_SEARCH_LIST_GROUPS_QUERY',
  'LDAP_SEARCH_GROUPS',
  'LDAP_USER_BY_NAME',
  'LDAP_NUMBER_OF_PARALLEL_BINDS',
  'LDAP_HEARTBEAT_SEARCH_QUERY',
  'LDAP_HEARTBEAT_SECONDS',
  'LDAP_BASE_GROUPS',
  'AD_HUB',
  'ALLOW_PASSWORD_EXPIRED',
  'ALLOW_PASSWORD_CHANGE_REQUIRED',
  'WITH_KERBEROS_PROXY_FRONTEND',
  'GROUPS_CACHE_SECONDS',
  'GROUPS',
  'GROUP_PROPERTY',
  'GROUP_PROPERTIES',
  'GROUPS_TIMEOUT_SECONDS',
  'GROUPS_DEREF_ALIASES',
  'WS_RECONNECT_INTERVAL_MS',
  'CONNECTION',
  'REALM',
  'WSFED_ISSUER',
  'MAX_HEADER_SIZE',
  'ENABLE_WRITE_BACK',
  'ENABLE_ACTIVE_DIRECTORY_UNICODE_PASSWORD',
  'SERVER_URL',
  'PORT',
  'HTTP_PROXY',
  'SSL_PFX',
  'SSL_OPENSSLDIR_PATTERN',
  'SSL_CA_PATH',
  'SSL_CA_FILE',
  'CA_CERT',
  'CLIENT_CERT_AUTH', // this is really shouldUseClientCertAuthentication (a boolean)
  'PROVISIONING_TICKET',
  'AGENT_MODE',
  'SITE_NAME',
  'OVERRIDE_CONFIG',
  'TENANT_SIGNING_KEY',
  'KERBEROS_AUTH', // this is really shouldUseKerberosAuthentication (a boolean)
  'KERBEROS_DEBUG_USER',
  'PROFILE_MAPPER',
  'PROFILE_MAPPER_FILE',
  'AUTO_UNLOCK_ON_PASSWORD_CHANGE',
];
const CONFIG_PATH = __dirname + '/../data/config.json';

/**
 * Application configuration class. Handles loading configuration from disk and environment variables, providing
 * defaults, and saving configuration back to disk.
 *
 * Supports two modes - file and memory.
 * When process.env.OVERRIDE_CONFIG is set to false, this will only work with in memory configuration (loading and saving).
 * When process.env.OVERRIDE_CONFIG is set to true or unset, this will load config from CONFIG_PATH and save to it.
 *
 * In both modes, retrieving values will inspect memory (even in file mode). On save however, only variables loaded from
 * the configuration file or explictly at runtime (via set()) will be persisted.
 */
class Config {
  #fs;
  #nconf;
  #process;

  /**
   *
   * @param fsModule node fs module
   * @param nconfModule nconf module
   * @param execFunction function that async calls a shell command and returns the output
   * @param processModule node process module
   */
  constructor({
    fsModule = fs,
    nconfModule = nconf,
    processModule = process
  } = {}) {
    this.#fs = fsModule;
    this.#nconf = nconfModule;
    this.#process = processModule;
  }

  get configPath() {
    return CONFIG_PATH;
  }

  async initialize() {
    if (this.inMemoryMode()) {
      this.#nconf.use('memory')
        .overrides({ OVERRIDE_CONFIG: false })
        .env('||')
        .defaults(defaults);
    } else {
      // load configuration from disk and environment, allowing environment variables to override disk configuration,
      // and both to override defaults
      const self = this;
      this.#nconf.env('||')
        .file({
          file: CONFIG_PATH,
          logicalSeparator: '||',
          format: {
            parse: function (content) {
              return JSON.parse(content);
            },
            stringify: function (content){
              var result = JSON.stringify(content, null, 2);
              if (self.#process.platform === 'win32') {
                result = result.replace(/\n/ig, '\r\n');
              }
              return result;
            }
          }
        })
        .defaults(defaults);
    }
  }

  inMemoryMode() {
    return this.#process.env.OVERRIDE_CONFIG === 'false';
  }

  /**
   * Gets all config values from the file store (config.json). In memory mode, returns from all stores.
   *
   * @return {{}}
   */
  getAll() {
    const fullConfig = {};
    let store = this.#nconf.stores.file;
    if (this.inMemoryMode()) {
      store = this.#nconf;
    }
    for (const key of CONFIG_ALLOW_LIST) {
      if (store.get(key) !== undefined) {
        fullConfig[key] = this.#nconf.get(key);
      }
    }
    return fullConfig;
  }

  get(key) {
    return this.#nconf.get(key);
  }

  set(key, value) {
    this.#nconf.set(key, value);
  }

  clear(key) {
    this.#nconf.clear(key);
  }

  /**
   * Persists the current configuration to disk.
   * Only keys in the allow list will be persisted, and only if OVERRIDE_CONFIG is true.
   * This is a no-op if OVERRIDE_CONFIG is false.
   */
  async save() {
    if (this.inMemoryMode()) {
      return;
    }

    const configToSave = {};
    for (const key of CONFIG_ALLOW_LIST) {
      if (this.#nconf.stores.file.get(key) !== undefined) {
        configToSave[key] = this.#nconf.stores.file.get(key);
      }
    }

    this.#fs.writeFileSync(CONFIG_PATH, JSON.stringify(configToSave, null, 2));
  }
}

const configInstance = new Config();
module.exports = configInstance;
module.exports.Config = Config;
