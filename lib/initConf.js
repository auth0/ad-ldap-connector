var nconf = require('nconf');
var defaults = {
  PORT:                                 4000,
  SESSION_SECRET:                       'a1b2c3d4567',
  AUTHENTICATION:                       'FORM',
  LDAP_SEARCH_QUERY:                    '(&(objectCategory=person)(anr={0}))',
  LDAP_SEARCH_ALL_QUERY:                '(objectCategory=person)',
  LDAP_SEARCH_LIST_GROUPS_QUERY:        '(objectCategory=group)',
  LDAP_SEARCH_GROUPS:                   '(member:1.2.840.113556.1.4.1941:={0})',
  LDAP_USER_BY_NAME:                    '(sAMAccountName={0})',
  LDAP_NUMBER_OF_PARALLEL_BINDS:        1,
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
  OVERRIDE_CONFIG:                      true,
  CACHE_FILE:                           __dirname + '/../cache.db',
  SSL_ENABLE_EMPTY_SUBJECT:             true,
  SSL_CA_FILE:                          '.+.(pem|crt|cer)$',
  SSL_CA_PATH:                          false,
  SSL_OPENSSLDIR_PATTERN:               'OPENSSLDIR\\s*\\:\\s*\\"([^\\"]*)\\"',
  ENABLE_WRITE_BACK:                    false,
  ENABLE_ACTIVE_DIRECTORY_UNICODE_PASSWORD: false
};

if (process.env.OVERRIDE_CONFIG === 'false') {
  nconf.use('memory')
       .overrides({ OVERRIDE_CONFIG: false })
       .env('||')
       .defaults(defaults);
} else {
  nconf.env('||')
       .file({
          file: __dirname + '/../config.json',
          logicalSeparator: '||',
          format: {
              parse: function (content) {
                  return JSON.parse(content);
              },
              stringify: function (content){
                  var result = JSON.stringify(content, null, 2);
                  if (process.platform === 'win32') {
                      result = result.replace(/\n/ig, "\r\n");
                  }
                  return result;
              }
          }
       })
       .defaults(defaults);
}
