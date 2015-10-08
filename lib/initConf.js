var nconf = require('nconf');

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
     .env()
     .defaults({
        PORT:                                 4000,
        SESSION_SECRET:                       'a1b2c3d4567',
        AUTHENTICATION:                       'FORM',
        LDAP_SEARCH_QUERY:                    '(&(objectCategory=person)(anr={0}))',
        LDAP_SEARCH_ALL_QUERY:                '(objectCategory=person)',
        LDAP_SEARCH_GROUPS:                   '(member:1.2.840.113556.1.4.1941:={0})',
        LDAP_USER_BY_NAME:                    '(sAMAccountName={0})',
        WSFED_ISSUER:                         'urn:auth0',
        AGENT_MODE:                           true,
        GROUPS:                               true,
        LDAP_HEARTBEAT_SECONDS:               60,
        GROUPS_TIMEOUT_SECONDS:               20,
        GROUP_PROPERTY:                       'cn',
        GROUPS_CACHE_SECONDS:                 600,
        AUTH_WHEN_PASSWORD_EXPIRED:           false,
        AUTH_WHEN_PASSWORD_CHANGE_REQUIRED:   false
     });
