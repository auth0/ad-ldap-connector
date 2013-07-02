var nconf = require('nconf');

nconf.env('||')
     .file({ file: __dirname + '/../config.json', logicalSeparator: '||' })
     .defaults({
        PORT:              4000,
        SESSION_SECRET:    'a1b2c3d4567',
        AUTHENTICATION:    'FORM',
        LDAP_SEARCH_QUERY: '(&(objectCategory=person)(|(anr=*{q}*)(mail=*{q}*)(cn=*{q}*)(sn=*{q}*)(givenName=*{q}*)(displayName=*{q}*)(name=*{q}*)(sAMAccountName=*{q}*)(userPrincipalName=*{q}*)))'
     });
