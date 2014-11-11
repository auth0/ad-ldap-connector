var nconf = require('nconf');
var ldap  = require('ldapjs');
var exit  = require('./exit');
var client, binder;
var crypto = require('./crypto');

ldap.Attribute.settings.guid_format = ldap.GUID_FORMAT_D;

function createConnection () {
  var connection = ldap.createClient({
    url: nconf.get("LDAP_URL")
  });

  connection.on('close', function () {
    console.error('Connection to ldap was closed.');
    exit(1);
  });

  var LDAP_BIND_CREDENTIALS = crypto.decrypt(nconf.get('LDAP_BIND_CREDENTIALS'));

  connection.bind(nconf.get("LDAP_BIND_USER"), LDAP_BIND_CREDENTIALS, function(err) {
    if(err){
      console.error("Error binding to LDAP", 'dn: ' + err.dn + '\n code: ' + err.code + '\n message: ' + err.message);
      return exit(1);
    }

    var ping = setInterval(function () {
      connection.search('', '(objectclass=*)', function (err) {
        if (err) {
          console.error('Error on Heartbeat from LDAP');
          clearInterval(ping);
          return exit(1);
        }
        return undefined;
      });
    }, nconf.get('LDAP_HEARTBEAT_SECONDS') * 1000);
  });

  return connection;
}

Object.defineProperty(module.exports, 'client', {
  enumerable: true,
  configurable: false,
  get: function () {
    client = client || createConnection();
    return client;
  }
});

Object.defineProperty(module.exports, 'binder', {
  enumerable: true,
  configurable: false,
  get: function () {
    binder = binder || createConnection();
    return binder;
  }
});