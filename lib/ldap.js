var nconf = require('nconf');
var ldap  = require('ldapjs');
var exit  = require('./exit');
var client, binder;
var crypto = require('./crypto');

ldap.Attribute.settings.guid_format = ldap.GUID_FORMAT_D;


function createClient () {
  var LDAP_BIND_CREDENTIALS = crypto.decrypt(nconf.get('LDAP_BIND_CREDENTIALS'));

  var client = ldap.createClient({
    url:            nconf.get("LDAP_URL"),
    bindDN:         nconf.get("LDAP_BIND_USER"),
    credentials:    LDAP_BIND_CREDENTIALS,
    maxConnections: 5,
    checkInterval:  30000,  //check every 30seconds that the connection is not idle
    maxIdleTime:    nconf.get('LDAP_HEARTBEAT_SECONDS') * 1000, //if the connection is idle for more than 5minutes, run the heartbeat
  });

  client.bind(nconf.get("LDAP_BIND_USER"), LDAP_BIND_CREDENTIALS, function(err) {
    if(err){
      console.error("Error binding to LDAP", 'dn: ' + err.dn + '\n code: ' + err.code + '\n message: ' + err.message);
      return exit(1);
    }
  });

  client.on('close', function () {
    console.error('Connection to ldap was closed');
    exit(1);
  });

  return client;
}

function createBinder () {
  var binder = ldap.createClient({
    url: nconf.get("LDAP_URL")
  });

  binder.on('close', function () {
    console.error('Connection to ldap was closed.');
    exit(1);
  });

  var LDAP_BIND_CREDENTIALS = crypto.decrypt(nconf.get('LDAP_BIND_CREDENTIALS'));

  binder.bind(nconf.get("LDAP_BIND_USER"), LDAP_BIND_CREDENTIALS, function(err) {
    if(err){
      console.error("Error binding to LDAP", 'dn: ' + err.dn + '\n code: ' + err.code + '\n message: ' + err.message);
      return exit(1);
    }

    var ping = setInterval(function () {
      binder.search('', '(objectclass=*)', function (err) {
        if (err) {
          console.error('Error on Heartbeat from LDAP');
          clearInterval(ping);
          return exit(1);
        }
        return undefined;
      });
    }, nconf.get('LDAP_HEARTBEAT_SECONDS') * 1000);
  });

  return binder;
}

Object.defineProperty(module.exports, 'client', {
  enumerable: true,
  configurable: false,
  get: function () {
    client = client || createClient();
    return client;
  }
});

Object.defineProperty(module.exports, 'binder', {
  enumerable: true,
  configurable: false,
  get: function () {
    binder = binder || createBinder();
    return binder;
  }
});