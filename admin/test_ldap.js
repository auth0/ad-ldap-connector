var ldap = require('ldapjs');
var url = require('url');
var net = require('net');

ldap.Attribute.settings.guid_format = ldap.GUID_FORMAT_D;

function try_tcp (options, callback) {
  var parsed = url.parse(options.LDAP_URL);
  var port = parsed.port || (parsed.protocol === 'ldap:' ? 389 : 636);
  net.connect({
    port: port,
    host: parsed.hostname
  }, function () {
    return callback();
  }).on('error', function (err) {
    console.log(err);
    return callback(new Error('Cannot connect to ' + parsed.hostname + ':' + port + '. Verify the hostname, port and your firewall settings.'));
  });
}

function try_connect(client, options, callback) {
  client.bind(options.LDAP_BIND_USER, options.LDAP_BIND_PASSWORD, function(err) {
    if(err){
      return callback(new Error("Cannot bind to LDAP."));
    }
    callback();
  });
}

function try_search(client, options, callback) {
  var opts = {
    scope: 'sub',
    filter: '(&(objectclass=user)(|(sAMAccountName=foo)(UserPrincipalName=foo)))'
  };
  client.search(options.LDAP_BASE, opts, function(err){
    if(err){
      return callback(new Error("The provided account cannot execute queries in LDAP."));
    }
    return callback();
  });
}

module.exports = function(options, callback){
  var missing_required = ['LDAP_URL', 'LDAP_BASE', 'LDAP_BIND_USER', 'LDAP_BIND_PASSWORD']
                          .filter(function (k) {
                            return !options[k];
                          });

  if (missing_required.length > 0) {
    return callback(new Error(missing_required[0] + ' is required.'));
  }

  if (!options.LDAP_URL.match(/ldaps?\:/)) {
    return callback(new Error('LDAP url must start with ldap:// or ldaps://'));
  }

  try_tcp(options, function (err) {
    if (err) return callback(err);

    var client = ldap.createClient({
      url:            options.LDAP_URL,
      maxConnections: 10,
      bindDN:         options.LDAP_BIND_USER,
      credentials:    options.LDAP_BIND_PASSWORD
    });

    try_connect(client, options, function (err) {
      if (err) return callback(err);
      try_search(client, options, callback);
    });
  });
};