var ldap = require('ldapjs');
var url = require('url');
var net = require('net');
var WebSocket = require('ws');

function try_tcp (options, callback) {
  var parsed = url.parse(options.LDAP_URL);
  var port = parsed.port || (parsed.protocol === 'ldap:' ? 389 : 636);
  net.connect({
    port: port,
    host: parsed.hostname
  }, function () {
    return callback(null , port);
  }).on('error', function (err) {
    return callback(new Error('Cannot connect to ' + parsed.hostname + ':' + port + '. Verify the hostname, port and your firewall/proxy settings.'), port);
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

function try_socket (socket_url, callback) {
  try {
    var parsed = url.parse(socket_url);
    var port = parsed.port ||
              (parsed.protocol === 'https:' || parsed.protocol === 'wss:' ? 443 : 89);

    var ws = new WebSocket(socket_url);
    ws.on('open', function () {
        try {
          ws.close();
        } catch (e) { }
        return callback(null, port);
    }).on('error', function (err) {
        try {
          ws.close();
        } catch (e) { }
        return callback(new Error('Cannot connect to ' + parsed.hostname + ':' + port + '. Verify the hostname, port and your firewall settings.'), port);
    });
  }
  catch (err) {
    return callback(err, port);
  }
}

module.exports = function(config, callback){
  var missing_required = ['LDAP_URL', 'LDAP_BASE', 'LDAP_BIND_USER', 'LDAP_BIND_PASSWORD']
                          .filter(function (k) {
                            return !config[k];
                          });
  var result = [];

  if (missing_required.length > 0) {
    return callback(new Error(missing_required[0] + ' is required.'));
  }

  if (!config.LDAP_URL.match(/ldaps?\:/)) {
    return callback(new Error('LDAP url must start with ldap:// or ldaps://'));
  }

  try_tcp(config, function (err, port) {
    result.push({
      proof: 'Testing TCP connection to LDAP server on port: ' + port,
      result: err ? 'Not OK' : 'OK'
    });
    if (err){
      return callback(err, result);
    }

    var tlsOptions;

    if (process.platform === 'win32' &&
        config.LDAP_URL.toLowerCase().substr(0, 5) === 'ldaps') {

      var certs = require('windows-certs');

      var cas = certs.get({
        storeLocation: 'LocalMachine',
        storeName: ['TrustedPeople', 'CertificateAuthority', 'Root']
      }).map(function (cert) {
        return cert.pem;
      });

      tlsOptions = { ca: cas };
    }

    var client = ldap.createClient({
      url:            config.LDAP_URL,
      bindDN:         config.LDAP_BIND_USER,
      credentials:    config.LDAP_BIND_PASSWORD,
      tlsOptions:     tlsOptions
    });

    // Handles `unhandled` connection errors to avoid admin console crash  
    client.on('error',function(err){
      return callback(err,result);
    });

    try_connect(client, config, function (err) {
      result.push({
        proof: 'Testing LDAP bind to LDAP server',
        result: err ? 'Not OK' : 'OK'
      });
      if (err) return callback(err, result);

      try_search(client, config, function (err) {
        result.push({
          proof: 'Querying LDAP',
          result: err ? 'Not OK' : 'OK'
        });

        if (err) return callback(err, result);

        try_socket(config.AD_HUB, function (err, port) {
          result.push({
            proof: 'Outbound connection PORT ' + port,
            result: err ? 'Not OK' : 'OK'
          });
          if (err) return callback(err, result);
          callback(null, result);
        });

      });
    });
  });
};
