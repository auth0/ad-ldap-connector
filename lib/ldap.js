var config = require('./config');
var ldap  = require('ldapjs');
var exit  = require('./exit');
var client, binder;
var cb = require('cb');
var https = require('https');
const dns = require('dns');
const secureStorage = require('./secureStorage');

let ldapBindCredentials;

// heartbeat related consts
const HEARTBEAT_QUERY_TIMEOUT_MS = 5000;

function createConnection () {
  // Resolve using IPv4 first. This lets us continue to use localhost
  // Needed for Node 17+. See: https://github.com/node-fetch/node-fetch/issues/1624#issuecomment-1407717012
  if(dns.setDefaultResultOrder) {
    dns.setDefaultResultOrder('ipv4first');
  }

  var clientOpts = {
    url: config.get('LDAP_URL')
  };

  if (config.get('LDAP_URL').toLowerCase().substr(0, 5) === 'ldaps') {
    clientOpts.tlsOptions = { ca: https.globalAgent.options.ca };
  }

  const client = ldap.createClient(clientOpts);
  // Manual promisify because ldapjs client methods have a `_bypass` at the end (wtf.gif)
  client.searchAsync = async function (base, options) {
    return new Promise((resolve, reject) => {
      client.search(base, options, (err, res) => {
        if (err) {
          reject(err);
        }
        resolve(res);
      });
    });
  };
  return client;
}

function initializeConnection () {
  var connection = createConnection();

  connection.on('close', function () {
    console.error('Connection to ldap was closed.');
    exit(1);
  });

  connection.heartbeat = function (callback) {
    // alway re-bind the connection in an heartbeat before searching, underlying connection might be bound to a different users from previous
    // login validations, and the search query might fail randomly otherwise.
    const user = config.get('ANONYMOUS_SEARCH_ENABLED') ? '' : config.get('LDAP_BIND_USER');
    const creds = config.get('ANONYMOUS_SEARCH_ENABLED') ? '' : ldapBindCredentials;
    
    connection.bind(user, creds, function(err) {
      if(err){
        console.error('Heartbeat: Error binding to LDAP', 'dn: ' + err.dn + '\n code: ' + err.code + '\n message: ' + err.message);
        return callback(err);
      }
      
      connection.search(config.get('LDAP_BASE'), config.get('LDAP_HEARTBEAT_SEARCH_QUERY'), function (err, res) {
        if (err) {
          return callback(err);
        }
  
        var abort = setTimeout(function () {
          client.removeAllListeners('end');
          client.removeAllListeners('error');
          callback(new Error(`No heartbeat response within allocated timeout of ${HEARTBEAT_QUERY_TIMEOUT_MS} ms`));
        }, HEARTBEAT_QUERY_TIMEOUT_MS);
  
        res.once('error', function(err) {
          client.removeAllListeners('end');
          clearTimeout(abort);
          callback(err);
        }).once('end', function () {
          client.removeAllListeners('error');
          clearTimeout(abort);
          callback();
        });
      });
    });
  };

  function protect_with_timeout (func) {
    var original = connection[func];
    connection[func] = function () {
      var args = [].slice.call(arguments);
      var original_callback = args.pop();
      var timeoutable_callback = cb(original_callback).timeout(450000);
      var new_args = args.concat([timeoutable_callback]);
      return original.apply(this, new_args);
    };
  }
  protect_with_timeout('bind');
  protect_with_timeout('search');

  function ping_recurse () {
    connection.heartbeat(function (err) {
      if (err) {
        console.error('Error on heartbeat response from LDAP: ', err.message);
        return exit(1);
      }
      setTimeout(ping_recurse, config.get('LDAP_HEARTBEAT_SECONDS') * 1000);
    });
  }

  if (!config.get('ANONYMOUS_SEARCH_ENABLED')) {
    connection.bind(config.get('LDAP_BIND_USER'), ldapBindCredentials, function(err) {
      if(err){
        console.error('Error binding to LDAP', 'dn: ' + err.dn + '\n code: ' + err.code + '\n message: ' + err.message);
        return exit(1);
      }
      ping_recurse();
    });
  } else {
    ping_recurse();
  }

  return connection;
}

module.exports.createConnection = createConnection;

module.exports.initialize = async function () {
  ldapBindCredentials = await secureStorage.get(secureStorage.keys.LDAP_BIND_PASSWORD);
};

module.exports.resetCredentials = function () {
  ldapBindCredentials = null;
};

Object.defineProperty(module.exports, 'client', {
  enumerable: true,
  configurable: false,
  get: function () {
    client = client || initializeConnection();
    return client;
  }
});

Object.defineProperty(module.exports, 'binder', {
  enumerable: true,
  configurable: false,
  get: function () {
    binder = binder || initializeConnection();
    return binder;
  }
});
