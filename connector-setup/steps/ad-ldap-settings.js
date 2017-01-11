var dns = require('dns');
var ldap = require('ldapjs');
var net = require('net');


function compareSrvRecords(srv1, srv2) {
  if (srv1.priority < srv2.priority) {
    return -1;
  } else if (srv1.priority > srv2.priority) {
    return 1;
  } else if (srv1.weight > srv1.weight) {
    return -1;
  } else if (srv1.weight < srv1.weight) {
    return 1;
  } else {
    return 0;
  }
}

function buildLdapUrl(srv) {
  return 'ldap://' + srv.name + ':' + srv.port;
};

function getDomainDN(domain) {
  var parts = domain.split('.');
  return 'DC=' + parts.join(',DC=');
}

function tryLdapServers(domain, urls, cb){
  if (!urls && urls.length === 0) return cb();
  var url = urls.shift();
  var client = ldap.createClient({url: url});

  client.bind('anonymous','', function(err) {
    if (!err) return cb({
      LDAP_BASE: getDomainDN(domain),
      LDAP_URL: url
    });

    tryLdapServers(domain, urls, cb);
  });
}

function tryGetDomainSettings(domains, cb) {
  if (!domains || domains.length===0) return cb({});


  if(!Array.isArray(domains)) {
    domains = [domains];
  }
  var domain = domains.shift();

  dns.resolveSrv('_ldap._tcp.' + domain, function(err, addresses) {
    if (!addresses || addresses.length === 0) return tryGetDomainSettings(domains, cb);
    var hostnames = addresses
      .sort(compareSrvRecords)
      .map(buildLdapUrl);

    tryLdapServers(domain, hostnames, function(config) {
      if (!config) return tryGetDomainSettings(domains);
      cb(config);
    });

  });

}

function discover(domains, cb){
  if (!cb) {
    cb = domains;
    domains = null;
  }

  if (!domains) return cb();

  tryGetDomainSettings(domains, cb);
}


module.exports = {
  discoverSettings : discover
}
