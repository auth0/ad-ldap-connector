var nconf = require('nconf');
var ldap  = require('ldapjs');

ldap.Attribute.settings.guid_format = ldap.GUID_FORMAT_D;

var Users = module.exports = function(){
  var options = this._options = {
    url:             nconf.get("LDAP_URL"),
    base:            nconf.get("LDAP_BASE"),
    bindDN:          nconf.get("LDAP_BIND_USER"),
    bindCredentials: nconf.get("LDAP_BIND_PASSWORD")
  };

  this._client = ldap.createClient({
    url:            options.url,
    maxConnections: 10,
    bindDN:         options.bindDN,
    credentials:    options.bindCredentials  
  });


  this._client.on('error', function(e){
    console.log('LDAP connection error:', e);
  });

  this._queue = [];

  var self = this;
  this._client.bind(options.bindDN, options.bindCredentials, function(err) {
    if(err){
        return console.log("Error binding to LDAP", 'dn: ' + err.dn + '\n code: ' + err.code + '\n message: ' + err.message);
    }
    self.clientConnected = true;
    self._queue.forEach(function (cb) { cb(); });
  });
};

Users.prototype.list = function (search, callback) {
  var self = this;
  function exec(){
    var opts = { 
      scope:  'sub',
      filter: '(&(objectclass=user)(|(sAMAccountName=*' + search + '*)(name=*' +  search + '*)(mail=*' + search + '*)))' 
    };
    self._client.search(self._options.base, opts, function(err, res){
      var entries = [];
      res.on('searchEntry', function(entry) {
        entries.push(entry);
      });
      res.on('error', function(err) {
        callback(err);
      });
      res.on('end', function() {
        if(entries.length === 0) return callback(null, []);
        var result = entries.map(function (e) { return e.object; });
        callback(null, result);
      });
    });
  }

  if(this.clientConnected){
    exec();
  } else {
    this._queue.push(exec);
  }
};