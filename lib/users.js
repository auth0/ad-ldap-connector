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

Users.prototype.list = function (search, options, callback) {
  var self = this;

  if (typeof options === 'function') {
    callback = options;
    options = {};
  }

  function exec(){
    var opts = { 
      scope:  'sub',
      filter: search ? nconf.get('LDAP_SEARCH_QUERY').replace(/\{0\}/ig, search) : nconf.get('LDAP_SEARCH_ALL_QUERY')
    };

    if (options.limit) opts.sizeLimit = parseInt(options.limit, 10);

    self._client.search(self._options.base, opts, function(err, res){
      if (err) {
        console.log('List users error:', err);
        return callback(err);
      }

      var entries = [];
      res.on('searchEntry', function(entry) {
        entries.push(entry);
      });

      res.on('error', function(err) {
        console.log('List users error:', err.message);
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