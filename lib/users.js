var nconf = require('nconf');
var ldap  = require('ldapjs');
var async = require('async');
var exit = require('./exit');

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
    bindDN:         options.bindDN,
    credentials:    options.bindCredentials,
    maxConnections: 5,
    checkInterval:  30000,
    maxIdleTime:    300000,
  });

  // This is a persistent connection we use just for bind operations
  // when validating username and passwords.
  //
  // A client that sends an LDAP request without doing a "bind" is
  // treated as an anonymous client (see the Anonymous Authentication
  // section for details). In the LDAP v3, the "bind" operation may be
  // sent at any time, possibly more than once, during the connection.
  // A client can send a "bind" request in the middle of a connection
  // to change its identity. If the request is successful, then all
  // outstanding requests that use the old identity on the connection
  // are discarded and the connection is associated with the new identity.
  this._binder = ldap.createClient({
    url: options.url
  });

  this._client.on('error', function(e){
    console.error('LDAP connection error:', e);
    exit(1);
  });

  this._queue = [];

  var self = this;

  this._client.bind(options.bindDN, options.bindCredentials, function(err) {
    if(err){
      console.error("Error binding to LDAP", 'dn: ' + err.dn + '\n code: ' + err.code + '\n message: ' + err.message);
      return exit(1);
    }
    self.clientConnected = true;

    self._queue.forEach(function (cb) { cb(); });
  });

  //Because the binder is just one tcp connection to the LDAP.
  //We need to keep this alive.
  this._binder.bind(options.bindDN, options.bindCredentials, function(err) {
    if(err){
      console.error("Error binding to LDAP", 'dn: ' + err.dn + '\n code: ' + err.code + '\n message: ' + err.message);
      return exit(1);
    }

    var ping = setInterval(function () {
      self._client.search(self._options.base, {
        scope: 'sub',
        filter: '(objectclass=organization)'
      }, function(err){
        if (err) {
          console.error('Error on Heartbeat from LDAP');
          clearInterval(ping);
          return exit(1);
        }
        console.log('Heartbeat LDAP: OK');
      });
    }, 30000);
  });
};

Users.prototype.validate = function (userName, password, callback) {
  this.getByUserName(userName, function (err, up) {
    if (err) return callback(err);
    if (!up) return callback();

    var client = this._binder;

    // AD will bind and delay an error till later if no password is given
    if(password === '') return callback();

    //try bind by password
    client.bind(up.dn, password, function(err) {
      if(err) return callback(new Error('wrong password'), up);

      this.getAllGroups(up, function (err, groups) {
        if (err) return callback(null, up);

        up.groups = groups.map(function (g) {
          return g.cn;
        });

        return callback(null, up);
      });

    }.bind(this));

  }.bind(this));
};

function getProperObject(entry) {
  var obj = {
    dn: entry.dn.toString(),
    controls: []
  };
  entry.attributes.forEach(function (a) {
    var buf = a.buffers;
    var val = a.vals;
    var item;
    if ( a.type == 'thumbnailPhoto' )
      item = buf;
    else
      item = val;
    if (item && item.length) {
      if (item.length > 1) {
        obj[a.type] = item.slice();
      } else {
        obj[a.type] = item[0];
      }
    } else {
      obj[a.type] = [];
    }
  });
  entry.controls.forEach(function (element) {
    obj.controls.push(element.json);
  });
  return obj;
}

Users.prototype.getByUserName = function (userName, callback) {
  var self = this;

  var opts = {
    scope:      'sub',
    filter:     nconf.get('LDAP_USER_BY_NAME').replace('{0}', userName)
  };

  self._client.search(self._options.base, opts, function(err, res){
    if (err) {
      console.error('Search For a Specific User error:', err);
      return callback(err);
    }

    var entries = [];
    res.on('searchEntry', function (entry) {
      entries.push(entry);
    });

    function done () {
      if (entries.length === 0) return callback(null);
      callback(null, getProperObject(entries[0]));
    }

    res.on('error', function(err) {
      if (err.message === 'Size Limit Exceeded') return done();
      callback(err);
    });

    res.on('end', done);
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

      function done () {
        if(entries.length === 0) return callback(null, []);
        var result = entries.map(function (e) { return e.object; });
        callback(null, result);
      }

      res.on('error', function(err) {
        if (err.message === 'Size Limit Exceeded') return done();
        callback(err);
      });

      res.on('end', done);
    });
  }

  if(this.clientConnected){
    exec();
  } else {
    this._queue.push(exec);
  }
};

Users.prototype.getAllGroups = function (obj, callback, explored) {
  var self = this;

  explored = explored || {};
  explored[obj.objectGUID] = true;

  self.getGroups(obj, function (err, groups) {
    if (err) return callback(err);

    async.map(groups, function (group, done){
      //call recursively only if the group has not been explored already.
      if (explored[group.objectGUID]) return done(null, []);
      self.getAllGroups(group, done, explored);
    }, function (err, res) {
      return callback(err, groups.concat.apply(groups, res));
    });

  });
};

Users.prototype.getGroups = function (obj, callback) {
  var self = this;

  var opts = {
    scope: 'sub',
    filter: '(&(objectclass=group)(member=' + obj.dn + '))'
  };

  self._client.search(self._options.base, opts, function(err, res){
    if (err) {
      console.log('List groups error:', err);
      return callback(err);
    }
    var entries = [];
    res.on('searchEntry', function(entry) {
      entries.push(entry);
    });

    function done () {
      if(entries.length === 0) return callback(null, []);
      var result = entries.map(function (e) { return e.object; });
      callback(null, result);
    }

    res.on('error', function(err) {
      if (err.message === 'Size Limit Exceeded') return done();
      callback(err);
    });

    res.on('end', done);
  });
};