var nconf = require('nconf');
var ldap  = require('ldapjs');
var async = require('async');
var ldap_clients = require('./ldap');
var cb = require('cb');

var WrongPassword = require('./errors/WrongPassword');
var WrongUsername = require('./errors/WrongUsername');
var UnexpectedError = require('./errors/UnexpectedError');

var Users = module.exports = function(){
  this._base = nconf.get("LDAP_BASE");
  this._client = ldap_clients.client;
  this._binder = ldap_clients.binder;
};

/**
 * Validate username and password,
 * And returns the profile or one of these errors:
 *
 * -  WrongPassword   { profile object }
 * -  WrongUsername   { username string }
 * -  UnexpectedError { inner Error }
 *
 * @param  {[type]}   userName [description]
 * @param  {[type]}   password [description]
 * @param  {Function} callback [description]
 */
Users.prototype.validate = function (userName, password, callback) {
  var self = this;
  var binder = this._binder;

  var log_prepend = 'user ' + userName + ':';
  var log = console.log.bind(console, log_prepend.blue);

  self.getByUserName(userName, function (err, profile) {
    if (err) {
      return callback(UnexpectedError.wrap(err));
    }

    if (!profile) {
      return callback(new WrongUsername(userName));
    }

    // AD will search and delay an error till later if no password is given
    if(password === '') {
      return callback(new WrongPassword(profile));
    }

    log('Bind with DN "' + profile.dn.green + '"');

    //try bind by password
    binder.bind(profile.dn, password, function(err) {
      if (err) {
        if (err instanceof ldap.InvalidCredentialsError) {
          return callback(new WrongPassword(profile));
        } else {
          return callback(UnexpectedError.wrap(err));
        }
      }

      log('Bind OK.');
      log('Enrich profile.');

      self.enrichProfile(profile, cb(function (err) {
        if (err) {
          log('Error enriching the profile of the user. This error will be ignored.');
          return callback(null, profile);
        }

        log('Enrich profile OK.');

        return callback(null, profile);
      }).timeout(3000));
    });
  });
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
    scope:  'sub',
    filter: nconf.get('LDAP_USER_BY_NAME').replace('{0}', userName)
  };

  var entries = [];

  var done = cb(function (err) {
    if (err) {
      console.log(err);
      return callback(UnexpectedError.wrap(err));
    }
    if (entries.length === 0) return callback(null);
    callback(null, getProperObject(entries[0]));
  }).timeout(5000);

  self._client.search(self._base, opts, function(err, res){
    if (err) {
      return done(err);
    }
    res.on('searchEntry', function (entry) {
      entries.push(entry);
    }).once('error', function(err) {
      if (err.message === 'Size Limit Exceeded') {
        return done();
      }
      done(err);
    }).once('end', function () {
      done();
    });
  });
};

Users.prototype.list = function (search, options, callback) {
  var self = this;

  if (typeof options === 'function') {
    callback = options;
    options = {};
  }

  var opts = {
    scope:  'sub',
    filter: search ? nconf.get('LDAP_SEARCH_QUERY').replace(/\{0\}/ig, search) : nconf.get('LDAP_SEARCH_ALL_QUERY')
  };

  console.log(opts);

  if (options.limit) opts.sizeLimit = parseInt(options.limit, 10);

  self._client.search(self._base, opts, function(err, res){
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
};


Users.prototype.enrichProfile = function (profile, callback) {
  var self = this;
  async.parallel([
    function (done) {
      self._getAllGroupsAD(profile, function (err, groups) {
        if (err) return done();
        done(null, groups.map(function (g) {
          return g.cn;
        }));
      });
    },
    function (done) {
      var ous = profile.dn.split(',').map(function (pair) {
        return pair.split('=');
      }).filter(function (pair){
        return pair[0] === 'ou';
      }).map(function (ous) {
        return ous[1];
      });
      done(null, ous);
    }
  ], function (err, results) {
    if (err) return callback(err);
    profile.groups = results[0];
    if (results[1] && results[1].length > 0) {
      profile.organizationUnits = results[1];
    }
    callback(null, profile);
  });
};

Users.prototype._getAllGroupsAD = function (obj, callback) {
  var self = this;

  var opts = {
    scope: 'sub',
    filter: '(member:1.2.840.113556.1.4.1941:=' + obj.dn + ')'
  };

  self._client.search(self._base, opts, function(err, res){
    if (err) {
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