var nconf        = require('nconf');
var ldap         = require('ldapjs');
var async        = require('async');
var ldap_clients = require('./ldap');
var cb           = require('cb');
var graph        = require('./graph');
var _            = require('lodash');

var AccountDisabled        = require('./errors/AccountDisabled');
var AccountExpired         = require('./errors/AccountExpired');
var AccountLocked          = require('./errors/AccountLocked');
var PasswordChangeRequired = require('./errors/PasswordChangeRequired');
var PasswordExpired        = require('./errors/PasswordExpired');
var WrongPassword          = require('./errors/WrongPassword');
var WrongUsername          = require('./errors/WrongUsername');
var UnexpectedError        = require('./errors/UnexpectedError');

var profileMapper;

if (nconf.get('PROFILE_MAPPER')) {
  profileMapper = eval(nconf.get('PROFILE_MAPPER'));
} else if (nconf.get('PROFILE_MAPPER_FILE')) {
  profileMapper = require(nconf.get('PROFILE_MAPPER_FILE'));
} else {
  profileMapper = require('./profileMapper');
}

function formatGuid(data) {
  var format = '{3}{2}{1}{0}-{5}{4}-{7}{6}-{8}{9}-{10}{11}{12}{13}{14}{15}';
  for (var i = 0; i < data.length; i++) {
    var re = new RegExp('\\{' + i + '\\}', 'g');
    // Leading 0 is needed if value of data[i] is less than 16 (of 10 as hex).
    var dataStr = data[i].toString(16);
    format = format.replace(re, data[i] >= 16 ? dataStr : '0' + dataStr);
  }
  return format;
}

function logger(userName) {
  require('colors');
  if (process.env.NODE_ENV === 'test') {
    return function () {};
  }
  var log_prepend = 'user ' + userName + ':';
  return console.log.bind(console, log_prepend.blue);
}

var Users = module.exports = function(disable_caching){
  this._base = nconf.get("LDAP_BASE");
  this._baseGroups = nconf.get("LDAP_BASE_GROUPS") || nconf.get("LDAP_BASE");
  this._client = ldap_clients.client;
  this._binder = ldap_clients.binder;

  if (typeof disable_caching === 'undefined' || !disable_caching) {
    this._groupsCache = require('./cache').groups;
  }
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

  var log = logger(userName);

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
          var detailedError = getDetailedError(err);
          profile.ldapStatus = detailedError.code;
          return self.enrichProfile(profile, function (e, profile) {
            callback(new detailedError.err_type(profile));
          });
        } else {
          return callback(UnexpectedError.wrap(err));
        }
      }

      log('Bind OK.');

      log('Enrich profile.');
      profile.ldapStatus = 'active';
      self.enrichProfile(profile, function (err, profile) {
        log('Enrich profile OK.');
        return callback(null, profile);
      });
    });
  });
};

// Get detailed error for AD: http://www-01.ibm.com/support/docview.wss?uid=swg21290631
function getDetailedError(invalidCredentialsError) {
  if (invalidCredentialsError && invalidCredentialsError.message) {
    if (invalidCredentialsError.message.indexOf('data 532') > -1) {
      return { code: 'password_expired', err_type: PasswordExpired };
    } else if (invalidCredentialsError.message.indexOf('data 533') > -1 || invalidCredentialsError.message.indexOf('data 534') > -1) {
      return { code: 'account_disabled', err_type: AccountDisabled };
    } else if (invalidCredentialsError.message.indexOf('data 701') > -1) {
      return { code: 'account_expired', err_type: AccountExpired };
    } else if (invalidCredentialsError.message.indexOf('data 773') > -1) {
      return { code: 'password_change_required', err_type: PasswordChangeRequired };
    } else if (invalidCredentialsError.message.indexOf('data 775') > -1) {
      return { code: 'account_locked', err_type: AccountLocked };
    }
  }

  return { code: 'wrong_password', err_type: WrongPassword };
}

function getProperObject(entry) {
  var obj = {
    dn: entry.dn.toString(),
    controls: []
  };

  entry.attributes.forEach(function (a) {
    var buf = a.buffers;
    var val = a.vals;
    var item;

    switch (a.type) {
      case 'thumbnailPhoto':
        item = buf;
        break;
      case 'objectGUID':
        item = formatGuid(buf[0]);
        break;
      default:
        item = val;
    }

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
    filter: nconf.get('LDAP_USER_BY_NAME').replace(/\{0\}/g, userName)
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

  if (options.limit) opts.sizeLimit = parseInt(options.limit, 10);

  self._client.search(self._base, opts, function(err, res){
    if (err) {
      console.log('List users error:', err);
      return callback(err);
    }

    var entries = [];

    function done () {
      if(entries.length === 0) {
        return callback(null, []);
      }

      async.map(entries, function (e, done) {
        self.enrichProfile(e.object, true, done);
      }, callback);
    }

    res.on('searchEntry', function(entry) {
      entries.push(entry);
    });

    res.on('error', function(err) {
      if (err.message === 'Size Limit Exceeded') return done();
      console.log('error listing users', err.message);
    });

    res.on('end', done);
  });
};


Users.prototype.enrichProfile = function (profile, noGroups, callback) {
  var self = this;

  if (typeof noGroups === 'function') {
    callback = noGroups;
    noGroups = false;
  }

  // if (profile.objectGUID) {
  //   console.dir(profile.objectGUID);
  //   profile.objectGUID = formatGuid(new Buffer(profile.objectGUID, 'binary'));
  // }

  async.parallel([
    function (done) {
      if (noGroups || nconf.get('GROUPS') === false) {
        return done(null, undefined);
      }

      self._getAllGroupsADCached(profile, function (err, groups) {
        if (err) {
          console.log('Error fetching groups in enrichProfile', err.message);
          return done();
        }
        var result = groups.map(function (group) {
          if (nconf.get('GROUP_PROPERTIES').length > 0) {
            return _.pick(group, nconf.get('GROUP_PROPERTIES'));
          }
          return group[nconf.get('GROUP_PROPERTY')];
        });
        done(null, result);
      });

    }, function (done) {
      var ous = profile.dn || profile.dn.split(',').map(function (pair) {
        return pair.split('=');
      }).filter(function (pair){
        return pair[0].toLowerCase() === 'ou';
      }).map(function (ous) {
        return ous[1];
      });
      done(null, ous);
    }
  ], function (err, results) {
    if (err) {
      console.log('error enriching profile');
    }

    profile.groups = results[0];
    profile.organizationUnits = results[1] && results[1].length > 0 ? results[1] : undefined;

    if (profileMapper.length === 1) {
      var result = profileMapper(profile);
      callback(null, result);
    } else {
      profileMapper(profile, callback);
    }
  });
};

Users.prototype._getAllGroupsADCached = function (profile, callback) {
  var self = this;
  var memberOf = Array.isArray(profile.memberOf) ? profile.memberOf : [profile.memberOf];

  function uniq (groups) {
    return _.uniq(groups, function (g) {
      return g.dn;
    });
  }

  async.map(memberOf, function (dn, done) {
    self._groupsCache.get(dn, function (err, groups) {
      done(null, groups && JSON.parse(groups));
    });
  }, function (err, fromCache) {
    var resolveFromCache = fromCache && fromCache.every(function (fc) {
      return !!fc;
    });

    if (resolveFromCache) {
      var result = fromCache.map(function (group) {
        return [group].concat(group.memberOf);
      }).reduce(function (prev, curr) {
        return prev.concat(curr);
      }, []);
      console.log('from cache');
      return callback(null, uniq(result));
    }

    return self._getAllGroupsAD(profile.dn, function (err, groups) {
      if (err) { return callback(err); }

      graph.flatDeps(groups).forEach(function (fg) {
        self._groupsCache.put(fg.dn, JSON.stringify(fg), {
          ttl: 1000 * nconf.get('GROUPS_CACHE_SECONDS')
        });
      });

      callback(null, uniq(groups));
    });
  });
};

Users.prototype._getAllGroupsAD = function (dn, callback) {
  var self = this;
  var opts = {
    scope:      'sub',
    filter:     nconf.get('LDAP_SEARCH_GROUPS').replace(/\{0\}/ig, dn),
    attributes: _.uniq([ 'cn', 'dn', 'memberOf' ].concat(nconf.get('GROUP_PROPERTIES'))),
    timeLimit:  nconf.get('GROUPS_TIMEOUT_SECONDS'),
    derefAliases: nconf.get('GROUPS_DEREF_ALIASES')
  };

  callback = cb(callback)
              .timeout(nconf.get('GROUPS_TIMEOUT_SECONDS') * 1000)
              .once();

  self._client.search(self._baseGroups, opts, function(err, res){
    if (err) {
      return callback(err);
    }
    var entries = [];

    res.on('searchEntry', function(entry) {
      entries.push(entry.object);
    });

    res.on('error', function(err) {
      console.log('search groups', err.message);
      callback(null, entries);
    });

    res.on('end', function (result) {
      if (result.status !== 0) {
        console.log('Unexpected result on _getAllGroupsAD', result.status);
      }
      callback(null, entries);
    });
  });
};


Users.prototype.changePassword = function (userId, password, callback) {
  //TODO: AD write-back
  callback(null,{});
}
