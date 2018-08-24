var levelup = require('levelup');
var ttl     = require('level-ttl');
var nconf   = require('nconf');
var fs      = require('fs');
var rimraf  = require('rimraf');
var path    = require('path');
var _       = require('lodash');

var db_path = nconf.get('CACHE_FILE');

const ALL_GROUPS_KEY = 'ALL_GROUPS';

const ENTRY_TTL = 1000 * nconf.get('GROUPS_CACHE_SECONDS');
const CACHE_TTL_OPTIONS = {
  ttl: ENTRY_TTL
};

if (fs.existsSync(path.join(db_path, 'LOCK'))) {
  rimraf.sync(db_path);
}

var db = levelup(nconf.get('CACHE_FILE'));

db = ttl(db, { checkFrequency: 100});

console.log('Cache enabled');

function addGroup(group, cb) {
  return db.put(`group|${group.dn}`, JSON.stringify(group), CACHE_TTL_OPTIONS, cb);
}

function getGroup(dn, cb) {
  return db.get(`group|${dn}`, function (err, group) {
    cb(err, group && JSON.parse(group));
  });
}

class InsertAllGroupsBatch{
  constructor() {
    this.startTimestamp = Date.now();
    this.ops = [];
    this.finished = false;
  }

  addGroupOperation(group) {
    if (this.finished) {
      console.log('WARNING: Adding an operation to an already finish batch');
      return;
    }
    this.ops.push({ type: 'put', key: `group|${group.dn}`, value: JSON.stringify(group) });
  }

  flushCurrentOperations(cb) {
    if (this.finished) {
      console.log('WARNING: Flushing operations to an already finish batch');
      return cb();
    }
    db.batch(this.ops, CACHE_TTL_OPTIONS, (err) => {
      if (err) { return cb(err); }
      this.ops = [];
      cb();
    });
  }

  finishCurrentBatch(cb) {
    if (this.finished) {
      console.log('WARNING: Finishing operations to an already finish batch');
      return cb();
    }
    this.finish = true;
    const elapsed = Date.now() - this.startTimestamp;
    const allGroupsFlagTTL = ENTRY_TTL - elapsed;

    if (allGroupsFlagTTL < 0) {
      return cb(new Error(`The Batch Operation took longer than the current TTL setting: Elapsed: ${elapsed}. TTL: ${ENTRY_TTL}`));
    }
    db.put(ALL_GROUPS_KEY, 'OK', allGroupsFlagTTL, (err) => {
      if (err) { return cb(err); }
      if (this.ops.length === 0) { return cb(); }

      db.batch(this.ops, CACHE_TTL_OPTIONS, cb);
    });

  }
}

/**
 * Creates a function to use as the event handler for 'onData' events
 * while reading the cache read stream
 * 
 * @param {array} entries 
 * @param {number} pageNumber 
 * @param {number} pageSize 
 */
function getReadPageElementsFunction(entries, pageNumber, pageSize) {
  var current = 1;

  return function processData(data) {
    const isPageCompleted = entries.length === pageSize;
    const currentElementWithinLowerLevel = (current > (pageNumber - 1) * pageSize);
    const currentElementWithinHigherLevel = (current <= pageNumber * pageSize);

    if (isPageCompleted) { return; }
    if (currentElementWithinLowerLevel && currentElementWithinHigherLevel) {
      var value = JSON.parse(data.value);

      if (nconf.get('GROUP_PROPERTIES').length > 0) {
        value = _.pick(value, nconf.get('GROUP_PROPERTIES'));
      } else {
        value = value[nconf.get('GROUP_PROPERTY')];
      }

      entries.push(value);
    }

    current += 1;
  };
}

/**
 * Read Groups From the LDAP Server in a paginated Fashion.
 * If no pageNumber or pageSize are set, it will use default values
 * based on common LDAP Server limits.
 * 
 * Returns the groups and metadata information like total entries (for pagination purposes)
 * 
 * @param {number} pageNumber 
 * @param {number} pageSize 
 * @param {function} cb 
 */
function getPagedGroups(pageNumber, pageSize, cb) {
  const pageEntries = [];
  var totalEntries = 0;
  pageNumber = pageNumber || 1;
  pageSize = pageSize || nconf.get('GROUPS_PAGE_SIZE');
  const readPageElements = getReadPageElementsFunction(pageEntries, pageNumber, pageSize);

  db.createReadStream({ gte: 'group|', lte: 'group|~', })
    .on('data', (data) => {
      totalEntries += 1;
      readPageElements(data);
    })
    .on('error', cb)
    .on('end', function () {
      cb(null, pageEntries, { totalEntries });
    });
}

function areAllGroupsCached(cb) {
  db.get(ALL_GROUPS_KEY, function (err) {
    if (err) {
      if (err.notFound) {
        return cb(null, false);
      }
      return cb(err);
    }
    return cb(null, true);
  });
}

module.exports = {
  db: db,
  groups: {
    addGroup,
    getGroup,
    getPagedGroups,
    areAllGroupsCached,
    newInsertAllGroupsBatch: () => new InsertAllGroupsBatch()
  }
};
