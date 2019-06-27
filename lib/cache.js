var levelup = require('levelup');
var ttl     = require('level-ttl');
var nconf   = require('nconf');
var fs      = require('fs');
var rimraf  = require('rimraf');
var path    = require('path');
var leveldown = require('leveldown');

var db_path = nconf.get('CACHE_FILE');

if (fs.existsSync(path.join(db_path, 'LOCK'))) {
  rimraf.sync(db_path);
}

var db = levelup(leveldown(nconf.get('CACHE_FILE')));

db = ttl(db, { checkFrequency: 100});

console.log('Cache enabled');

module.exports = {
  groups: db
};
