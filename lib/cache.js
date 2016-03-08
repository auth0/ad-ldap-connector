var levelup = require('levelup');
var ttl     = require('level-ttl');
var spaces  = require('level-spaces');
var nconf   = require('nconf');

var db = levelup(nconf.get('CACHE_FILE'));

db = ttl(db, { checkFrequency: 100});

module.exports = {
  groups: spaces(db, 'groups')
};