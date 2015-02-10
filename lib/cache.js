var levelup = require('levelup');
var ttl     = require('level-ttl');
var spaces  = require('level-spaces');

var db = levelup(__dirname + '/../cache.db');

db = ttl(db, { checkFrequency: 100});

module.exports = {
  groups: spaces(db, 'groups')
};