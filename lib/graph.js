var _ = require('lodash');

function get_dn (group) {
  return group.dn;
}

function getMemberOf (nodes, node, lookup_cache) {
  if (!node || !node.memberOf || !nodes || nodes.length === 0) {
    return [];
  }

  var from_cache = lookup_cache[node.dn];

  if (from_cache) {
    return from_cache;
  }

  var memberOf = Array.isArray(node.memberOf) ? node.memberOf : [node.memberOf];

  if (memberOf.length === 0) {
    return [];
  }

  var inmediate = nodes.filter(function (node) {
    return ~memberOf.indexOf(node.dn);
  });

  var upstream = inmediate.reduce(function (result, inmediate_node) {
    var search_in = _.difference(nodes, inmediate.concat([node]));
    return result.concat(getMemberOf(search_in, inmediate_node, lookup_cache));
  }, []);

  var result = inmediate.concat(upstream);

  result = _.uniq(result, get_dn);

  lookup_cache[node.dn] = result;

  return result;
}

function flatDeps(nodes) {
  return nodes.map(function (node) {
    var memberOf = getMemberOf(nodes, node, {});
    return _.extend({}, node, { memberOf: memberOf });
  });
}

module.exports = {
  flatDeps: flatDeps
};
