var xtend = require('xtend');

    // {
    //   "dn": "CN=Teenage Mutant Ninja Turtles,OU=Janitorial,DC=fabrikam,DC=local",
    //   "controls": [],
    //   "cn": "Teenage Mutant Ninja Turtles",
    //   "memberOf": [
    //     "CN=Reptile,OU=Janitorial,DC=fabrikam,DC=local",
    //     "CN=Replicator,CN=Builtin,DC=fabrikam,DC=local"
    //   ]
    // },

function getMemberOf (nodes, node) {
  if (!node.memberOf) return [];

  var memberOf = Array.isArray(node.memberOf) ? node.memberOf : [node.memberOf];

  var inmediate = memberOf.map(function (mof) {
    return nodes.filter(function (node) {
      return node.dn === mof;
    })[0];
  });


  var parents = inmediate.map(function (node) {
    return getMemberOf(nodes, node);
  }).reduce(function (prev, curr) {
    return prev.concat(curr);
  }, []);

  return inmediate.concat(parents).filter(function (node) {
    return !!node;
  });
}

function flatDeps(nodes) {
  return nodes.map(function (node) {
    return xtend({}, node, { memberOf: getMemberOf(nodes, node) });
  });
}

module.exports = {
  flatDeps: flatDeps
};