var fixture = [
    {
      "dn": "CN=Administrators,CN=Builtin,DC=fabrikam,DC=local",
      "controls": [],
      "cn": "Administrators"
    },
    {
      "dn": "CN=Replicator,CN=Builtin,DC=fabrikam,DC=local",
      "controls": [],
      "cn": "Replicator"
    },
    {
      "dn": "CN=Mammals,OU=Janitorial,DC=fabrikam,DC=local",
      "controls": [],
      "cn": "Mammals",
      "memberOf": "CN=Administrators,CN=Builtin,DC=fabrikam,DC=local"
    },
    {
      "dn": "CN=G8,OU=Janitorial,DC=fabrikam,DC=local",
      "controls": [],
      "cn": "G8",
      "memberOf": "CN=Human,OU=Janitorial,DC=fabrikam,DC=local"
    },
    {
      "dn": "CN=Teenage Mutant Ninja Turtles,OU=Janitorial,DC=fabrikam,DC=local",
      "controls": [],
      "cn": "Teenage Mutant Ninja Turtles",
      "memberOf": [
        "CN=Reptile,OU=Janitorial,DC=fabrikam,DC=local",
        "CN=Replicator,CN=Builtin,DC=fabrikam,DC=local"
      ]
    },
    {
      "dn": "CN=Reptile,OU=Janitorial,DC=fabrikam,DC=local",
      "controls": [],
      "cn": "Reptile"
    },
    {
      "dn": "CN=Biped,OU=Janitorial,DC=fabrikam,DC=local",
      "controls": [],
      "cn": "Biped",
      "memberOf": "CN=Mammals,OU=Janitorial,DC=fabrikam,DC=local"
    },
    {
      "dn": "CN=Human,OU=Janitorial,DC=fabrikam,DC=local",
      "controls": [],
      "cn": "Human",
      "memberOf": [
        "CN=Biped,OU=Janitorial,DC=fabrikam,DC=local",
        "CN=G8,OU=Janitorial,DC=fabrikam,DC=local"
      ]
    }
  ];

var graph = require('../lib/graph');
var expect = require('chai').expect;

describe('memberOf walker', function () {
  var g8;

  before(function () {
    var nodes = graph.flatDeps(fixture);
    g8 = nodes.filter(function (node) {
      return node.dn === 'CN=G8,OU=Janitorial,DC=fabrikam,DC=local';
    })[0];
  });

  it('should contain the inmediate parent', function () {
    var has_human = g8.memberOf.some(function (node) {
      return node.dn === 'CN=Human,OU=Janitorial,DC=fabrikam,DC=local';
    });

    expect(has_human).to.eql(true);
  });

  it('should contain the grand parents', function () {
    var has_biped = g8.memberOf.some(function (node) {
      return node.dn === 'CN=Biped,OU=Janitorial,DC=fabrikam,DC=local';
    });

    expect(has_biped).to.eql(true);
  });

  it('should contain the great grand parents', function () {
    var has_mammals = g8.memberOf.some(function (node) {
      return node.dn === 'CN=Mammals,OU=Janitorial,DC=fabrikam,DC=local';
    });

    expect(has_mammals).to.eql(true);
  });
});