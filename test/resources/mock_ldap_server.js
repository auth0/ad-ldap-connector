const ldap = require("ldapjs");
const path = require("path");
const db = require(path.join(__dirname, "mock_ldap_data.json"));

const BASE_DN = "dc=example,dc=org";

// This is an in-memory LDAP server used to run unit/integration tests
// It is based on the example of the ldapjs library: http://ldapjs.org/examples.html
const server = ldap.createServer();

server.bind(BASE_DN, function (req, res, next) {
  var dn = req.dn.format({skipSpace: true});
  if (!db[dn]) return next(new ldap.NoSuchObjectError(dn));

  if (!db[dn].userPassword)
    return next(new ldap.NoSuchAttributeError("userPassword"));

  if (db[dn].userPassword.indexOf(req.credentials) === -1)
    return next(new ldap.InvalidCredentialsError());

  res.end();
  return next();
});

server.search(BASE_DN, function (req, res, next) {
  var dn = req.dn.format({skipSpace: true});
  if (!db[dn]) return next(new ldap.NoSuchObjectError(dn));

  var scopeCheck;

  switch (req.scope) {
    case "base":
      if (req.filter.matches(db[dn])) {
        res.send({
          dn: dn,
          attributes: db[dn],
        });
      }

      res.end();
      return next();

    case "one":
      scopeCheck = function (k) {
        if (req.dn.equals(k)) return true;

        var parent = ldap.parseDN(k).parent();
        return parent ? parent.equals(req.dn) : false;
      };
      break;

    case "sub":
      scopeCheck = function (k) {
        return req.dn.equals(k) || req.dn.parentOf(k);
      };

      break;
  }

  Object.keys(db).forEach(function (key) {
    if (!scopeCheck(key)) return;

    if (req.filter.matches(db[key])) {
      res.send({
        dn: key,
        attributes: db[key],
      });
    }
  });

  res.end();
  return next();
});

module.exports = server;
