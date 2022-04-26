require("../lib/initConf");
var nconf = require("nconf");
var expect = require("chai").expect;
var Users = require("../lib/users");
var mockLdapServer = require("./resources/mock_ldap_server");

// These unit tests use a mocked in-memory ldap server implementation running on localhost.
// The mock server is implemented in ./resources/mock_ldap_server.js
// The test data is defined in ./resources/mock_ldap_data.json
const PORT = 1389;

nconf.set("LDAP_URL", `ldap://0.0.0.0:${PORT}`);
nconf.set("LDAP_BASE", "dc=example,dc=org");
nconf.set("LDAP_BIND_USER", "cn=admin,dc=example,dc=org");
nconf.set("LDAP_BIND_PASSWORD", "admin");
nconf.set("LDAP_USER_BY_NAME", "(&(objectClass=inetOrgPerson)(uid={0}))");
nconf.set(
  "LDAP_SEARCH_QUERY",
  "(&(objectClass=inetOrgPerson)(|(cn={0})(givenName={0})(sn={0})(uid={0})))"
);
nconf.set("LDAP_SEARCH_ALL_QUERY", "(objectClass=inetOrgPerson)");
nconf.set("LDAP_SEARCH_GROUPS", "(member={0})");

describe("users", function () {
  var server;

  beforeEach(function (done) {
    server = mockLdapServer.listen(PORT, function () {
      done();
    });
  });

  afterEach(function () {
    server.close();
  });

  describe("getByUserName", function () {
    describe("when username is valid", function () {
      it("should return user if user exists", function (done) {
        const users = new Users();

        users.getByUserName("jdoe", function (err, user) {
          expect(err).to.be.null;
          expect(user.cn).to.equal("jdoe");
          expect(user.mail).to.equal("jdoe@example.org");
          done();
        });
      });

      it("should return null if user does not exist", function (done) {
        const users = new Users();

        users.getByUserName("cdoe", function (err, user) {
          expect(err).to.be.null;
          expect(user).to.be.undefined;
          done();
        });
      });
    });

    describe("when username is not valid", function () {
      it("should return null", function (done) {
        const users = new Users();

        users.getByUserName("jsm\\t)*(", function (err, user) {
          expect(err).to.be.null;
          expect(user).to.be.undefined;
          done();
        });
      });
    });
  });

  describe("validate", function () {
    describe("when username and password are valid", function () {
      it("should return user profile", function (done) {
        const users = new Users();

        users.validate("jdoe", "123", function (err, profile) {
          expect(err).to.be.null;
          expect(profile.id).to.equal("jdoe");
          expect(profile.name.givenName).to.equal("john");
          expect(profile.name.familyName).to.equal("doe");
          expect(profile.nickname).to.equal("jdoe");
          expect(profile.emails.length).to.equal(1);
          expect(profile.emails[0].value).to.equal("jdoe@example.org");
          expect(profile.groups.length).to.equal(2);
          expect(profile.groups).to.have.members(["administrators", "users"]);
          done();
        });
      });

      describe("when username contains escaped characters", function () {
        it("should return user profile", function (done) {
          const users = new Users();

          users.validate("jd\\28\\29e", "123", function (err, profile) {
            expect(err).to.be.null;
            expect(profile.id).to.equal("jd()e");
            expect(profile.name.givenName).to.equal("john");
            expect(profile.name.familyName).to.equal("doe");
            expect(profile.nickname).to.equal("jd()e");
            expect(profile.emails.length).to.equal(1);
            expect(profile.emails[0].value).to.equal("jd()e@example.org");
            expect(profile.groups.length).to.equal(1);
            expect(profile.groups).to.have.members(["users"]);
            done();
          });
        });
      });
    });

    describe("when user does not exist", function () {
      it("should return wrong username error", function (done) {
        const users = new Users();

        users.validate("cdoe", "123", function (err, profile) {
          expect(err.name).to.equal("WrongUsername");
          expect(profile).to.be.undefined;
          done();
        });
      });
    });

    describe("when password is not specified", function () {
      it("should return wrong password error", function (done) {
        const users = new Users();

        users.validate("jdoe", "", function (err, profile) {
          expect(err.name).to.equal("WrongPassword");
          expect(profile).to.be.undefined;
          done();
        });
      });
    });

    describe("when password is not valid", function () {
      it("should return wrong password error", function (done) {
        const users = new Users();

        users.validate("jdoe", "456", function (err, profile) {
          expect(err.name).to.equal("WrongPassword");
          expect(profile).to.be.undefined;
          done();
        });
      });
    });
  });

  describe("list", function () {
    describe("when the specified filter is valid", function () {
      describe("and a matching record exists", function () {
        it("should return the user profile", function (done) {
          const users = new Users();

          users.list("jdoe", {}, function (err, users) {
            expect(err).to.be.null;
            expect(users.length).to.equal(1);
            expect(users[0].id).to.equal("jdoe");
            expect(users[0].name.givenName).to.equal("john");
            expect(users[0].name.familyName).to.equal("doe");
            expect(users[0].nickname).to.equal("jdoe");
            expect(users[0].emails.length).to.equal(1);
            expect(users[0].emails[0].value).to.equal("jdoe@example.org");
            done();
          });
        });
      });

      describe("and no matching record exists", function () {
        it("should return empty results", function (done) {
          const users = new Users();

          users.list("cdoe", {}, function (err, users) {
            expect(err).to.be.null;
            expect(users.length).to.equal(0);
            done();
          });
        });
      });
    });

    describe("when the specified filter is not valid", function () {
      it("should return empty results", function (done) {
        const users = new Users();

        users.list("jsm\\t)*(", {}, function (err, users) {
          expect(err).to.be.null;
          expect(users.length).to.equal(0);
          done();
        });
      });
    });

    describe("when no filter is specified", function () {
      describe("and it is an empty string", function () {
        it("should find all users", function (done) {
          const users = new Users();

          users.list("", {}, function (err, users) {
            expect(err).to.be.null;
            expect(users.length).to.equal(3);
            expect(users.map((u) => u.id)).to.have.members([
              "jdoe",
              "mdoe",
              "jd()e",
            ]);
            done();
          });
        });
      });

      describe("and it is undefined", function () {
        it("should find all users", function (done) {
          const users = new Users();

          users.list(undefined, {}, function (err, users) {
            expect(err).to.be.null;
            expect(users.length).to.equal(3);
            expect(users.map((u) => u.id)).to.have.members([
              "jdoe",
              "mdoe",
              "jd()e",
            ]);
            done();
          });
        });
      });
    });
  });
});
