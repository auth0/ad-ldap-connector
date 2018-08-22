require('../lib/initConf');
//process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;

var nconf = require('nconf');
var expect = require('chai').expect;
var Users = require('../lib/users');
var crypto = require('../lib/crypto');
var cas = require('../lib/add_certs');
var PasswordComplexityError = require('../lib/errors/PasswordComplexityError');
var async = require('async');

var password = nconf.get('LDAP_BIND_PASSWORD') || crypto.decrypt(nconf.get('LDAP_BIND_CREDENTIALS'));
var jane_password = nconf.get('JANE_PASSWORD');
/*
 * These tests needs a config.json file in place pointing to our test-AD
 */

describe('users', function () {

  var users;
  // Allow the tests to use ldaps.
  before(function (done) {
    if (nconf.get('LDAP_URL').toLowerCase().substr(0, 5) === 'ldaps') {
      cas.inject(function (err) {
        console.log('Using LDAPs');
        users = new Users();
        done();
      });
    }else{
      users = new Users();
      done();
    }
  });

  it('should be able to query by name', function (done) {
    users.list('wolo', function (err, users) {
      if (err) return done(err);
      expect(users[0].name.familyName).to.eql('Woloski');
      expect(users[0].name.givenName).to.eql('Matias');
      done();
    });
  });

  it('should be able to query by name (specifying limit)', function (done) {
    users.list('wolo', {
      limit: 1
    }, function (err, users) {
      if (err) return done(err);

      expect(users).to.have.length(1);
      expect(users[0].name.familyName).to.eql('Woloski');
      expect(users[0].name.givenName).to.eql('Matias');
      done();
    });
  });

  it('should returns all users if search parameter is empty', function (done) {
    users.list('', {
      limit: 15
    }, function (err, users) {
      if (err) return done(err);

      expect(users.length).to.be.within(11, 15);
      done();
    });
  });

  it('should be able ot validate multiple simultaneous requests', function (done) {
    async.parallel([
      function(cb) {
        users.validate('john', password, cb);
      },
      function(cb) {
        users.validate('john', password, cb);
      },
      function(cb) {
        users.validate('john', password, cb);
      }],
      done);
  });

  describe('validate with username and password', function () {
    var profile;

    before(function (done) {
      users.validate('john', password, function (err, p) {
        if (err) return done(err);
        profile = p;
        done();
      });
    });

    it('should include groups', function () {
      expect(profile.groups).to.include('Administrators');
      expect(profile.groups).to.include('Domain Admins');
      expect(profile.groups).to.include('Denied RODC Password Replication Group');
      expect(profile.groups).to.include('Full-Admin');
    });

    it('should include basic attributes', function () {
      expect(profile.id).to.equal('ae8fbd21-d66c-4f78-ad8e-53ab078cee16');
      expect(profile.name.familyName).to.equal('Fabrikam');
      expect(profile.name.givenName).to.equal('John');
      expect(profile.emails[0].value).to.equal('john@fabrikam.com');
      expect(profile.sAMAccountName).to.equal('john');
    });

  });

  describe('validate with wrong password', function () {
    var error;

    before(function (done) {
      users.validate('john', 'aa12', function (err) {
        if (!err) {
          return done(new Error('expected error'));
        }
        error = err;
        done();
      });
    });

    it('should fail with WrongPassword', function () {
      expect(error.name).to.equal('WrongPassword');
    });

    it('should include groups', function () {
      expect(error.profile.groups).to.include('Administrators');
      expect(error.profile.groups).to.include('Domain Admins');
      expect(error.profile.groups).to.include('Denied RODC Password Replication Group');
      expect(error.profile.groups).to.include('Full-Admin');
    });

    it('should include basic attributes', function () {
      expect(error.profile.id).to.equal('ae8fbd21-d66c-4f78-ad8e-53ab078cee16');
      expect(error.profile.name.familyName).to.equal('Fabrikam');
      expect(error.profile.name.givenName).to.equal('John');
      expect(error.profile.emails[0].value).to.equal('john@fabrikam.com');
      expect(error.profile.sAMAccountName).to.equal('john');
    });

  });

  describe('validate with wrong username', function () {
    var error;

    before(function (done) {
      users.validate('uqweu', 'aa12', function (err) {
        if (!err) {
          return done(new Error('expected error'));
        }
        error = err;
        done();
      });
    });

    it('should fail with WrongUsername', function () {
      expect(error.name).to.equal('WrongUsername');
    });

    it('should include the username', function () {
      expect(error.username).to.include('uqweu');
    });
  });

  describe('change password', function () {
    var profile;

    before(function (done) {
      users.changePassword('jane', jane_password, function (err, p) {
        if (err) return done(err);
        profile = p;
        done();
      });
    });

    it('should include groups', function () {
      expect(profile.groups).to.include('Administrators');
      expect(profile.groups).to.include('Domain Admins');
      expect(profile.groups).to.include('Denied RODC Password Replication Group');
      expect(profile.groups).to.include('Full-Admin');
    });

    it('should include basic attributes', function () {
      expect(profile.id).to.equal('d0eb2fa3-802d-4172-889c-1812e6e83f4f');
      expect(profile.name.familyName).to.equal('Doe');
      expect(profile.name.givenName).to.equal('Jane');
      expect(profile.emails[0].value).to.equal('jane@fabrikam.com');
      expect(profile.sAMAccountName).to.equal('jane');
    });
  });

  describe('change password that doesn\'t meet complexity', function () {
    var error;

    before(function (done) {
      users.changePassword('jane', 42, function (err, p) {
        error = err;
        done();
      });
    });

    it('should contain error', function () {
      expect(error.message).to.equal('Password doesn’t meet minimum requirements');
      expect(error).to.be.an.instanceof(PasswordComplexityError);
    });

    it('should include groups', function () {
      expect(error.profile.groups).to.include('Administrators');
      expect(error.profile.groups).to.include('Domain Admins');
      expect(error.profile.groups).to.include('Denied RODC Password Replication Group');
      expect(error.profile.groups).to.include('Full-Admin');
    });

    it('should include basic attributes', function () {
      expect(error.profile.id).to.equal('d0eb2fa3-802d-4172-889c-1812e6e83f4f');
      expect(error.profile.name.familyName).to.equal('Doe');
      expect(error.profile.name.givenName).to.equal('Jane');
      expect(error.profile.emails[0].value).to.equal('jane@fabrikam.com');
      expect(error.profile.sAMAccountName).to.equal('jane');
    });
  });

  describe('listing groups from the AD server', function() {
    var error;
    var response;
    var saveQuery;

    before(function (done) {
      // We override the group query to prevent the tests from breaking if new
      // custom groups are added to the test environment.
      saveQuery = nconf.get('LDAP_SEARCH_LIST_GROUPS_QUERY');
      nconf.set('LDAP_SEARCH_LIST_GROUPS_QUERY', '(&(isCriticalSystemObject=TRUE)(objectCategory=group))');
      users.listGroups(function(err, res) {
        error = err;
        response = res;
        done();
      });
    });

    after(function() {
      nconf.set('LDAP_SEARCH_LIST_GROUPS_QUERY', saveQuery);
    });

    it('should return the groups', function() {
      expect(error).to.not.exist;
      expect(response).to.deep.equal([
        "Administrators",
        "Users",
        "Guests",
        "Print Operators",
        "Backup Operators",
        "Replicator",
        "Remote Desktop Users",
        "Network Configuration Operators",
        "Performance Monitor Users",
        "Performance Log Users",
        "Distributed COM Users",
        "IIS_IUSRS",
        "Cryptographic Operators",
        "Event Log Readers",
        "Certificate Service DCOM Access",
        "Domain Computers",
        "Domain Controllers",
        "Schema Admins",
        "Enterprise Admins",
        "Cert Publishers",
        "Domain Admins",
        "Domain Users",
        "Domain Guests",
        "Group Policy Creator Owners",
        "RAS and IAS Servers",
        "Server Operators",
        "Account Operators",
        "Pre-Windows 2000 Compatible Access",
        "Incoming Forest Trust Builders",
        "Windows Authorization Access Group",
        "Terminal Server License Servers",
        "Allowed RODC Password Replication Group",
        "Denied RODC Password Replication Group",
        "Read-only Domain Controllers",
        "Enterprise Read-only Domain Controllers"
      ]);
    });
  });

  describe('listing groups from AD server with extended properties list', function() {
    var error;
    var response;
    var saveQuery;
    var saveValue;

    before(function (done) {
      saveQuery = nconf.get('LDAP_SEARCH_LIST_GROUPS_QUERY');
      saveValue = nconf.get('GROUP_PROPERTIES');
      nconf.set('LDAP_SEARCH_LIST_GROUPS_QUERY', '(&(isCriticalSystemObject=TRUE)(objectCategory=group))');
      nconf.set('GROUP_PROPERTIES', ['cn', 'objectGUID']);
      users.listGroups(function(err, res) {
        error = err;
        response = res;
        done();
      });
    });

    after(function() {
      nconf.set('LDAP_SEARCH_LIST_GROUPS_QUERY', saveQuery);
      nconf.set('GROUP_PROPERTIES', saveValue);
    });

    it('should return the groups with extended properties', function() {
      expect(error).to.not.exist;
      expect(response).to.deep.equal([
        {"cn":"Administrators", "objectGUID":"0@\u000bI\nZ�M�+o�\u0005\b�r"},
        {"cn":"Users", "objectGUID":"�Ǜ\u001b*�pC��\rkE��F"},
        {"cn":"Guests", "objectGUID":"t�L�M+\u001eL�X�<�5�J"},
        {"cn":"Print Operators", "objectGUID":"\u0015@��`,!@��\"�%J�"},
        {"cn":"Backup Operators", "objectGUID":"G��\u0019h&\u0002E�0\u001d�\u0001g��"},
        {"cn":"Replicator", "objectGUID":"\f\u000b���\u0016�D������"},
        {"cn":"Remote Desktop Users", "objectGUID":"S���\u0015�.L�L��\u0017���"},
        {"cn":"Network Configuration Operators", "objectGUID":"֏\"��]yD�c��<�O�"},
        {"cn":"Performance Monitor Users", "objectGUID":"�\u000b�v\f��J�\u001a�� vV�"},
        {"cn":"Performance Log Users", "objectGUID":"A��j:\n�F����F?\u0001�"},
        {"cn":"Distributed COM Users", "objectGUID":"�ǎ�k�YL�\u001e�,�V�@"},
        {"cn":"IIS_IUSRS", "objectGUID":"��fr�WHK���\u0018�.K"},
        {"cn":"Cryptographic Operators", "objectGUID":"�D���\u000e�B���MD���"},
        {"cn":"Event Log Readers", "objectGUID":"����U��K�\u0003u9\u001esdz"},
        {"cn":"Certificate Service DCOM Access", "objectGUID":"�]i�,&�H�\u001eƒ\u000e\u0006��"},
        {"cn":"Domain Computers", "objectGUID":"�\u0019\u001f\u001f���@��4P, ��"},
        {"cn":"Domain Controllers", "objectGUID":"7+\t\u0003��\u0016H�\u0012��X\u001d!\u0012"},
        {"cn":"Schema Admins", "objectGUID":"�B�\f��\u0013C�Է��TC "},
        {"cn":"Enterprise Admins", "objectGUID":"\u0017\u0018�K��MO�-P�\u0018\u0013��"},
        {"cn":"Cert Publishers", "objectGUID":"\\\u0005�2���J�e�&�*ݟ"},
        {"cn":"Domain Admins", "objectGUID":"��\rJ��\u0016H�D����1="},
        {"cn":"Domain Users", "objectGUID":"\u000b���\u0002��C�c�\t���7"},
        {"cn":"Domain Guests", "objectGUID":"̊�/2��O�<�J�z�D"},
        {"cn":"Group Policy Creator Owners", "objectGUID":"r�Gק�,C�A��v�=�"},
        {"cn":"RAS and IAS Servers", "objectGUID":"hq�\u0011���O�|�\tr\u0012�T"},
        {"cn":"Server Operators", "objectGUID":"��\b�]/.D�E�&\u001b�x�"},
        {"cn":"Account Operators", "objectGUID":"�G���J�F�\u0000\u0005�n�E�"},
        {"cn":"Pre-Windows 2000 Compatible Access", "objectGUID":"�^\u0003��uoE�0�/e` 3"},
        {"cn":"Incoming Forest Trust Builders", "objectGUID":"-�;>\u0000xYM��0:�~\\�"},
        {"cn":"Windows Authorization Access Group", "objectGUID":"{e��\u0003m\u0013B�p:H��6:"},
        {"cn":"Terminal Server License Servers", "objectGUID":"�\u0016%\b�\u001f�C�!�X(�a\b"},
        {"cn":"Allowed RODC Password Replication Group", "objectGUID":"Adm>_%�@���L\"���"},
        {"cn":"Denied RODC Password Replication Group", "objectGUID":"��kU\u0007\u0004\u0018K�CԡDh��"},
        {"cn":"Read-only Domain Controllers", "objectGUID":"&X0)��<M�㡆����"},
        {"cn":"Enterprise Read-only Domain Controllers", "objectGUID":"4L�\u0013\u0002�\u0010A�ex[�R\u0016q"}
      ]);
    });
  });

  describe('listing groups from AD server with a limit', function() {
    var error;
    var response;
    var saveQuery;

    before(function (done) {
      // We override the group query to prevent the tests from breaking if new
      // custom groups are added to the test environment.
      saveQuery = nconf.get('LDAP_SEARCH_LIST_GROUPS_QUERY');
      nconf.set('LDAP_SEARCH_LIST_GROUPS_QUERY', '(&(isCriticalSystemObject=TRUE)(objectCategory=group))');
      users.listGroups({limit: 1}, function(err, res) {
        error = err;
        response = res;
        done();
      });
    });

    after(function() {
      nconf.set('LDAP_SEARCH_LIST_GROUPS_QUERY', saveQuery);
    });

    it('should return the groups', function() {
      expect(error).to.not.exist;
      expect(response).to.deep.equal([
        "Administrators"
      ]);
    });
  });
});
