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
      expect(users[0].id).to
        .match(/[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}/, 'Id should be a UUID');

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

  it('should be able to validate multiple simultaneous requests', function (done) {
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

  describe('validate with username and password and groups with extended properties list', function () {
    var profile;
    var saveValue;

    before(function () { users._groupsCache.reset(); });

    before(function () {
      saveValue = nconf.get('GROUP_PROPERTIES');
      nconf.set('GROUP_PROPERTIES', ['cn', 'objectGUID']);
    });

    after(function() {
      nconf.set('GROUP_PROPERTIES', saveValue);
    });

    before(function (done) {
      users.validate('john', password, function (err, p) {
        if (err) return done(err);
        profile = p;
        done();
      });
    });

    it('should include groups', function () {
      expect(profile.groups[0]).to.deep.equal({ cn: 'Administrators', objectGUID: '490b4030-5a0a-4dd5-a32b-6fd10508c272' });
      expect(profile.groups[1]).to.deep.equal({ cn: 'Domain Admins', objectGUID: '4a0deedb-cffa-4816-b144-adfac0d7313d' });
      expect(profile.groups[2]).to.deep.equal({ cn: 'Denied RODC Password Replication Group', objectGUID: '556bdab6-0407-4b18-a443-d4a14468f688' });
      expect(profile.groups[3]).to.deep.equal({ cn: 'Full-Admin', objectGUID: '27f15475-5a5e-42a9-9c08-0e9c6718be3d' });
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

  //this test does not work with ldap:
  const describeOrSkipChangePassword = nconf.get('LDAP_URL').startsWith('ldaps') ?
    describe :
    describe.skip;

  describeOrSkipChangePassword('change password', function () {
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
      users.listGroups('john', function(err, res) {
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

  describe('listing users with groups from the AD server when the cache is disabled', function() {
    var error;
    var user;
    var saveOmitGroups;

    before(function (done) {
      saveOmitGroups = nconf.get('LDAP_SEARCH_RESULTS_OMIT_GROUPS', false);
      nconf.set('LDAP_SEARCH_RESULTS_OMIT_GROUPS', false);
      var users = new Users(true);
      users.list('john', function(err, res) {
        error = err;
        user = res[0];
        done();
      });
    });

    after(() => {
      nconf.set('LDAP_SEARCH_RESULTS_OMIT_GROUPS', saveOmitGroups);
    });

    it('should return the groups', function() {
      expect(error).to.not.exist;
      expect(user.groups).to.deep.equal([
        "Administrators",
        "Domain Admins",
        "Denied RODC Password Replication Group",
        "Full-Admin"
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
      users.listGroups('john', function(err, res) {
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
        { cn: 'Administrators', objectGUID: '490b4030-5a0a-4dd5-a32b-6fd10508c272' },
        { cn: 'Users', objectGUID: '1b9bc7aa-ef2a-4370-adeb-0d6b45fffa46' },
        { cn: 'Guests', objectGUID: 'b34cc274-2b4d-4c1e-b458-cb3cbb35a44a' },
        { cn: 'Print Operators', objectGUID: 'e7f44015-2c60-4021-aebd-22ca254ae0b3' },
        { cn: 'Backup Operators', objectGUID: '19b3b847-2668-4502-8c30-1dd20167d3d1' },
        { cn: 'Replicator', objectGUID: 'fce80b0c-1699-44d7-94b9-bbe4a9ddf485' },
        { cn: 'Remote Desktop Users', objectGUID: 'c9819153-a815-4c2e-934c-fa92178af5ab' },
        { cn: 'Network Configuration Operators', objectGUID: 'e0228fd6-5de0-4479-9e63-88c83cb14fb3' },
        { cn: 'Performance Monitor Users', objectGUID: '768b0b90-b90c-4a87-821a-b1dd207656ca' },
        { cn: 'Performance Log Users', objectGUID: '6aa9a841-0a3a-4689-bfc8-d7ff463f01c1' },
        { cn: 'Distributed COM Users', objectGUID: 'dc8ec7f6-a96b-4c59-aa1e-f22cb156ad40' },
        { cn: 'IIS_IUSRS', objectGUID: '7266fbc0-57a0-4b48-a9f9-cc18ea832e4b' },
        { cn: 'Cryptographic Operators', objectGUID: 'fcd844c8-0e82-42d6-b0bf-ae4d449a9184' },
        { cn: 'Event Log Readers', objectGUID: '8d9585b9-ae55-4bf8-8303-75391e73647a' },
        { cn: 'Certificate Service DCOM Access', objectGUID: 'a6695dc6-262c-48de-911e-c6920e06d4ed' },
        { cn: 'Domain Computers', objectGUID: '1f1f198c-f9d1-40e0-bede-34502c208de5' },
        { cn: 'Domain Controllers', objectGUID: '03092b37-d6b5-4816-bf12-aade581d2112' },
        { cn: 'Schema Admins', objectGUID: '0cb242b3-c282-4313-86d4-b7dbd2544320' },
        { cn: 'Enterprise Admins', objectGUID: '4ba21817-cfac-4f4d-a32d-50b51813f1de' },
        { cn: 'Cert Publishers', objectGUID: '32bd055c-f3ac-4afa-8a65-e726ec2add9f' },
        { cn: 'Domain Admins', objectGUID: '4a0deedb-cffa-4816-b144-adfac0d7313d' },
        { cn: 'Domain Users', objectGUID: 'c5c1cb0b-ac02-43a8-bb63-88099a94cf37' },
        { cn: 'Domain Guests', objectGUID: '2fe68acc-cf32-4fd2-aa3c-d94aa17af644' },
        { cn: 'Group Policy Creator Owners', objectGUID: 'd7479b72-84a7-432c-b541-80b276e33dd0' },
        { cn: 'RAS and IAS Servers', objectGUID: '11c47168-99b7-4fa8-847c-ef097212f054' },
        { cn: 'Server Operators', objectGUID: '8408fdab-2f5d-442e-bd45-ac261bb87898' },
        { cn: 'Account Operators', objectGUID: 'afa447da-4ad1-46d5-9600-05ac6eee45db' },
        { cn: 'Pre-Windows 2000 Compatible Access', objectGUID: 'c1035ec5-75ef-456f-8930-fb2f65602033' },
        { cn: 'Incoming Forest Trust Builders', objectGUID: '3e3ba02d-7800-4d59-b8d4-303ac27e5c8f' },
        { cn: 'Windows Authorization Access Group', objectGUID: 'ffcf657b-6d03-4213-ad70-3a48c0b4363a' },
        { cn: 'Terminal Server License Servers', objectGUID: '082516d6-1fdf-4395-8921-a55828f36108' },
        { cn: 'Allowed RODC Password Replication Group', objectGUID: '3e6d6441-255f-40a9-aaa3-904c2291b6c1' },
        { cn: 'Denied RODC Password Replication Group', objectGUID: '556bdab6-0407-4b18-a443-d4a14468f688' },
        { cn: 'Read-only Domain Controllers', objectGUID: '29305826-dbb0-4d3c-9fe3-a186c9f79795' },
        { cn: 'Enterprise Read-only Domain Controllers', objectGUID: '13c64c34-af02-4110-9865-785b83521671' }
      ]);
    });
  });
});
