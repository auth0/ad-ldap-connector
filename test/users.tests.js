require('../lib/initConf');

var nconf = require('nconf');
var expect = require('chai').expect;
var Users = require('../lib/users');
var crypto = require('../lib/crypto');
var cas = require('../lib/add_certs');
var https = require('https');

var password = nconf.get('LDAP_BIND_PASSWORD') || crypto.decrypt(nconf.get('LDAP_BIND_CREDENTIALS'));

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

  describe.skip('changePassword with username and password', function () {
    var profile;

    before(function (done) {
      users.changePassword('john', password, function (err, p) {
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
});