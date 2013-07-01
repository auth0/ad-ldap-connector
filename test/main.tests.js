require('../lib/initConf');

var expect = require('chai').expect;
var Users  = require('../lib/users');
var users  = new Users();

describe('what?', function () {
  it('should be able to query by name', function (done) {
    users.list('wolo', function (err, users) {
      if (err) return done(err);
      expect(users[0].name).to.eql('Matias Woloski');
      done();
    });
  });

  // it('should be able to query by mail', function (done) {
  //   users.list('onelogin@auth', function (err, users) {
  //     if (err) return done(err);
  //     expect(users[0].mail).to.eql('onelogin@auth10.com');
  //     done();
  //   });
  // });
});