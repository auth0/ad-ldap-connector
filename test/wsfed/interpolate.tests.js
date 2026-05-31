var interpolate = require('../lib/interpolate');
var expect = require('chai').expect;

describe('interpolation template', function () {
  it('should work', function () {
    var r = interpolate('aaa@@test@@')({
      test:'bbb'
    });
    expect(r).to.equal('aaabbb');
  });
});