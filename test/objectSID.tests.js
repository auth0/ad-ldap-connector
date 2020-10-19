const { assert } = require('chai');
const objectSid = require('../lib/objectsid');

describe('objectsid parsing', function() {

  it('should work', function() {
    const buffer = Buffer.from('01 05 00 00 00 00 00 05 15 00 00 00 75 19 89 A4 FC B3 64 B5 92 2C 56 92 92 23 00 00'.split(' ').map(n => parseInt(n, 16)))
    const expected = 'S-1-5-21-2760448373-3043275772-2455121042-9106';
    assert.equal(
      objectSid.parse(buffer),
      expected
    );
  });

  it('should return undefined when is not a buffer', function() {
    assert.equal(
      objectSid.parse({}),
      undefined
    );
  });

  it('should return undefined when buffer is empty', function() {
    assert.equal(
      objectSid.parse(Buffer.from([])),
      undefined
    );
  });
});
