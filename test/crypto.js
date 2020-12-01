const { assert } = require('chai');
const proxyquire =  require('proxyquire');

const mockNconf = {
  values: {},
  get: (key) => mockNconf.values[key],
  set: (key, value) => {
      mockNconf.values[key] = value;
  },
  '@global': true,
}

const key = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAiVK8Xv3EVlr9APNwr8mE5+7gPNrpZrQgUlfaZjbGoy5sfhKn
tMPmlc6rKkceKN9matJZLI7Mt9GH3IcEIZ4KGJ91AAxpV9UuWRm0WjmEmKGKlhIt
gZ48tmGGh2EFOR40MgP8gYsbSfBLEel3Xn9A4vd/CtlPcAa+K+QM6wy67qwTFxJA
awRc2w7kue4FMAOutH0tFy/OPffWrwXtSrOw6PFYzhXmmjhheOIYcDyh6s/P3Nuw
jjowPbGYUVO0IuGYs4W8bKM1YyIT8YhwlUGuq/nfyTbY4PJBr2QhWnIwmB3FatHM
dmNYZ7LCb2SieDe13fPgartFAHEK7AJh49XMbwIDAQABAoIBAG76+5v1kQiNbm2n
UMnwnkXnazgjX4AOURTbRXlYCX711N6q6viPXjpyFSkM4tX7fkUUjNcS7WYdo6RZ
RcB5fgVaUW9hmH1Qn62ItZY5Z+0GmP8h378iiESJWvTsNxFrVJmbWSXEq6A84B6w
xTUMuP71MKou6CFMgcLtAnewCR87oagR6IaBi+qH+XMQ0DZTTfrrIU8DEamIxNK0
OGomZctZnC+CkZks3w8p1nt+PCwPa3JmFwM9njc1KdPtWLE96bfkMSroP+FEkwul
/On13j1lsaGRWtuVp7fZO27nVKe1iK44nU1C2bywr8B7EZXjIXcp8FF/2+22XQza
ikWdQsECgYEA6Yo3wUBAzMF0bXCr2A9FV6irVRsojooYVYoWW5mjIygDCUsKADgt
TYUZ4w4K2M3MohaHh9IZI46a0Kev80VmzGg4gr8/K82ZzfYF85bVqLmT/MDWhu+S
CtUbvGRGzbJTjO9d6jUB+NhktKKD/RIeYUT3AYon3cuuhig5qOXQyyECgYEAloem
agiTus6w/Bo5PitzqHGthko9gU7ac60bP292S/GMRIji6swObmE8Bdr3r2X4LPL3
ngKrU1WVJgO/XkpUTh/hBmPLszHRRnW7M08nrGXFZ2rxhb9RoWgtNIuDLVkw2I4p
SGtN6z8n3jl6yEMgQAoxeYxTA/+JvzMFfzfWtY8CgYBnBS/fMebj7BreBCvqHaJr
Lt6VpmtXpZdidI20TqvmYEommVGKEz34ylRHEvS5+t7gSavzwDySsN+eV7qIR/83
AGqdUpwdSI8mifbKI6mQynx7rN11nM0BtkyL6HhLWPT+YME/Ba8fBOY3wNEUnB+G
rROBPF6luqn8SFZXKTnXwQKBgGv1sCHeMu3I7eBxglqXWWUW2sg0mLYT8tMB9Ufi
ziobfGlu76hMX5FExYLBj+DJNlwuie9WpL+o4saX63lZv+skLASkMGU9toVdTLy4
6ZBYkWLhrYUqOQaVK87CvHsau9Ck7PDWnNS6wAI+oVPd6NRlOyScwrFcZdOuaSPb
zW77AoGALXvpUYa/xDrYERiERH5cVE065ktt+exRPuE+u0XvLJ1l+2h7rnsFhZ51
7n5A81OslefjtSQ+DRQHzLn5CUvDL0ui6oV+xQUXYe3uM/u0Q/lS/0vaUkNss2oe
6x5P1U8QqIT01XAPfE1X02mcQj/FYJGnLFwf5GKUBcvSPhwxkT8=
-----END RSA PRIVATE KEY-----`;

mockNconf.set('AUTH_CERT_KEY', key);

describe('crypto deciphering', function () {
  const crypto = proxyquire('../lib/crypto', {
    nconf: mockNconf
  });

  it('should work for v1 encryption', function () {
    const cipher = 'cfcb8eac5d97b067dfc6544b2affbd94daf8723456d1c24b8fe8cb6f2a88e8aa'
    const expected = 'GoodNewsEveryone';
    assert.equal(
      crypto.decrypt(cipher),
      expected
    );
  });

  it('should work for v2 encryption', function () {
    const cipher = '$2$.f3e9ef58a357b263c49f84aef2aea010.7ae2d5324ec8d976405e076e276f6d04.eb2507a72af23e22eab57c406e55fc43b3527ea505914eda4d541025390fab28';
    const expected = 'GoodNewsEveryone';
    assert.equal(
      crypto.decrypt(cipher),
      expected
    );
  });

  it('encryption/decryption should work for v2 encryption', function () {
    const expected = 'GoodNewsEveryone';
    assert.equal(
      crypto.decrypt(crypto.encrypt(expected)),
      expected
    );
  });
});
