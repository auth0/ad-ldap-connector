const { expect } = require('chai');
const jwt = require('jsonwebtoken');

const { rejectUnverified, INVALID_SIGNATURE } = require('../lib/rejectUnverified');

function signatureError() {
  const err = new Error('invalid signature');
  err.name = 'JsonWebTokenError';
  return err;
}

describe('rejectUnverified', () => {
  let sent;
  const send = (event, payload) => sent.push({ event, payload });

  beforeEach(() => {
    sent = [];
  });

  it('answers on the reply event of the request, with the pid taken from the unverified token', () => {
    const token = jwt.sign({ pid: 'abc123', username: 'jdoe' }, 'some secret');

    const replied = rejectUnverified(token, signatureError(), '_search_users_result', send);

    expect(replied).to.equal(true);
    expect(sent).to.deep.equal([
      {
        event: 'abc123_search_users_result',
        payload: {
          err: {
            code: INVALID_SIGNATURE,
            message: 'The connector could not verify the signature of the request.',
            reason: 'JsonWebTokenError'
          }
        }
      }
    ]);
  });

  it('uses the invalid_signature code the hub looks for', () => {
    expect(INVALID_SIGNATURE).to.equal('invalid_signature');
  });

  it('does not put the verification error text in the reply', () => {
    const token = jwt.sign({ pid: 'abc123' }, 'some secret');
    const err = signatureError();
    err.message = 'No signing key matching kid "k1" was found in https://tenant.example.com/.well-known/jwks.json.';

    rejectUnverified(token, err, '_result', send);

    expect(JSON.stringify(sent)).to.not.contain('tenant.example.com');
  });

  it('stays silent when the token carries no pid to answer on', () => {
    const token = jwt.sign({ username: 'jdoe' }, 'some secret');

    expect(rejectUnverified(token, signatureError(), '_result', send)).to.equal(false);
    expect(sent).to.have.length(0);
  });

  it('stays silent when the token cannot be decoded at all', () => {
    expect(rejectUnverified('not-a-token', signatureError(), '_result', send)).to.equal(false);
    expect(rejectUnverified(undefined, signatureError(), '_result', send)).to.equal(false);
    expect(sent).to.have.length(0);
  });

  ['TokenExpiredError', 'NotBeforeError'].forEach((name) => {
    it(`answers for ${name} too and says why, so the hub can tell a clock problem from a key problem`, () => {
      const token = jwt.sign({ pid: 'abc123' }, 'some secret');
      const err = signatureError();
      err.name = name;

      expect(rejectUnverified(token, err, '_result', send)).to.equal(true);
      expect(sent).to.have.length(1);
      expect(sent[0].payload.err.reason).to.equal(name);
    });
  });

  it('leaves the reason out when there is no verification error to name', () => {
    const token = jwt.sign({ pid: 'abc123' }, 'some secret');

    rejectUnverified(token, undefined, '_result', send);

    expect(sent[0].payload.err).to.not.have.property('reason');
  });
});
