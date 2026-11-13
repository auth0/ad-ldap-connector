const { expect } = require('chai');
const fs = require('fs');
const path = require('path');
const sinon = require('sinon');
const express = require('express');
const request = require('supertest');

const wsfed = require('../../lib/wsfed');
const samlUtils = require('../../lib/saml/utils');

const FIXTURES = path.join(__dirname, 'fixtures');
const KEY  = fs.readFileSync(path.join(__dirname, 'fixture', 'wsfed.test-cert.key'));
const CERT = fs.readFileSync(path.join(__dirname, 'fixture', 'wsfed.test-cert.pem'));

const FAKE_USER = {
  id: 'user-id-123',
  emails: [{ value: 'jane@example.com' }],
  displayName: 'Jane Doe',
  name: { givenName: 'Jane', familyName: 'Doe' }
};

function readExpected(name) {
  return fs.readFileSync(path.join(FIXTURES, name), 'utf8');
}

function writeExpected(name, contents) {
  fs.writeFileSync(path.join(FIXTURES, name), contents, 'utf8');
}

describe('expected output byte-equality', function () {
  let clock;
  let uidStub;

  before(function () {
    if (!fs.existsSync(FIXTURES)) fs.mkdirSync(FIXTURES);
    clock = sinon.useFakeTimers({
      now: new Date('2026-01-01T00:00:00.000Z').getTime(),
      toFake: ['Date']
    });
    uidStub = sinon.stub(samlUtils, 'uid').returns('FIXEDFIXEDFIXEDFIXEDFIXEDFIXEDXX');
  });

  after(function () {
    clock.restore();
    uidStub.restore();
  });

  it('produces a stable signed assertion for /wsfed', function (done) {
    const app = express();
    app.use((req, res, next) => { req.user = FAKE_USER; next(); });
    app.get('/wsfed', wsfed.auth({
      issuer: 'urn:test-issuer',
      cert: CERT,
      key: KEY,
      getPostURL: function (wtrealm, wreply, req, cb) { cb(null, 'https://example.test/cb'); }
    }));

    request(app)
      .get('/wsfed?wa=wsignin1.0&wctx=ctx-123&wtrealm=urn:test-realm')
      .set('Host', 'idp.example.test')
      .expect(200)
      .end(function (err, res) {
        if (err) return done(err);
        if (process.env.UPDATE_EXPECTED) {
          writeExpected('expected-assertion.xml', res.text);
          return done();
        }
        expect(res.text).to.equal(readExpected('expected-assertion.xml'));
        done();
      });
  });

  it('produces a stable metadata document', function (done) {
    const app = express();
    app.get('/wsfed/FederationMetadata/2007-06/FederationMetadata.xml', wsfed.metadata({
      cert: CERT,
      issuer: 'urn:test-issuer'
    }));

    request(app)
      .get('/wsfed/FederationMetadata/2007-06/FederationMetadata.xml')
      .set('Host', 'idp.example.test')
      .expect(200)
      .expect('Content-Type', /xml/)
      .end(function (err, res) {
        if (err) return done(err);
        if (process.env.UPDATE_EXPECTED) {
          writeExpected('expected-metadata.xml', res.text);
          return done();
        }
        expect(res.text).to.equal(readExpected('expected-metadata.xml'));
        done();
      });
  });
});
