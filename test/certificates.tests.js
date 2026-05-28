const path = require('path');
const { expect } = require('chai');
const { Certificates } = require('../lib/certificates');

// These paths mirror the module-level constants in lib/certificates.js
const CERT_PEM_PATH = path.join(__dirname, '../lib', '../', 'data', 'certs', 'cert.pem');
const CERT_KEY_PATH = path.join(__dirname, '../lib', '../', 'data', 'certs', 'cert.key');

// ---------------------------------------------------------------------------
// Mock factories
// ---------------------------------------------------------------------------

function makeFsMock(files = {}) {
  const written = {};
  return {
    existsSync: (p) => Object.prototype.hasOwnProperty.call(files, p),
    readFileSync: (p) => files[p],
    writeFileSync: (p, content) => { written[p] = content; files[p] = content; },
    mkdirSync: () => {},
    _written: written,
    _files: files,
  };
}

function makeExecMock() {
  const calls = [];
  const fn = async (cmd) => { calls.push(cmd); };
  fn.calls = calls;
  return fn;
}

function makeConfigMock(store = {}) {
  const s = { ...store };
  return {
    get: (key) => s[key],
    clear: (key) => { delete s[key]; },
    _store: s,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Certificates', () => {
  describe('getCertificate()', () => {
    it('returns null when cert file does not exist', () => {
      const certs = new Certificates({ fsModule: makeFsMock() });
      expect(certs.getCertificate()).to.be.null;
    });

    it('reads and returns cert contents from file when the file exists', () => {
      const fsMock = makeFsMock({ [CERT_PEM_PATH]: 'cert-contents' });
      const certs = new Certificates({ fsModule: fsMock });
      expect(certs.getCertificate()).to.equal('cert-contents');
    });

    it('caches the cert so the file is only read once on subsequent calls', () => {
      let readCount = 0;
      const fsMock = {
        existsSync: () => true,
        readFileSync: () => { readCount++; return 'cert-data'; },
        writeFileSync: () => {},
        mkdirSync: () => {},
      };
      const certs = new Certificates({ fsModule: fsMock });

      certs.getCertificate();
      certs.getCertificate();

      expect(readCount).to.equal(1);
    });
  });

  describe('getPrivateKey()', () => {
    it('returns null when key file does not exist', () => {
      const certs = new Certificates({ fsModule: makeFsMock() });
      expect(certs.getPrivateKey()).to.be.null;
    });

    it('reads and returns key contents from file when the file exists', () => {
      const fsMock = makeFsMock({ [CERT_KEY_PATH]: 'key-contents' });
      const certs = new Certificates({ fsModule: fsMock });
      expect(certs.getPrivateKey()).to.equal('key-contents');
    });

    it('caches the key so the file is only read once on subsequent calls', () => {
      let readCount = 0;
      const fsMock = {
        existsSync: () => true,
        readFileSync: () => { readCount++; return 'key-data'; },
        writeFileSync: () => {},
        mkdirSync: () => {},
      };
      const certs = new Certificates({ fsModule: fsMock });

      certs.getPrivateKey();
      certs.getPrivateKey();

      expect(readCount).to.equal(1);
    });
  });

  describe('initialize()', () => {
    describe('config migration', () => {
      it('writes AUTH_CERT from config to the pem file and clears it', async () => {
        const fsMock = makeFsMock();
        const execMock = makeExecMock();
        const configMock = makeConfigMock({ AUTH_CERT: 'pem-from-config' });
        const certs = new Certificates({
          fsModule: fsMock,
          execFunction: execMock,
          configModule: configMock,
          processModule: { platform: 'linux' },
        });

        await certs.initialize();

        expect(fsMock._written[CERT_PEM_PATH]).to.equal('pem-from-config');
        expect(configMock.get('AUTH_CERT')).to.be.undefined;
      });

      it('writes AUTH_CERT_KEY from config to the key file and clears it', async () => {
        const fsMock = makeFsMock();
        const execMock = makeExecMock();
        const configMock = makeConfigMock({ AUTH_CERT_KEY: 'key-from-config' });
        const certs = new Certificates({
          fsModule: fsMock,
          execFunction: execMock,
          configModule: configMock,
          processModule: { platform: 'linux' },
        });

        await certs.initialize();

        expect(fsMock._written[CERT_KEY_PATH]).to.equal('key-from-config');
        expect(configMock.get('AUTH_CERT_KEY')).to.be.undefined;
      });
    });

    describe('skipping generation', () => {
      it('does not generate or write new files when cert and key already exist on disk', async () => {
        const fsMock = makeFsMock({ [CERT_PEM_PATH]: 'existing-cert', [CERT_KEY_PATH]: 'existing-key' });
        const execMock = makeExecMock();
        const certs = new Certificates({
          fsModule: fsMock,
          execFunction: execMock,
          configModule: makeConfigMock(),
          processModule: { platform: 'linux' },
        });

        await certs.initialize({ connectionName: 'my-conn', connectionDomain: 'example.com' });

        expect(Object.keys(fsMock._written)).to.be.empty;
        expect(execMock.calls).to.be.empty;
      });

      it('does not generate files when connectionName is missing', async () => {
        const fsMock = makeFsMock();
        const execMock = makeExecMock();
        const certs = new Certificates({
          fsModule: fsMock,
          execFunction: execMock,
          configModule: makeConfigMock(),
          processModule: { platform: 'linux' },
        });

        await certs.initialize({ connectionDomain: 'example.com' });

        expect(Object.keys(fsMock._written)).to.be.empty;
        expect(execMock.calls).to.be.empty;
      });

      it('does not generate files when connectionDomain is missing', async () => {
        const fsMock = makeFsMock();
        const execMock = makeExecMock();
        const certs = new Certificates({
          fsModule: fsMock,
          execFunction: execMock,
          configModule: makeConfigMock(),
          processModule: { platform: 'linux' },
        });

        await certs.initialize({ connectionName: 'my-conn' });

        expect(Object.keys(fsMock._written)).to.be.empty;
        expect(execMock.calls).to.be.empty;
      });
    });

    describe('certificate generation', () => {
      it('writes a PEM certificate and private key to the expected file paths', async () => {
        const fsMock = makeFsMock();
        const certs = new Certificates({
          fsModule: fsMock,
          execFunction: makeExecMock(),
          configModule: makeConfigMock(),
          processModule: { platform: 'linux' },
        });

        await certs.initialize({ connectionName: 'test-conn', connectionDomain: 'example.com' });

        expect(fsMock._written[CERT_PEM_PATH]).to.be.a('string').and.include('BEGIN CERTIFICATE');
        expect(fsMock._written[CERT_KEY_PATH]).to.be.a('string').and.include('BEGIN');
      });

      it('makes the generated cert available via getCertificate() from cache', async () => {
        const fsMock = makeFsMock();
        const certs = new Certificates({
          fsModule: fsMock,
          execFunction: makeExecMock(),
          configModule: makeConfigMock(),
          processModule: { platform: 'linux' },
        });

        await certs.initialize({ connectionName: 'test-conn', connectionDomain: 'example.com' });

        expect(certs.getCertificate()).to.be.a('string').and.include('BEGIN CERTIFICATE');
      });

      it('makes the generated key available via getPrivateKey() from cache', async () => {
        const fsMock = makeFsMock();
        const certs = new Certificates({
          fsModule: fsMock,
          execFunction: makeExecMock(),
          configModule: makeConfigMock(),
          processModule: { platform: 'linux' },
        });

        await certs.initialize({ connectionName: 'test-conn', connectionDomain: 'example.com' });

        expect(certs.getPrivateKey()).to.be.a('string').and.include('BEGIN');
      });
    });

  });
});