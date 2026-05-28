const { expect } = require('chai');
const { Config } = require('../lib/config');

// ---------------------------------------------------------------------------
// Mock factories
// ---------------------------------------------------------------------------

function makeFsMock() {
  const written = {};
  return {
    writeFileSync: (path, content) => { written[path] = content; },
    _written: written,
  };
}

/**
 * fileStore: values considered to be on disk (nconf.stores.file)
 * store:     values visible to nconf.get() (env overrides, memory, etc.)
 */
function makeNconfMock({ fileStore = {}, store = {} } = {}) {
  const initCalls = [];
  const mock = {
    _fileStore: { ...fileStore },
    _store: { ...store },
    _initCalls: initCalls,
    use:       function ()    { initCalls.push('use');               return this; },
    overrides: function (v)   { initCalls.push(['overrides', v]);   return this; },
    env:       function ()    { initCalls.push('env');               return this; },
    file:      function (o)   { initCalls.push(['file', o]);        return this; },
    defaults:  function (d)   { initCalls.push(['defaults', d]);    return this; },
    get:       function (key) { return this._store[key] !== undefined ? this._store[key] : this._fileStore[key]; },
    set:       function (key, val) { this._store[key] = val; },
    clear:     function (key) { delete this._store[key]; },
    stores: {
      file: {
        get: function (key) { return mock._fileStore[key]; },
      },
    },
  };
  return mock;
}

function makeProcessMock(env = {}, platform = 'linux') {
  return { env, platform };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Config', () => {
  describe('inMemoryMode()', () => {
    it('returns true when OVERRIDE_CONFIG is "false"', () => {
      const config = new Config({ processModule: makeProcessMock({ OVERRIDE_CONFIG: 'false' }) });
      expect(config.inMemoryMode()).to.be.true;
    });

    it('returns false when OVERRIDE_CONFIG is not set', () => {
      const config = new Config({ processModule: makeProcessMock({}) });
      expect(config.inMemoryMode()).to.be.false;
    });

    it('returns false when OVERRIDE_CONFIG is "true"', () => {
      const config = new Config({ processModule: makeProcessMock({ OVERRIDE_CONFIG: 'true' }) });
      expect(config.inMemoryMode()).to.be.false;
    });
  });

  describe('initialize()', () => {
    describe('in memory mode (OVERRIDE_CONFIG=false)', () => {
      it('calls use("memory"), overrides, env, defaults — in that order', async () => {
        const nconfMock = makeNconfMock();
        const config = new Config({
          nconfModule: nconfMock,
          processModule: makeProcessMock({ OVERRIDE_CONFIG: 'false' }),
        });

        await config.initialize();

        expect(nconfMock._initCalls[0]).to.equal('use');
        expect(nconfMock._initCalls[1][0]).to.equal('overrides');
        expect(nconfMock._initCalls[2]).to.equal('env');
        expect(nconfMock._initCalls[3][0]).to.equal('defaults');
      });

      it('sets OVERRIDE_CONFIG to false in overrides', async () => {
        const nconfMock = makeNconfMock();
        const config = new Config({
          nconfModule: nconfMock,
          processModule: makeProcessMock({ OVERRIDE_CONFIG: 'false' }),
        });

        await config.initialize();

        const overridesCall = nconfMock._initCalls.find(c => Array.isArray(c) && c[0] === 'overrides');
        expect(overridesCall[1]).to.deep.equal({ OVERRIDE_CONFIG: false });
      });
    });

    describe('in file mode', () => {
      it('calls env, file, defaults — in that order', async () => {
        const nconfMock = makeNconfMock();
        const config = new Config({
          nconfModule: nconfMock,
          processModule: makeProcessMock({}),
        });

        await config.initialize();

        expect(nconfMock._initCalls[0]).to.equal('env');
        expect(nconfMock._initCalls[1][0]).to.equal('file');
        expect(nconfMock._initCalls[2][0]).to.equal('defaults');
      });

      it('does not call use("memory")', async () => {
        const nconfMock = makeNconfMock();
        const config = new Config({
          nconfModule: nconfMock,
          processModule: makeProcessMock({}),
        });

        await config.initialize();

        expect(nconfMock._initCalls).to.not.include('use');
      });
    });
  });

  describe('get()', () => {
    it('returns the value from nconf', () => {
      const config = new Config({
        nconfModule: makeNconfMock({ store: { PORT: 8080 } }),
        processModule: makeProcessMock(),
      });
      expect(config.get('PORT')).to.equal(8080);
    });

    it('returns undefined for unknown keys', () => {
      const config = new Config({
        nconfModule: makeNconfMock(),
        processModule: makeProcessMock(),
      });
      expect(config.get('NONEXISTENT')).to.be.undefined;
    });
  });

  describe('set()', () => {
    it('makes the value available via get()', () => {
      const nconfMock = makeNconfMock();
      const config = new Config({ nconfModule: nconfMock, processModule: makeProcessMock() });

      config.set('PORT', 9000);

      expect(config.get('PORT')).to.equal(9000);
    });
  });

  describe('clear()', () => {
    it('removes the value so get() returns undefined', () => {
      const nconfMock = makeNconfMock({ store: { PORT: 8080 } });
      const config = new Config({ nconfModule: nconfMock, processModule: makeProcessMock() });

      config.clear('PORT');

      expect(config.get('PORT')).to.be.undefined;
    });
  });

  describe('getAll()', () => {
    describe('in file mode', () => {
      it('returns only keys present in the file store', () => {
        const nconfMock = makeNconfMock({
          fileStore: { LDAP_URL: 'ldap://localhost', PORT: 4000 },
          store:     { LDAP_URL: 'ldap://localhost', PORT: 4000 },
        });
        const config = new Config({ nconfModule: nconfMock, processModule: makeProcessMock() });

        const result = config.getAll();

        expect(result).to.include.keys('LDAP_URL', 'PORT');
      });

      it('excludes keys that are only in env/memory, not in the file store', () => {
        const nconfMock = makeNconfMock({
          fileStore: { LDAP_URL: 'ldap://localhost' },
          store:     { LDAP_URL: 'ldap://localhost', PORT: 9000 }, // PORT is env-only
        });
        const config = new Config({ nconfModule: nconfMock, processModule: makeProcessMock() });

        const result = config.getAll();

        expect(result).to.have.key('LDAP_URL');
        expect(result).to.not.have.key('PORT');
      });

      it('excludes keys not in the allow list even if present in file store', () => {
        const nconfMock = makeNconfMock({
          fileStore: { LDAP_URL: 'ldap://localhost', SOME_SECRET: 'hunter2' },
          store:     { LDAP_URL: 'ldap://localhost', SOME_SECRET: 'hunter2' },
        });
        const config = new Config({ nconfModule: nconfMock, processModule: makeProcessMock() });

        const result = config.getAll();

        expect(result).to.have.key('LDAP_URL');
        expect(result).to.not.have.key('SOME_SECRET');
      });

      it('returns the nconf chain value, not the raw file value (env can override)', () => {
        // File has PORT=4000 but env has PORT=9000 in the full nconf chain
        const nconfMock = makeNconfMock({
          fileStore: { PORT: 4000 },
          store:     { PORT: 9000 },
        });
        const config = new Config({ nconfModule: nconfMock, processModule: makeProcessMock() });

        const result = config.getAll();

        expect(result.PORT).to.equal(9000);
      });
    });

    describe('in memory mode (OVERRIDE_CONFIG=false)', () => {
      it('returns allow-listed keys present in the nconf store', () => {
        const nconfMock = makeNconfMock({
          store: { LDAP_URL: 'ldap://localhost', PORT: 4000 },
        });
        const config = new Config({
          nconfModule: nconfMock,
          processModule: makeProcessMock({ OVERRIDE_CONFIG: 'false' }),
        });

        const result = config.getAll();

        expect(result).to.include.keys('LDAP_URL', 'PORT');
      });

      it('excludes keys not in the allow list', () => {
        const nconfMock = makeNconfMock({
          store: { LDAP_URL: 'ldap://localhost', NOT_ALLOWED_KEY: 'value' },
        });
        const config = new Config({
          nconfModule: nconfMock,
          processModule: makeProcessMock({ OVERRIDE_CONFIG: 'false' }),
        });

        const result = config.getAll();

        expect(result).to.not.have.key('NOT_ALLOWED_KEY');
      });
    });
  });

  describe('save()', () => {
    it('is a no-op in memory mode — does not write any files', async () => {
      const fsMock = makeFsMock();
      const config = new Config({
        fsModule: fsMock,
        nconfModule: makeNconfMock(),
        processModule: makeProcessMock({ OVERRIDE_CONFIG: 'false' }),
      });

      await config.save();

      expect(Object.keys(fsMock._written)).to.be.empty;
    });

    it('writes JSON containing allow-listed file-store keys', async () => {
      const fsMock = makeFsMock();
      const config = new Config({
        fsModule: fsMock,
        nconfModule: makeNconfMock({ fileStore: { LDAP_URL: 'ldap://localhost', PORT: 4000 } }),
        processModule: makeProcessMock(),
      });

      await config.save();

      const written = Object.values(fsMock._written)[0];
      const parsed = JSON.parse(written);
      expect(parsed).to.include.keys('LDAP_URL', 'PORT');
    });

    it('does not write keys absent from the file store', async () => {
      const fsMock = makeFsMock();
      const config = new Config({
        fsModule: fsMock,
        nconfModule: makeNconfMock({
          fileStore: { LDAP_URL: 'ldap://localhost' },
          store:     { LDAP_URL: 'ldap://localhost', PORT: 9000 }, // PORT is env-only
        }),
        processModule: makeProcessMock(),
      });

      await config.save();

      const written = Object.values(fsMock._written)[0];
      const parsed = JSON.parse(written);
      expect(parsed).to.not.have.key('PORT');
    });

    it('does not write keys not in the allow list', async () => {
      const fsMock = makeFsMock();
      const config = new Config({
        fsModule: fsMock,
        nconfModule: makeNconfMock({ fileStore: { LDAP_URL: 'ldap://localhost', SOME_SECRET: 'hunter2' } }),
        processModule: makeProcessMock(),
      });

      await config.save();

      const written = Object.values(fsMock._written)[0];
      const parsed = JSON.parse(written);
      expect(parsed).to.not.have.key('SOME_SECRET');
    });

  });
});
