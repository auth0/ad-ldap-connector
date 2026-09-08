const { expect } = require('chai');
const proxyquire = require('proxyquire');
const path = require('node:path');

// BRIDGE_FILE_PATH mirrors the constant in the module under test
const BRIDGE_FILE_PATH = path.join(__dirname, '../data/.connector-bridge');

// existsSyncResult is mutated per-test so the closure-based stub picks up the current value
let existsSyncResult = false;

// Load module once with existsSync stubbed; all other behaviour is controlled
// via constructor injection on each test's bridge instance.
const { ConnectorServiceSecretsBridge } = proxyquire('../lib/connectorServiceSecretsBridge', {
  fs: { existsSync: () => existsSyncResult },
});

function makeBridge({ bridgeData = null } = {}) {
  const writtenFiles = {};
  const unlinkedFiles = [];
  const storedSecrets = {};

  const mockAsyncFs = {
    readFile: async () => {
      if (bridgeData !== null) return bridgeData;
      throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    },
    writeFile: async (filePath, contents) => { writtenFiles[filePath] = contents; },
    unlink: async (filePath) => { unlinkedFiles.push(filePath); },
  };

  const mockSecureStorage = {
    store: async (key, value) => { storedSecrets[key] = value; },
  };

  const bridge = new ConnectorServiceSecretsBridge({
    fsModule: mockAsyncFs,
    secureStorageModule: mockSecureStorage,
  });

  return { bridge, writtenFiles, unlinkedFiles, storedSecrets };
}

describe('ConnectorServiceSecretsBridge', function () {
  beforeEach(function () {
    existsSyncResult = false;
  });

  describe('store()', function () {
    it('creates a new bridge file with the given key/value when no file exists', async function () {
      existsSyncResult = false;
      const { bridge, writtenFiles } = makeBridge();

      await bridge.store('LDAP_BIND_PASSWORD', 's3cr3t');

      const written = JSON.parse(writtenFiles[BRIDGE_FILE_PATH]);
      expect(written).to.deep.equal({ LDAP_BIND_PASSWORD: 's3cr3t' });
    });

    it('writes to the .connector-bridge file path', async function () {
      existsSyncResult = false;
      const { bridge, writtenFiles } = makeBridge();

      await bridge.store('key', 'value');

      expect(Object.keys(writtenFiles)[0]).to.include('.connector-bridge');
    });

    it('writes valid JSON', async function () {
      existsSyncResult = false;
      const { bridge, writtenFiles } = makeBridge();

      await bridge.store('key', 'value');

      expect(() => JSON.parse(writtenFiles[BRIDGE_FILE_PATH])).to.not.throw();
    });

    it('merges new key with existing bridge file contents', async function () {
      existsSyncResult = true;
      const existing = JSON.stringify({ EXISTING_KEY: 'existing-value' });
      const { bridge, writtenFiles } = makeBridge({ bridgeData: existing });

      await bridge.store('NEW_KEY', 'new-value');

      const written = JSON.parse(writtenFiles[BRIDGE_FILE_PATH]);
      expect(written).to.deep.equal({ EXISTING_KEY: 'existing-value', NEW_KEY: 'new-value' });
    });

    it('overwrites an existing key in the bridge file', async function () {
      existsSyncResult = true;
      const existing = JSON.stringify({ MY_KEY: 'old-value' });
      const { bridge, writtenFiles } = makeBridge({ bridgeData: existing });

      await bridge.store('MY_KEY', 'updated-value');

      const written = JSON.parse(writtenFiles[BRIDGE_FILE_PATH]);
      expect(written.MY_KEY).to.equal('updated-value');
    });

    it('preserves other keys when overwriting one', async function () {
      existsSyncResult = true;
      const existing = JSON.stringify({ KEY_A: 'a', KEY_B: 'b' });
      const { bridge, writtenFiles } = makeBridge({ bridgeData: existing });

      await bridge.store('KEY_A', 'updated-a');

      const written = JSON.parse(writtenFiles[BRIDGE_FILE_PATH]);
      expect(written.KEY_B).to.equal('b');
    });
  });

  describe('processBridgeFile()', function () {
    describe('when no bridge file exists', function () {
      it('does not call secureStorage.store', async function () {
        existsSyncResult = false;
        const { bridge, storedSecrets } = makeBridge();

        await bridge.processBridgeFile();

        expect(Object.keys(storedSecrets).length).to.equal(0);
      });

      it('does not unlink any file', async function () {
        existsSyncResult = false;
        const { bridge, unlinkedFiles } = makeBridge();

        await bridge.processBridgeFile();

        expect(unlinkedFiles.length).to.equal(0);
      });
    });

    describe('when a valid bridge file exists', function () {
      it('stores each key/value pair in secure storage', async function () {
        existsSyncResult = true;
        const data = JSON.stringify({ FOO: 'bar', BAZ: 'qux' });
        const { bridge, storedSecrets } = makeBridge({ bridgeData: data });

        await bridge.processBridgeFile();

        expect(storedSecrets).to.deep.equal({ FOO: 'bar', BAZ: 'qux' });
      });

      it('stores the correct value for a single key', async function () {
        existsSyncResult = true;
        const data = JSON.stringify({ LDAP_BIND_PASSWORD: 'super-secret' });
        const { bridge, storedSecrets } = makeBridge({ bridgeData: data });

        await bridge.processBridgeFile();

        expect(storedSecrets['LDAP_BIND_PASSWORD']).to.equal('super-secret');
      });

      it('unlinks the bridge file after processing', async function () {
        existsSyncResult = true;
        const data = JSON.stringify({ KEY: 'VALUE' });
        const { bridge, unlinkedFiles } = makeBridge({ bridgeData: data });

        await bridge.processBridgeFile();

        expect(unlinkedFiles).to.include(BRIDGE_FILE_PATH);
      });

      it('unlinks exactly once', async function () {
        existsSyncResult = true;
        const data = JSON.stringify({ KEY: 'VALUE' });
        const { bridge, unlinkedFiles } = makeBridge({ bridgeData: data });

        await bridge.processBridgeFile();

        expect(unlinkedFiles.length).to.equal(1);
      });

      it('processes multiple keys from the bridge file', async function () {
        existsSyncResult = true;
        const data = JSON.stringify({ A: '1', B: '2', C: '3' });
        const { bridge, storedSecrets } = makeBridge({ bridgeData: data });

        await bridge.processBridgeFile();

        expect(storedSecrets.A).to.equal('1');
        expect(storedSecrets.B).to.equal('2');
        expect(storedSecrets.C).to.equal('3');
      });
    });

    describe('when the bridge file contains malformed JSON', function () {
      it('does not store any secrets', async function () {
        existsSyncResult = true;
        const { bridge, storedSecrets } = makeBridge({ bridgeData: 'not valid json {{{' });

        await bridge.processBridgeFile();

        expect(Object.keys(storedSecrets).length).to.equal(0);
      });

      it('still unlinks the malformed file', async function () {
        existsSyncResult = true;
        const { bridge, unlinkedFiles } = makeBridge({ bridgeData: 'not valid json {{{' });

        await bridge.processBridgeFile();

        expect(unlinkedFiles).to.include(BRIDGE_FILE_PATH);
      });
    });
  });
});