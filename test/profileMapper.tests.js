/**
 * isolated-vm has no native build in the test environment, so we stub it in the
 * require cache before loading profileMapper. The stub uses Node's built-in `vm`
 * module to provide the same sandboxing semantics (context isolation, script
 * compilation) that isolated-vm provides in production.
 */

const nodeVm = require('node:vm');

// Minimal isolated-vm stub backed by Node's vm module.
// Records constructor options and script.run options so tests can assert on them.
const vmCalls = { isolateOptions: [], runOptions: [] };

const isolatedVmStub = {
  _calls: vmCalls,
  Isolate: class Isolate {
    constructor(opts) {
      vmCalls.isolateOptions.push(opts || {});
    }
    async createContext() {
      const sandbox = Object.create(null);
      const ctx = nodeVm.createContext(sandbox);
      ctx.__sandbox = sandbox;
      return {
        global: {
          set: async (key, value) => { sandbox[key] = value; },
          get: async (key) => sandbox[key],
        },
        release: () => {},
        __ctx: ctx,
        __sandbox: sandbox,
      };
    }
    async compileScript(code) {
      const script = new nodeVm.Script(code);
      return {
        run: async (context, opts) => {
          vmCalls.runOptions.push(opts || {});
          return script.runInContext(context.__ctx);
        },
      };
    }
    dispose() {}
  },
};

// Inject stub before profileMapper (or any of its deps) loads isolated-vm
require.cache[require.resolve('isolated-vm')] = {
  id: require.resolve('isolated-vm'),
  filename: require.resolve('isolated-vm'),
  loaded: true,
  exports: isolatedVmStub,
};

const { expect } = require('chai');
const path = require('node:path');
const { ProfileMapper } = require('../lib/profileMapper');
const defaultMappingFn = require('../lib/defaultProfileMapping');

const RAW_PROFILE = {
  objectGUID: 'guid-123',
  displayName: 'John Doe',
  sn: 'Doe',
  givenName: 'John',
  sAMAccountName: 'jdoe',
  mail: 'jdoe@example.com',
  groups: ['users', 'admins'],
  department: 'Engineering',
  company: 'Acme',
  userPrincipalName: 'jdoe@example.com',
};

function makeMapper({ fsOverrides = {}, configValues = {} } = {}) {
  const defaultFs = {
    existsSync: () => false,
    readFileSync: () => null,
    mkdirSync: () => {},
    writeFileSync: () => {},
  };

  return new ProfileMapper({
    configModule: { get: (key) => configValues[key] ?? null },
    pathModule: path,
    fsModule: { ...defaultFs, ...fsOverrides },
    vmModule: isolatedVmStub,
  });
}

describe('ProfileMapper', function () {
  this.timeout(10000);

  beforeEach(function () {
    vmCalls.isolateOptions.length = 0;
    vmCalls.runOptions.length = 0;
  });

  describe('loadMappingScript', function () {
    it('returns custom file contents when custom script file exists', function () {
      const script = 'module.exports = function(p) { return p; }';
      const mapper = makeMapper({
        fsOverrides: { existsSync: () => true, readFileSync: () => script },
      });
      expect(mapper.loadMappingScript()).to.equal(script);
    });

    it('returns PROFILE_MAPPER config value when no custom file exists', function () {
      const script = 'module.exports = function(p) { return p; }';
      const mapper = makeMapper({ configValues: { PROFILE_MAPPER: script } });
      expect(mapper.loadMappingScript()).to.equal(script);
    });

    it('returns PROFILE_MAPPER_FILE contents when that file exists', function () {
      const fileScript = 'module.exports = function(p) { return p; }';
      const customPath = '/some/custom/mapper.js';
      const mapper = makeMapper({
        fsOverrides: {
          existsSync: (p) => p === customPath,
          readFileSync: (p) => (p === customPath ? fileScript : null),
        },
        configValues: { PROFILE_MAPPER_FILE: customPath },
      });
      expect(mapper.loadMappingScript()).to.equal(fileScript);
    });

    it('returns null when no custom script is available and fallbackToDefaultScript is false', function () {
      const mapper = makeMapper();
      expect(mapper.loadMappingScript({ fallbackToDefaultScript: false })).to.be.null;
    });

    it('returns default script contents when fallbackToDefaultScript is true and no custom script exists', function () {
      const defaultContents = 'default script';
      const defaultScriptPath = path.join(__dirname, '../lib/defaultProfileMapping.js');
      const mapper = makeMapper({
        fsOverrides: {
          existsSync: () => false,
          readFileSync: (p) => (p === defaultScriptPath ? defaultContents : null),
        },
      });
      expect(mapper.loadMappingScript({ fallbackToDefaultScript: true })).to.equal(defaultContents);
    });

    it('prefers custom file over PROFILE_MAPPER config', function () {
      const fileScript = 'file script';
      const mapper = makeMapper({
        fsOverrides: { existsSync: () => true, readFileSync: () => fileScript },
        configValues: { PROFILE_MAPPER: 'inline script' },
      });
      expect(mapper.loadMappingScript()).to.equal(fileScript);
    });
  });

  describe('saveMappingScript', function () {
    it('writes script contents to a path containing custom.js', function () {
      let savedPath = null;
      let savedContents = null;
      const mapper = makeMapper({
        fsOverrides: {
          mkdirSync: () => {},
          writeFileSync: (p, c) => { savedPath = p; savedContents = c; },
        },
      });

      mapper.saveMappingScript('module.exports = function(p) { return p; }');
      expect(savedPath).to.include('custom.js');
      expect(savedContents).to.equal('module.exports = function(p) { return p; }');
    });

    it('creates the directory recursively before writing', function () {
      let mkdirOptions = null;
      const mapper = makeMapper({
        fsOverrides: {
          mkdirSync: (_, opts) => { mkdirOptions = opts; },
          writeFileSync: () => {},
        },
      });

      mapper.saveMappingScript('module.exports = function(p) { return p; }');
      expect(mkdirOptions).to.have.property('recursive', true);
    });
  });

  describe('mapProfile', function () {
    describe('default mapping (no custom script)', function () {
      it('produces output identical to defaultProfileMapping', async function () {
        const mapper = makeMapper();
        const result = await mapper.mapProfile(RAW_PROFILE);
        expect(result).to.deep.equal(defaultMappingFn(RAW_PROFILE));
      });

      it('maps id from objectGUID', async function () {
        const mapper = makeMapper();
        expect((await mapper.mapProfile(RAW_PROFILE)).id).to.equal('guid-123');
      });

      it('falls back to uid for id when objectGUID is absent', async function () {
        const mapper = makeMapper();
        const result = await mapper.mapProfile({ ...RAW_PROFILE, objectGUID: undefined, uid: 'uid-456' });
        expect(result.id).to.equal('uid-456');
      });

      it('falls back to cn for id when objectGUID and uid are absent', async function () {
        const mapper = makeMapper();
        const result = await mapper.mapProfile({ ...RAW_PROFILE, objectGUID: undefined, uid: undefined, cn: 'cn-789' });
        expect(result.id).to.equal('cn-789');
      });

      it('maps emails array from mail field', async function () {
        const mapper = makeMapper();
        expect((await mapper.mapProfile(RAW_PROFILE)).emails).to.deep.equal([{ value: 'jdoe@example.com' }]);
      });

      it('sets emails to undefined when mail is absent', async function () {
        const mapper = makeMapper();
        const result = await mapper.mapProfile({ ...RAW_PROFILE, mail: undefined });
        expect(result.emails).to.be.undefined;
      });

      it('maps displayName, name, nickname, groups, department, company', async function () {
        const mapper = makeMapper();
        const result = await mapper.mapProfile(RAW_PROFILE);
        expect(result.displayName).to.equal('John Doe');
        expect(result.name).to.deep.equal({ givenName: 'John', familyName: 'Doe' });
        expect(result.nickname).to.equal('jdoe');
        expect(result.groups).to.deep.equal(['users', 'admins']);
        expect(result.department).to.equal('Engineering');
        expect(result.company).to.equal('Acme');
      });
    });

    describe('custom mapping script (sync, 1-arg form)', function () {
      it('executes the script and returns its result', async function () {
        const script = `module.exports = function(p) { return { id: p.mail, custom: true }; }`;
        const mapper = makeMapper({
          fsOverrides: { existsSync: () => true, readFileSync: () => script },
        });
        const result = await mapper.mapProfile(RAW_PROFILE);
        expect(result.id).to.equal('jdoe@example.com');
        expect(result.custom).to.be.true;
      });
    });

    describe('custom mapping script (callback, 2-arg form)', function () {
      it('executes the script and returns the result passed to the callback', async function () {
        const script = `module.exports = function(p, cb) { cb(null, { id: p.mail, callback: true }); }`;
        const mapper = makeMapper({
          fsOverrides: { existsSync: () => true, readFileSync: () => script },
        });
        const result = await mapper.mapProfile(RAW_PROFILE);
        expect(result.id).to.equal('jdoe@example.com');
        expect(result.callback).to.be.true;
      });
    });

    describe('error handling', function () {
      async function expectRejection(mapper) {
        let threw = false;
        try {
          await mapper.mapProfile(RAW_PROFILE);
        } catch (e) {
          threw = true;
        }
        expect(threw, 'expected mapProfile to reject').to.equal(true);
      }

      it('fails authentication when custom script throws', async function () {
        const script = `module.exports = function(p) { throw new Error('boom'); }`;
        const mapper = makeMapper({
          fsOverrides: { existsSync: () => true, readFileSync: () => script },
        });
        await expectRejection(mapper);
      });

      it('fails authentication when callback receives an error', async function () {
        const script = `module.exports = function(p, cb) { cb(new Error('cb error')); }`;
        const mapper = makeMapper({
          fsOverrides: { existsSync: () => true, readFileSync: () => script },
        });
        await expectRejection(mapper);
      });

      it('fails authentication when custom script has a syntax error', async function () {
        const script = `module.exports = function(p) { this is not valid js`;
        const mapper = makeMapper({
          fsOverrides: { existsSync: () => true, readFileSync: () => script },
        });
        await expectRejection(mapper);
      });

      it('fails authentication when a callback mapper never invokes its callback', async function () {
        // In the real isolate this models a mapper that defers cb() to a timer that never fires;
        // it must fail auth rather than resolve to an undefined/empty profile.
        const script = `module.exports = function(p, cb) { /* never calls cb */ }`;
        const mapper = makeMapper({
          fsOverrides: { existsSync: () => true, readFileSync: () => script },
        });
        await expectRejection(mapper);
      });
    });

    describe('inline PROFILE_MAPPER config', function () {
      it('executes the inline script from config', async function () {
        const script = `module.exports = function(p) { return { id: 'from-config' }; }`;
        const mapper = makeMapper({ configValues: { PROFILE_MAPPER: script } });
        expect((await mapper.mapProfile(RAW_PROFILE)).id).to.equal('from-config');
      });
    });

    describe('PROFILE_MAPPING_MEMORY_LIMIT_MB config', function () {
      const script = `module.exports = function(p) { return p; }`;

      it('passes the configured memory limit to the Isolate constructor', async function () {
        const mapper = makeMapper({
          fsOverrides: { existsSync: () => true, readFileSync: () => script },
          configValues: { PROFILE_MAPPING_MEMORY_LIMIT_MB: 64 },
        });
        await mapper.mapProfile(RAW_PROFILE);
        expect(vmCalls.isolateOptions[0]).to.have.property('memoryLimit', 64);
      });

      it('passes the default memory limit (16) when the config value is not set', async function () {
        const mapper = makeMapper({
          fsOverrides: { existsSync: () => true, readFileSync: () => script },
          configValues: { PROFILE_MAPPING_MEMORY_LIMIT_MB: 16 },
        });
        await mapper.mapProfile(RAW_PROFILE);
        expect(vmCalls.isolateOptions[0]).to.have.property('memoryLimit', 16);
      });
    });

    describe('PROFILE_MAPPING_TIMEOUT_MS config', function () {
      const script = `module.exports = function(p) { return p; }`;

      it('passes the configured timeout to script.run', async function () {
        const mapper = makeMapper({
          fsOverrides: { existsSync: () => true, readFileSync: () => script },
          configValues: { PROFILE_MAPPING_TIMEOUT_MS: 500 },
        });
        await mapper.mapProfile(RAW_PROFILE);
        expect(vmCalls.runOptions[0]).to.have.property('timeout', 500);
      });

      it('passes the default timeout (10000) when the config value is not set', async function () {
        const mapper = makeMapper({
          fsOverrides: { existsSync: () => true, readFileSync: () => script },
          configValues: { PROFILE_MAPPING_TIMEOUT_MS: 10000 },
        });
        await mapper.mapProfile(RAW_PROFILE);
        expect(vmCalls.runOptions[0]).to.have.property('timeout', 10000);
      });
    });
  });
});