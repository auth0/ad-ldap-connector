const path = require('node:path');
const fs = require('node:fs');
const isolatedVM = require('isolated-vm');
const config = require('./config');

class ProfileMapper {
  #config;
  #path;
  #fs;
  #vm;
  #defaultMappingFunction;
  #defaultMappingScriptPath;
  #customMappingScriptPath;

  constructor({ configModule, pathModule, fsModule, vmModule }) {
    this.#config = configModule;
    this.#path = pathModule;
    this.#fs = fsModule;
    this.#vm = vmModule;
    this.#defaultMappingFunction = require('./defaultProfileMapping');
    this.#defaultMappingScriptPath = this.#path.join(__dirname, 'defaultProfileMapping.js');
    this.#customMappingScriptPath = this.#path.join(__dirname, '../data/profileMapper/custom.js');
  }

  /**
   * Given a raw profile, maps it using custom (or default) profile mapping specified in the current configuration.
   *
   * @param rawProfile
   * @return {Promise<*>}
   */
  async mapProfile(rawProfile)
  {
    let isolate, context;
    try {
      const mappingScript = this.loadMappingScript({
        fallbackToDefaultScript: false
      });
      if (!mappingScript) {
        return this.#defaultMappingFunction(rawProfile);
      }

      const memoryLimit = this.#config.get('PROFILE_MAPPING_MEMORY_LIMIT_MB');
      const timeout = this.#config.get('PROFILE_MAPPING_TIMEOUT_MS');

      isolate = new this.#vm.Isolate({ memoryLimit });
      context = await isolate.createContext();
      const global = context.global;

      await global.set('__rawProfile', rawProfile, { copy: true });
      await global.set('__result', undefined, { copy: true });
      await global.set('__error', null, { copy: true });
      await global.set('__mapperWithCallback', false, { copy: true });

      const script = await isolate.compileScript(`
        (function() {
          var module = { exports: {} };
          ${mappingScript}
          var fn = module.exports;
          if (fn.length === 1) {
            __result = fn(__rawProfile);
          } else {
            __mapperWithCallback = true;
            fn(__rawProfile, function(err, result) {
              __error = err ? String(err) : null;
              __result = result;
            });
          }
        })();
      `);
      await script.run(context, { timeout });

      const mapperWithCallback = await global.get('__mapperWithCallback', { copy: true });
      if (mapperWithCallback) {
        console.error('Profile mapping scripts with a callback are not supported and can result in unexpected behavior. Modify your script to perform mapping synchronously.');
      }
      const error = await global.get('__error', { copy: true });
      if (error) {
        throw new Error(error);
      }

      // A mapper that returns/yields nothing (including a callback-style mapper that never fired,
      // since the isolate has no event loop) leaves __result undefined. Fail rather than
      // authenticating with an empty profile.
      const result = await global.get('__result', { copy: true });
      if (result === undefined) {
        throw new Error('Custom mapping returned an empty profile.');
      }
      return result;
    } catch (err) {
      console.error(`Could not use custom mapping for user profile because: ${err.message}. Failing authentication.`);
      throw err;
    } finally {
      if (context) context.release();
      if (isolate) isolate.dispose();
    }
  }

  /**
   * Loads the most appropriate profile mapping script depending on config values, custom saved files etc.
   * Optionally, falls back to the default script. Otherwise, returns null if no viable custom profile mapping script
   * is available.
   *
   * @param fallbackToDefaultScript if true, falls back to returning the default profile mapping script contents
   * @return {*|null} script contents as text
   */
  loadMappingScript({ fallbackToDefaultScript } = { fallbackToDefaultScript: false }) {
    if (this.#fs.existsSync(this.#customMappingScriptPath)) {
      return this.#fs.readFileSync(this.#customMappingScriptPath, 'utf8');
    }

    if (this.#config.get('PROFILE_MAPPER')) {
      console.log('Using profile mapping script from PROFILE_MAPPER config value.');
      return this.#config.get('PROFILE_MAPPER');
    }

    const customPathFromConfig = this.#config.get('PROFILE_MAPPER_FILE');
    if (customPathFromConfig && this.#fs.existsSync(customPathFromConfig)) {
      return this.#fs.readFileSync(customPathFromConfig, 'utf8');
    }

    if (fallbackToDefaultScript) {
      return this.#fs.readFileSync(this.#defaultMappingScriptPath, 'utf8');
    }
    return null;
  }

  /**
   * Saves the given script contents to the custom profile mapping script file at data/profileMapper/custom.js
   * @param {string} scriptContents
   */
  saveMappingScript(scriptContents) {
    this.#fs.mkdirSync(this.#path.dirname(this.#customMappingScriptPath), { recursive: true });
    this.#fs.writeFileSync(this.#customMappingScriptPath, scriptContents);
  }
}

const _profileMapper = new ProfileMapper({
  configModule: config,
  pathModule: path,
  fsModule: fs,
  vmModule: isolatedVM
});
module.exports = _profileMapper;
module.exports.ProfileMapper = ProfileMapper;
