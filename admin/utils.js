const exec = require('child_process').exec;
const execFile = require('child_process').execFile;
const { promisify } = require('util');
const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);

const path = require('path');
const process = require('node:process');
const secureStorage = require('../lib/secureStorage');

/**
 * Restarts the Auth0 ADLDAP service on windows. On other platforms, it's a no-op.
 */

async function restartConnectorService() {
  if (process.platform !== 'win32') {
    return;
  }

  console.log('Restarting Auth0 ADLDAP Service...');
  const isRunning = await isServiceRunning('Auth0 ADLDAP');
  if (isRunning) {
    await execAsync('net stop "Auth0 ADLDAP"');
  }
  await execAsync('net start "Auth0 ADLDAP"');
  console.log('Done.');
}

/**
 * Runs a command in a shell and calls the callback with the output.
 *
 * @param cmd
 * @param args
 * @param callback
 */
function run(cmd, args, callback) {
  const spawn = require('child_process').spawn;
  const dir = path.dirname(cmd);
  const processName = path.basename(cmd);
  const options = {shell: true};
  if (dir !== '.') {
    options.cwd = dir;
  }
  const command = spawn(processName, args, options);
  let result = '';
  command.stderr.on('data', function (data) {
    result += data.toString();
  });
  command.stdout.on('data', function (data) {
    result += data.toString();
  });
  command.on('close', function (code) {
    return callback(result);
  });
}

/**
 * Tries to detect LDAP settings on windows using the settings_detector.exe. Windows only.
 *
 * Note: No idea what this executable is and where the source for it is.
 * TODO: figure out if we can just stop using this and require users to input LDAP settings manually
 *
 * @return {Promise<{LDAP_BASE?: string, LDAP_URL?: string}>}
 */
async function detectLdapSettings() {
  const detected = {};
  try {
    if (process.platform === 'win32') {
      const { stdout } = await execAsync('"' + __dirname + '//settings_detector.exe"');
      const parsed = JSON.parse(stdout);
      console.log(parsed);
      if (!parsed.error) {
        detected.LDAP_BASE = parsed.baseDN;
        detected.LDAP_URL = 'ldap://' + parsed.domainController;
      }
    }
  } catch (err) {
    // don't care
  }
  return detected;
}

/**
 * Gets the hashed admin password from the keychain. If it doesn't exist, or is empty, returns null.
 * @return {Promise<null|string>}
 */
async function getHashedAdminPassword() {
  try {
    const hashedPassword = await secureStorage.get(secureStorage.keys.ADMIN_CONSOLE_PASSWORD);
    if (!hashedPassword) {
      return null;
    }
    return hashedPassword;
  } catch {
    return null;
  }
}

/**
 * Checks to see if a service with the given name is running. Windows only.
 *
 * @param serviceName
 * @return {Promise<*|boolean>}
 */
async function isServiceRunning(serviceName) {
  try {
    const { stdout } = await execFileAsync('sc.exe', ['query', serviceName]);
    return stdout.includes('RUNNING');
  } catch {
    return false;
  }
}

/**
 * Starts the service with the given name. Windows only.
 * @param serviceName
 * @return {Promise<void>}
 */
async function startService(serviceName) {
  await execFileAsync('sc.exe', ['start', serviceName]);
}

/**
 * Stops the service with the given name. Windows only.
 * @param serviceName
 * @return {Promise<void>}
 */
async function stopService(serviceName) {
  await execFileAsync('sc.exe', ['stop', serviceName]);
}

module.exports = {
  restartConnectorService,
  run,
  detectLdapSettings,
  getHashedAdminPassword,
  isServiceRunning,
  startService,
  stopService
};
