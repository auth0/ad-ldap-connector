/**
 * This script migrates data from previous versions of the AD LDAP Connector. Can be run as is from the command line
 * (or installer) or included in a larger install script.
 *
 */

const fs = require('node:fs/promises');
const { existsSync } = require('fs');
const path = require('node:path');
const secureStorage = require('../lib/secureStorage');
const config = require('../lib/config');
const crypto = require('../lib/crypto');
const secretsBridge = require('../lib/connectorServiceSecretsBridge');

const INSTALL_PATH = path.join(__dirname, '../');

/**
 * Helper function to build a path relative to the installation directory
 *
 * @param relativePath
 * @return {string}
 */
function buildPath(relativePath) {
  return path.join(INSTALL_PATH, relativePath);
}

/**
 * Moves data from legacy locations to newer more restricted locations.
 *
 * @return {Promise<void>}
 */
async function migrateData() {
  // Ensure data directory exists
  await fs.mkdir(buildPath('data'), { recursive: true });

  // Move the config file if it's in the root directory
  console.log('Moving config...');
  if (existsSync(buildPath('config.json'))) {
    console.log('Moving config.json');
    await fs.rename(buildPath('config.json'), buildPath('data/config.json'));
  }
  console.log('- Done');
  console.log('------------------\n');

  // Move certs if they are in the root directory
  console.log('Moving certs...');
  if (existsSync(buildPath('certs'))) {
    console.log('Moving certs');
    await fs.rename(buildPath('certs'), buildPath('data/certs'));
  }
  console.log('- Done');
  console.log('------------------\n');

  // Move any logs
  console.log('Moving logs...');
  const connectorLogsPattern = buildPath('logs*.log');
  const connectorLogsDirectory = buildPath('data/logs/connector');
  await fs.mkdir(connectorLogsDirectory, { recursive: true });
  try {
    for await (const entry of fs.glob(connectorLogsPattern)) {
      const destination = path.join(connectorLogsDirectory, path.basename(entry));
      await fs.rename(entry, destination);
      console.log(`Moved: ${entry} to ${destination}`);
    }
  } catch (error) {
    console.error('Error moving files:', error);
  }
  const adminLogsDirectory = buildPath('data/logs/admin');
  const adminLogsPath = buildPath('admin-service.log');
  await fs.mkdir(adminLogsDirectory, { recursive: true });
  if (existsSync(adminLogsPath)) {
    await fs.rename(adminLogsPath, buildPath('data/logs/admin/admin-service.log'));
  }
  console.log('- Done');
  console.log('------------------\n');

  // Migrate any secrets from config file to secure storage via the connector bridge
  console.log('Moving secrets...');
  await config.initialize();
  if (config.get('LDAP_BIND_PASSWORD')) {
    console.log('Found LDAP_BIND_PASSWORD in config file, migrating to secure storage and removing from config file.');
    await secretsBridge.store(secureStorage.keys.LDAP_BIND_PASSWORD, config.get('LDAP_BIND_PASSWORD'));
    config.clear('LDAP_BIND_PASSWORD');
  }
  if (config.get('LDAP_BIND_CREDENTIALS')) {
    console.log('Found LDAP_BIND_CREDENTIALS in config file, migrating to secure storage and removing from config file.');
    const plainTextPassword = await crypto.decrypt(config.get('LDAP_BIND_CREDENTIALS'));
    await secretsBridge.store(secureStorage.keys.LDAP_BIND_PASSWORD, plainTextPassword);
    config.clear('LDAP_BIND_CREDENTIALS');
  }
  if (config.get('SSL_KEY_PASSWORD')) {
    console.log('Found SSL_KEY_PASSWORD in config file, migrating to secure storage and removing from config file.');
    await secretsBridge.store(secureStorage.keys.CUSTOM_SSL_PFX_PASSWORD, config.get('SSL_KEY_PASSWORD'));
    config.clear('SSL_KEY_PASSWORD');
  }
  console.log('- Done');
  console.log('------------------\n');

  console.log('Re-saving config without secrets...');
  await config.save();
  console.log('- Done');
  console.log('------------------\n');
}

// Runs migrate data if run from command line
(async () => {
  if (require.main === module) {
    await migrateData();
  }
})();

module.exports = migrateData;
