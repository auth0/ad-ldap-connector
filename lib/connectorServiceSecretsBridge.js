/**
 * This module provides functionality to pass on secrets to the connector service via a pending file. The connector
 * service then loads these secrets into its own secure storage that is safe from other users.
 */

const fs = require('node:fs/promises');
const { existsSync } = require('fs');
const path = require('node:path');
const secureStorage = require('./secureStorage');

const DATA_DIRECTORY = path.join(__dirname, '../data');
const BRIDGE_FILE_NAME = '.connector-bridge';
const BRIDGE_FILE_PATH = path.join(DATA_DIRECTORY, BRIDGE_FILE_NAME);

class ConnectorServiceSecretsBridge {
  #fs;
  #secureStorage;

  constructor({
    fsModule = fs,
    secureStorageModule = secureStorage
  }) {
    this.#fs = fsModule;
    this.#secureStorage = secureStorageModule;
  }

  /**
   * Stores a secret key,value pair to the bridge. This should only be called from the Admin Console service.
   * @param key
   * @param value
   */
  async store(key, value) {
    const currentData = await this.#loadBridgeFileContents();
    currentData[key] = value;
    await this.#fs.writeFile(BRIDGE_FILE_PATH, JSON.stringify(currentData, null, 2), 'utf-8');
  }

  /**
   * Reads the secrets bridge file and loads any secrets in to secure storage. Removes the bridge file after.
   * @return {Promise<void>}
   */
  async processBridgeFile() {
    const data = await this.#loadBridgeFileContents();
    try {
      for (const [key, value] of Object.entries(data)) {
        console.log(`Moving secret ${key} from bridge file to secure storage.`);
        await this.#secureStorage.store(key, value);
      }
    } finally {
      // Always remove the plaintext bridge file, even if storing a secret failed part-way
      // through, so secrets are never left orphaned on disk. The original error still propagates.
      if (this.#bridgeFileExists()) {
        await this.#fs.unlink(BRIDGE_FILE_PATH);
      }
    }
  }

  async #loadBridgeFileContents() {
    let data = {};
    if (this.#bridgeFileExists()) {
      const bridgeFileContents = await this.#fs.readFile(BRIDGE_FILE_PATH, 'utf-8');
      try {
        data = JSON.parse(bridgeFileContents);
      } catch (err) {
        console.error('Error parsing connector bridge file, it may be malformed:', err);
      }
    }
    return data;
  }

  #bridgeFileExists() {
    return existsSync(BRIDGE_FILE_PATH);
  }
}

const connectorServiceSecretsBridge = new ConnectorServiceSecretsBridge({});
module.exports = connectorServiceSecretsBridge;
module.exports.ConnectorServiceSecretsBridge = ConnectorServiceSecretsBridge;
