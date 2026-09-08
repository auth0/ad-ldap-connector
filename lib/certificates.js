const fs = require('fs');
const path = require('path');
const selfsigned = require('selfsigned');
const execAsync = require('util').promisify(require('child_process').exec);
const process = require('node:process');

const config = require('./config');

const certsDirectory = path.join(__dirname, '../', 'data', 'certs');
const certPaths = {
  pem: path.join(certsDirectory, 'cert.pem'),
  key: path.join(certsDirectory, 'cert.key')
};

class Certificates {
  #fs;
  #exec;
  #selfsigned;
  #process;
  #config;
  #path;
  #cache;

  constructor({
    fsModule = fs,
    execFunction = execAsync,
    processModule = process,
    configModule = config,
    selfsignedModule = selfsigned,
    pathModule = path
  } = {}) {
    this.#fs = fsModule;
    this.#exec = execFunction;
    this.#selfsigned = selfsignedModule;
    this.#process = processModule;
    this.#config = configModule;
    this.#path = pathModule;
    this.#cache = {};
  }

  /**
   * Ensures certificates are available, migrating from config if necessary. The cert files are then locked down.
   *
   * @param options
   * @param {string} options.connectionName - The name of the connection, used as CN in the certificate.
   * @param {string} options.connectionDomain - The domain of the connection, used as OU in the certificate.
   * @return {Promise<void>}
   */
  async initialize(options = {}) {
    if (this.#config.get('AUTH_CERT')) {
      console.log('AUTH_CERT is set, moving to file.');
      await this.#writeToFile(this.#config.get('AUTH_CERT'), this.certificatePath);
      this.#config.clear('AUTH_CERT');
    }

    if (this.#config.get('AUTH_CERT_KEY')) {
      console.log('AUTH_CERT_KEY is set, moving to file.');
      await this.#writeToFile(this.#config.get('AUTH_CERT_KEY'), this.privateKeyPath);
      this.#config.clear('AUTH_CERT_KEY');
    }

    // If certs are available at this point (after migration from config or files already exist), we skip generation.
    const cert = this.getCertificate();
    const key = this.getPrivateKey();
    if (cert && key) {
      console.log('Certificates already exist, skipping certificate generation.');
      return;
    }

    if (!options.connectionName || !options.connectionDomain) {
      console.warn('Connection name and domain are required to generate certificates, but were not provided.'.yellow);
      return;
    }

    console.log('Generating a self-signed certificate.'.yellow);
    var pems = selfsigned.generate([
      {shortName: 'CN', value: options.connectionName},
      {shortName: 'OU', value: options.connectionDomain},
      {shortName: 'O', value: 'auth0/ad-ldap-connector'}
    ], {
      days: 365,
      algorithm: 'sha256',
      keySize: 2048
    });

    await this.#writeToFile(pems.cert, this.certificatePath);
    await this.#writeToFile(pems.private, this.privateKeyPath);

    console.log('Certificates generated.\n'.green);
  }

  get certificatePath() {
    return certPaths.pem;
  }

  get privateKeyPath() {
    return certPaths.key;
  }

  getCertificate() {
    if (this.#cache.cert) {
      return this.#cache.cert;
    }
    if (!this.#fs.existsSync(certPaths.pem)) {
      return null;
    }
    const certContents = this.#fs.readFileSync(certPaths.pem, 'utf8');
    this.#cache.cert = certContents;
    return certContents;
  }

  getPrivateKey() {
    if (this.#cache.key) {
      return this.#cache.key;
    }
    if (!this.#fs.existsSync(certPaths.key)) {
      return null;
    }
    const keyContents = this.#fs.readFileSync(certPaths.key, 'utf8');
    this.#cache.key = keyContents;
    return keyContents;
  }

  async #writeToFile(contents, filePath) {
    this.#cache = {};
    this.#fs.mkdirSync(this.#path.dirname(filePath), { recursive: true });
    this.#fs.writeFileSync(filePath, contents);
  }
}

const certificates = new Certificates();

module.exports = certificates;
module.exports.Certificates = Certificates;
