require('colors');

const os = require('os');
const path = require('path');
const fs = require('fs/promises');

const config = require('../lib/config');
const cas = require('../lib/add_certs');
const createConnection = require('../lib/ldap').createConnection;
const secureStorage = require('../lib/secureStorage');

const { input, password, confirm } = require('@inquirer/prompts');

const { loadProvisioningTicket } = require('../lib/provisioningTicket');
const migrateData = require('./migrateData');
const adLdapSettings = require('../lib/adLdapSettings');

const INSTALL_DIR = path.join(__dirname, '../');

function printTitle(title) {
  console.log('');
  console.log('-'.repeat(100));
  console.log('| ' + title + ' '.repeat(100 - 2 - title.length - 1) + '|');
  console.log('-'.repeat(100));
  console.log('');
}

(async () => {

  console.log('');
  console.log('='.repeat(100));
  console.log('Auth0 ADLDAP Connector Setup');
  console.log('='.repeat(100));
  console.log('');

  // Prevent running on windows platform
  if (process.platform === 'win32') {
    console.error('This setup script is meant to be used on non-windows platforms like *nix and MacOS. For windows platforms, use the installer (.msi) provided.');
    process.exit(1);
  }

  const username = os.userInfo().username;
  const startInstall = await confirm({
    message: `This installer should be run under the same user as the one used to run the connector itself. 
    It is currently being run under [${username}]. Continue?`,
    default: false
  });

  if (!startInstall) {
    process.exit(0);
  }

  // Migrate any legacy data
  printTitle('Migrating data from older installs...');
  await migrateData();

  // Inject CA certificates
  printTitle('Importing certificates...');
  await cas.injectAsync();

  // Initialize existing config
  await config.initialize();

  // Get provisioning ticket from user input if not already set
  let provisioningTicket = config.get('PROVISIONING_TICKET');
  if (!provisioningTicket) {
    provisioningTicket = await input({
      message: 'Please enter your provisioning ticket URL: ',
      required: true
    });
    config.set('PROVISIONING_TICKET', provisioningTicket);
  }

  // Load options / settings from the provisioning ticket
  printTitle('Testing provisioning ticket...');
  const ticketInfo = await loadProvisioningTicket(provisioningTicket);

  // Discover AD/LDAP settings if not already set
  let ldapUrl = config.get('LDAP_URL');
  let ldapBase = config.get('LDAP_BASE');
  if (!ldapUrl || !ldapBase) {
    const discoveredSettings = await adLdapSettings.discoverSettings(ticketInfo.connectionDomain);
    ldapUrl = discoveredSettings.LDAP_URL || '';
    ldapBase = discoveredSettings.LDAP_BASE || '';

    ldapUrl = await input({
      message: 'Please enter your LDAP server URL: ',
      default: ldapUrl,
      prefill: 'tab',
      required: true
    });
    ldapBase = await input({
      message: 'Please enter the LDAP server base DN: ',
      default: ldapBase,
      prefill: 'tab',
      required: true
    });
    config.set('LDAP_URL', ldapUrl);
    config.set('LDAP_BASE', ldapBase);
  }

  // Check if Anonymous LDAP search is enabled
  const ldapClient = createConnection();
  const anonymousSearchEnabled = await adLdapSettings.isAnonymousSearchEnabled(ldapClient, ldapBase);
  ldapClient.destroy();
  config.set('ANONYMOUS_SEARCH_ENABLED', anonymousSearchEnabled);
  console.log(`Is Anonymous LDAP search enabled? ${anonymousSearchEnabled ? 'yes' : 'no'}`);

  // If anonymous search is not enabled, ask for LDAP bind user credentials if they aren't set already
  if (
    !anonymousSearchEnabled &&
    (!config.get('LDAP_BIND_USER') || !await secureStorage.get(secureStorage.keys.LDAP_BIND_PASSWORD))
  ) {
    const ldapBindUser = await input({
      message: 'Please enter the LDAP bind user (e.g. cn=admin,dc=example,dc=com): ',
      required: true
    });
    const ldapBindPassword = await password({
      message: 'Please enter the LDAP bind password: ',
      required: true
    });
    config.set('LDAP_BIND_USER', ldapBindUser.trim());
    await secureStorage.store(secureStorage.keys.LDAP_BIND_PASSWORD, ldapBindPassword);
  }

  // Save config to file
  await config.save();

  // Restrict file permissions to owner and group
  printTitle('Restricting file permissions...');
  await fs.chown(INSTALL_DIR, os.userInfo().uid, os.userInfo().gid);
  await fs.chmod(INSTALL_DIR, 0o700);
  console.log(`Restricted install directory to owner [${username}] and group, with permissions 700.`);

  printTitle('Connector setup complete.');
})();
