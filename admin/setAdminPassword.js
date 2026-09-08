const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const process = require('node:process');

/**
 * This script is used to set the password for the pending admin user.
 * It reads the password from the console arguments, hashes it,
 * and saves it to a file named `.pending-admin-password` in the same directory as this script.
 *
 * The pending password is then used by the admin console service on startup to save the hashed password to the keychain.
 *
 * If the console argument is not provided, the script exits without doing anything.
 */

const password = process.argv[2];
if (!password) {
  process.exit(0);
}

let preHashed = false;
const preHashedFlag = process.argv[3];
if (preHashedFlag === '--prehashed') {
  preHashed = true;
}

(async () => {
  try {
    const hash = preHashed ? password : await bcrypt.hash(password, 12);
    const filePath = path.join(__dirname, '../data', '.pending-admin-password');
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, hash, 'utf8');
  } catch (err) {
    process.stdout.write('Failed to save pending password: ' + err.message + '\n');
    process.exit(1);
  }
})();
