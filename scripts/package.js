/* eslint-env node */
/**
 * Uses archiver package to make a zip file of all files in this directory excluding some folders like
 * .claude, .github etc.
 *
 * This is mostly to help developers create a zipped archive they can copy to a windows machine to build the installer.
 * It is not meant to be distributed.
 */

const archiver = require('archiver');
const fs = require('fs');
const path = require('path');

const excluded = [
  'node_modules',
  '.git',
  '.github',
  '.claude',
  '.idea',
  '.vscode',
  'certs',
  'test',
  'config.json',
  'cache.db',
  '.env',
  '*.log',
  '.DS_Store',
  'installer/output',
  'ad-ldap-connector.zip',
];

const ROOT = path.resolve(__dirname, '..');
const outputPath = path.join(require('os').homedir(), 'ad-ldap-connector.zip');

const output = fs.createWriteStream(outputPath);
const archive = archiver('zip', { zlib: { level: 9 } });

output.on('close', () => {
  console.log(`Created ${outputPath} (${archive.pointer()} bytes)`);
});

archive.on('error', (err) => { throw err; });

archive.pipe(output);

// For each excluded entry, ignore at root level and anywhere nested under a subdirectory
const ignorePatterns = excluded.flatMap(e => [e, `${e}/**`, `**/${e}`, `**/${e}/**`]);

archive.glob('**', { cwd: ROOT, ignore: ignorePatterns, dot: true });

archive.finalize();
