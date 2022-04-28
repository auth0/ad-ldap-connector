# Changelog

## [6.1.6]
### Fixes
Updated dependencies
async 0.2.10 -> 2.6.4
ini 1.3.5 -> 1.3.8
path-parse 1.0.6 -> 1.0.7
normalize-url 4.5.0 -> 4.5.1
glob-parent 5.1.1 -> 5.1.2
lodash 4.17.20 -> 4.17.21
hosted-git-info 2.8.8 -> 2.8.9
y18n 3.2.1 ->3.2.2

## [6.1.5]
### Fixes
Fix installer creation

## [6.1.4]

### Fixes
Use TLS 1.2 protocol in connector updater script for Windows

## [6.1.3]

### Fixes
Fix initialization bug introduced in 6.1.2

## [6.1.2]

### Fixes
Better websocket reconnection handling [this release should not be installed]

## [6.1.1]

### Refactor
Improve LDAP heartbeat search query and introduced LDAP_HEARTBEAT_SEARCH_QUERY configuration 

## [6.1.0]

### Feature
Remove deprecated crypto.createCipher and crypto.createDecipher calls
Introduce v2 encryption that uses more securely generated IVs for new connections.

Backwards compatible decryption is supported.

## [6.0.1]

### Fixes
Fix vulnerabilities reported by npm and snyk.

## [6.0.0]

### Breaking
Node 12 update

## [5.0.14]

### Fixes
Fix anonymous LDAP search detection logic.
Add CHANGELOG.md

## [5.0.13]

### Security
Fixes CVE-2020-15259

## [5.0.12]

### Fixes
Remove the use of deprecated parameter for jwt signature.

## [5.0.11]

### Chore
dependency bumps

## [5.0.10]

### Fix
Parse objectSid attribute from Windows Active Directory.

## [5.0.9]

### Fix
fix issue when searching a user in the admin console

### Refactor 
refactor for internal build systems
replace levelup disk cache with lru

## [5.0.0]

### Breaking
Update linux to node 10. 

### Add
Attempt to reconnect instead of crashing
