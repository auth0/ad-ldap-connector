# Changelog

## [5.0.14]

### Fixes
Fix anonymous LDAP search detection logic.

## [Unreleased]
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