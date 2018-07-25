/**
 * Test functionality related to groups
 */
const expect = require('chai').expect;
const groups = require('../lib/groups');
const ldap_clients = require('../lib/ldap');

describe('users', function() {
  context('constructPrimaryGroupSid', function() {
    describe('when the user primaryGroupID and SID are supplied', function() {
      it('constructs a valid SID for the primary group', function() {
        let userPID = "513";
        let userSID = "S-1-5-21-110722640-2407186977-2355281104-1105";

        let result = groups.constructPrimaryGroupSid(userPID, userSID);
        expect(result).to.equal('S-1-5-21-110722640-2407186977-2355281104-513');
      });
    });
  });

  context('findGroups', function() {
    class MockConfig {
      get(key) {
        return {
          'LDAP_SEARCH_PRIMARY_GROUP': '(objectSid:={0})',
          'LDAP_SEARCH_PRIMARY_ALL_GROUPS': '(member:1.2.840.113556.1.4.1941:={0})',
          'GROUP_PROPERTIES': [],
          'GROUPS_TIMEOUT_SECONDS': 20,
          'GROUPS_DEREF_ALIASES': 0
        }[key];
      }
    }

    describe('when using active directory', function() {
      it('we can find the primary groups belonging to the user', async function() {
        let config = new MockConfig();
        let client = ldap_clients.client;
        let user = {
          primaryGroupID: 513,
          objectSid: 'S-1-5-21-110722640-2407186977-2355281104-1105'
        };
        let baseDn = 'DC=fabrikam,DC=com';

        let result = await groups.getPrimaryGroups(config, client, baseDn, user);
        expect(result).to.be.an('array');
        expect(result).to.eql([
          { dn: 'CN=Users,CN=Builtin,DC=fabrikam,DC=com', cn: 'Users', controls: [] },
          { dn: 'CN=Domain Users,CN=Users,DC=fabrikam,DC=com', cn: 'Domain Users', controls: [],
            memberOf: [
              'CN=Recursive Group,CN=Users,DC=fabrikam,DC=com',
              'CN=Users,CN=Builtin,DC=fabrikam,DC=com'
          ]},
          { dn: 'CN=Recursive Group,CN=Users,DC=fabrikam,DC=com', cn: 'Recursive Group', controls: [],
            memberOf: 'CN=Domain Users,CN=Users,DC=fabrikam,DC=com'
          }
        ]);
      });

      it('we fail with a sensible error if the primary group ID is wrong', async function() {
        let config = new MockConfig();
        let client = ldap_clients.client;
        let user = {
          primaryGroupID: 000, // Bad group ID
          objectSid: 'S-1-5-21-110722640-2407186977-2355281104-1105'
        };
        let baseDn = 'DC=wrong,DC=base,DC=distinguished,DC=name';

        let result = await groups.getPrimaryGroups(config, client, baseDn, user);
        expect(result).to.be.an.instanceOf(Error);
        expect(result.message).to.equal('Failed to construct the primary group SID. The user object is missing primaryGroupID or objectSid.');
      });

      it('we fail with a sensible error if the objectSid for the user is wrong', async function() {
        let config = new MockConfig();
        let client = ldap_clients.client;
        let user = {
          primaryGroupID: 513,
          objectSid: 'S-0-0-00-000000000-0000000000-0000000000-0000' // Bad user security ID
        };
        let baseDn = 'DC=wrong,DC=base,DC=distinguished,DC=name';

        let result = await groups.getPrimaryGroups(config, client, baseDn, user);
        expect(result).to.be.an.instanceOf(Error);
        expect(result.message).to.equal('Failed to get the primary group or primary group is missing distinguishedName');
      });

      it('we fail with a sensible error if the user profile is wrong', async function() {
        let config = new MockConfig();
        let client = ldap_clients.client;
        let user = {}; // This should not be empty
        let baseDn = 'DC=wrong,DC=base,DC=distinguished,DC=name';

        let result = await groups.getPrimaryGroups(config, client, baseDn, user);
        expect(result).to.be.an.instanceOf(Error);
        expect(result.message).to.equal('Failed to construct the primary group SID. The user object is missing primaryGroupID or objectSid.');
      });

      it('we fail with a sensible error if the base distinguished name is wrong', async function() {
        let config = new MockConfig();
        let client = ldap_clients.client;
        let user = {
          primaryGroupID: 513,
          objectSid: 'S-1-5-21-110722640-2407186977-2355281104-1105'
        };
        let baseDn = 'DC=wrong,DC=base,DC=distinguished,DC=name'; // This is a bad DN

        let result = await groups.getPrimaryGroups(config, client, baseDn, user);
        expect(result).to.be.an.instanceOf(Error);
        expect(result.message).to.equal('Failed to get the primary group or primary group is missing distinguishedName');
      });
    });
  });
});