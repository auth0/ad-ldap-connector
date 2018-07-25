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
    });
  });
});