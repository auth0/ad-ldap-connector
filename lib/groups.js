/**
 *  Routines to extract groups and group information
 */
const findGroups = require('./users').findGroups;
const _ = require('lodash');


/**
 * Constructs the primary groups SID from the primaryGroupID in the user profile
 * and the domain relative ID (RID).
 * Based on the process described here: https://support.microsoft.com/en-us/help/297951/how-to-use-the-primarygroupid-attribute-to-find-the-primary-group-for
 * Overview:
 *  1. Get the primary group ID for the user
 *  2. Get the SID for the user
 *  3. Remove last segment of the user SID to extract the domain relative ID (RID)
 *  4. Append the primary group ID to the domain RID to create the primary group SID
 * @param {*} primaryGroupId The primaryGroupID from the active directory entry for the user
 * @param {*} profileSid The SID from the active directory entry for the user
 */
function constructPrimaryGroupSid(primaryGroupId, profileSid) {
  let segments = profileSid.split('-');
  let rid = segments.slice(0, -1).concat([primaryGroupId]);
  let groupSid = rid.join('-');
  return groupSid;
}
module.exports.constructPrimaryGroupSid = constructPrimaryGroupSid;


/**
 * ldapjs search for using async/await syntax
 * @param {*} client The ldapjs client
 * @param {*} baseGroups Defines the location in the directory from which the LDAP search for groups begins 
 * @param {*} opts The options to pass to the ldapjs client
 */
function search(client, baseGroups, opts) {
  return new Promise(function(resolve, reject) {
    client.search(baseGroups, opts, function(err, ldapEvents) {
      if (err) {
        return reject(err);
      }

      let entries = [];
      ldapEvents.on('searchEntry', (entry) => {
        entries.push(entry.object);
      });

      ldapEvents.on('error', (err) => {
        return resolve(entries);
      });

      ldapEvents.on('end', (result) => {
        if (result.status !== 0) {
          console.info('Unexpected result on _getAllGroupsAD', result.status);
        }
        return resolve(entries);
      });
    });
  });
}
module.exports.search = search;

/**
 * Get the primary groups for the user
 * We use the following process:
 *   1. Get the primaryGroupID for the user object
 *   2. Convert the user primaryGroupID and user objectSid into an SID for the primary group
 *   3. Retrieve the group object to get the distinguishedName attribute for the group
 *   4. Recursively search for all parent groups of the primary group
 * TODO: We may be able to combine the queries by caching the group objects to avoid
 *       directory lookups.
 * @param {nconf.config} config The nconf configuration object
 * @param {ldapjs.client} client The ldapjs client object
 * @param {string} baseDn The base distinguishing name for the directory to search
 * @param {object} user The user directory object
 */
async function getPrimaryGroups(config, client, baseDn, user) {
  if (!user || !user.primaryGroupID || !user.objectSid) {
    console.info('Unable to retrieve the primary group info');
    return new Error('Failed to construct the primary group SID. The user object is missing primaryGroupID or objectSid.');
  }

  let primaryGroupSid = constructPrimaryGroupSid(user.primaryGroupID, user.objectSid);
  let primaryGroup = null;
  try {
    let result = await search(client, baseDn, {
      scope: 'sub',
      filter: config.get('LDAP_SEARCH_PRIMARY_GROUP').replace(/\{0\}/ig, primaryGroupSid),
      attributes: _.uniq(['cn', 'dn', 'memberOf'].concat(config.get('GROUP_PROPERTIES'))),
      timeLimit: config.get('GROUPS_TIMEOUT_SECONDS'),
      derefAliases: config.get('GROUPS_DEREF_ALIASES')
    });
    primaryGroup = result[0];
  } catch (e) {
    console.info('Couldn\'t find the primary group', e);
    return new Error('Error occurred while trying to get the primary group');
  }

  if (!primaryGroup || !primaryGroup.dn) {
    console.info('Failed to find the primary group for the user');
    return new Error('Failed to get the primary group or primary group is missing distinguishedName');
  }

  try {
    return await search(client, baseDn, {
      scope: 'sub',
      filter: config.get('LDAP_SEARCH_PRIMARY_ALL_GROUPS').replace(/\{0\}/ig, primaryGroup.dn),
      attributes: _.uniq(['cn', 'dn', 'memberOf'].concat(config.get('GROUP_PROPERTIES'))),
      timeLimit: config.get('GROUPS_TIMEOUT_SECONDS'),
      derefAliases: config.get('GROUPS_DEREF_ALIASES')
    });
  } catch (e) {
    console.info('Couldn\'t find the primary parent groups', e);
    return new Error('Failed to find all the groups in the primary group hierarchy.');
  }
}
module.exports.getPrimaryGroups = getPrimaryGroups;