module.exports = function (raw_data) {
  var profile = {
    id:          raw_data.objectGUID || raw_data.uid || raw_data.cn,
    displayName: raw_data.displayName,
    name: {
      familyName: raw_data.sn,
      givenName: raw_data.givenName
    },
    nickname: raw_data['sAMAccountName'] || raw_data['cn'] || raw_data['commonName'],
    groups: raw_data['groups'],
    emails: (raw_data.mail ? (Array.isArray(raw_data.mail) ? raw_data.mail : [{value: raw_data.mail}]) : undefined)
  };

  profile['dn'] = raw_data['dn'];
  profile['st'] = raw_data['st'];
  profile['description'] = raw_data['description'];
  profile['postalCode'] = raw_data['postalCode'];
  profile['telephoneNumber'] = raw_data['telephoneNumber'];
  profile['distinguishedName'] = raw_data['distinguishedName'];
  profile['co'] = raw_data['co'];
  profile['department'] = raw_data['department'];
  profile['company'] = raw_data['company'];
  profile['mailNickname'] = raw_data['mailNickname'];
  profile['sAMAccountName'] = raw_data['sAMAccountName'];
  profile['sAMAccountType'] = raw_data['sAMAccountType'];
  profile['userPrincipalName'] = raw_data['userPrincipalName'];
  profile['manager'] = raw_data['manager'];
  profile['organizationUnits'] = raw_data['organizationUnits'];
  
  // if your LDAP service provides verified email addresses, uncomment this:
  // profile['email_verified'] = true;
  
  // This will make the profile huge:
  // if (raw_data['thumbnailPhoto']) {
  //   profile['picture'] = 'data:image/bmp;base64,' +
  //     raw_data['thumbnailPhoto'].toString('base64');
  // }
  return profile;
};
