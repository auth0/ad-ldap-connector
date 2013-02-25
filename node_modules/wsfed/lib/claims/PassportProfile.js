var fm = {
  'nameidentifier': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier',
  'email': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
  'name': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
  'givenname': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
  'surname': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
  'upn': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn',
  'groups': 'http://schemas.xmlsoap.org/claims/Group'
};

/**
 * returns a claim based WSFed identity from a Passport.js profile.
 *
 * Passport User Profile
 * http://passportjs.org/guide/profile/
 * 
 * Claim Types
 * http://msdn.microsoft.com/en-us/library/microsoft.identitymodel.claims.claimtypes_members.aspx
 * 
 * @param  {[type]} pu Passport.js user (req.user)
 */
function PassportProfile (pu) {
  
  if(!(this instanceof PassportProfile)) {
    return new PassportProfile(pu);
  }

  this[fm.nameidentifier]  = pu.id;
  this[fm.email]      = pu.emails[0] && pu.emails[0].value;
  this[fm.name]       = pu.displayName;
  this[fm.givenname]  = pu.name.givenName;
  this[fm.surname]    = pu.name.familyName;
};

PassportProfile.metadata = [ {
  id: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
  optional: true,
  displayName: 'E-Mail Address',
  description: 'The e-mail address of the user'
}, {
  id: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
  optional: true,
  displayName: 'Given Name',
  description: 'The given name of the user'
}, {
  id: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
  optional: true,
  displayName: 'Name',
  description: 'The unique name of the user'
}, {
  id: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
  optional: true,
  displayName: 'Surname',
  description: 'The surname of the user'
}, {
  id: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
  optional: true,
  displayName: 'Name ID',
  description: 'The SAML name identifier of the user'
}];

module.exports = PassportProfile;