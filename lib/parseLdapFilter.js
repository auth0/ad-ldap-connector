const ldap = require("ldapjs");

const parseLdapFilter = function (filterString) {
  try {
    const filter = ldap.parseFilter(filterString);
    return { filter: filter, isValid: true };
  } catch (err) {
    console.log(`Invalid filter: ${filterString}. Reason: ${err.message}`);
    return { filter: null, isValid: false };
  }
};

module.exports = parseLdapFilter;
