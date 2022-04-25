// Escapes an input string so that it can safely be used in a LDAP query filter, as defined in RFC 2254.
const escapeLdapFilter = function (inp) {
  if (typeof inp === "string") {
    let esc = "";
    for (let i = 0; i < inp.length; i++) {
      switch (inp[i]) {
        case "*":
          esc += "\\2a";
          break;
        case "(":
          esc += "\\28";
          break;
        case ")":
          esc += "\\29";
          break;
        case "\\":
          esc += "\\5c";
          break;
        case "\0":
          esc += "\\00";
          break;
        default:
          esc += inp[i];
          break;
      }
    }
    return esc;
  } else {
    return inp;
  }
};

module.exports = escapeLdapFilter;
