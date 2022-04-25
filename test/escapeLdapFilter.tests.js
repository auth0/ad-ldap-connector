const expect = require("chai").expect;
const escapeLdapFilter = require("../lib/escapeLdapFilter");

describe("escapeLdapFilter", () => {
  describe("given input is a string", () => {
    it("should work in the base case (no escaping)", function () {
      const input = "cn=jsmith,dc=example,dc=org";
      const expected = "cn=jsmith,dc=example,dc=org";
      const actual = escapeLdapFilter(input);
      expect(actual).to.equal(expected);
    });

    it('should escape the "*" "(" ")" "\\" and "NUL" characters according to RFC 2254', function () {
      const input = "Hi, (This) = is * a \\ test\0";
      const expected = "Hi, \\28This\\29 = is \\2a a \\5c test\\00";
      const actual = escapeLdapFilter(input);
      expect(actual).to.equal(expected);
    });
  });

  describe("given input is not a string", () => {
    it("should return the input unchanged", () => {
      const input = 123;
      const expected = 123;
      const actual = escapeLdapFilter(input);
      expect(actual).to.equal(expected);
    });
  });

  describe("given input is undefined", () => {
    it("should return undefined", () => {
      const input = undefined;
      const actual = escapeLdapFilter(input);
      expect(actual).to.be.undefined;
    });
  });
});
