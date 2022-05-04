const ldap = require("ldapjs");
const expect = require("chai").expect;
const parseLdapFilter = require("../lib/parseLdapFilter");

describe("parseLdapFilter", () => {
  describe("when filter is valid", () => {
    describe("and does not contain escaped characters", () => {
      it("should return valid filter", function (done) {
        const input = "(cn=jsmith)";

        const result = parseLdapFilter(input);
        expect(result.isValid).to.be.true;
        expect(result.filter.matches({ cn: "jsmith" })).to.be.true;
        done();
      });
    });

    describe("and contains escaped characters", () => {
      it("should return valid filter", function (done) {
        const input = "(cn=jsm\\5ct\\29\\2a\\28)";

        const result = parseLdapFilter(input);
        expect(result.isValid).to.be.true;
        expect(result.filter.matches({ cn: "jsm\\t)*(" })).to.be.true;
        done();
      });
    });
  });

  describe("when filter is not valid", () => {
    describe("and is undefined", () => {
      it("should return invalid filter", function (done) {
        const input = undefined;

        const result = parseLdapFilter(input);
        expect(result.isValid).to.be.false;
        expect(result.filter).to.be.null;
        done();
      });
    });

    describe("and contains invalid syntax", () => {
      it("should return invalid filter", function (done) {
        const input = "(cn=jsm(th)";

        const result = parseLdapFilter(input);
        expect(result.isValid).to.be.false;
        expect(result.filter).to.be.null;
        done();
      });
    });
  });
});
