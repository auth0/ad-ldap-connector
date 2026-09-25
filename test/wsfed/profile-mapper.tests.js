const { expect } = require('chai');
const PassportProfileMapper = require('../../lib/wsfed/claims/PassportProfileMapper');

const NS = {
  nameIdentifier: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier',
  email:          'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
  name:           'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
  givenname:      'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
  surname:        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'
};

describe('PassportProfileMapper', function () {
  describe('getClaims', function () {
    it('maps id to nameidentifier', function () {
      const claims = PassportProfileMapper({ id: '12345' }).getClaims();
      expect(claims[NS.nameIdentifier]).to.equal('12345');
    });

    it('maps emails[0].value to emailaddress', function () {
      const claims = PassportProfileMapper({
        id: '1',
        emails: [{ value: 'a@b.com' }]
      }).getClaims();
      expect(claims[NS.email]).to.equal('a@b.com');
    });

    it('maps displayName to name', function () {
      const claims = PassportProfileMapper({
        id: '1',
        displayName: 'Jane Doe'
      }).getClaims();
      expect(claims[NS.name]).to.equal('Jane Doe');
    });

    it('maps name.givenName and name.familyName', function () {
      const claims = PassportProfileMapper({
        id: '1',
        name: { givenName: 'Jane', familyName: 'Doe' }
      }).getClaims();
      expect(claims[NS.givenname]).to.equal('Jane');
      expect(claims[NS.surname]).to.equal('Doe');
    });

    it('passes custom keys through under the passportjs namespace', function () {
      const claims = PassportProfileMapper({
        id: '1',
        groups: ['admins', 'users']
      }).getClaims();
      expect(claims['http://schemas.passportjs.com/groups']).to.deep.equal(['admins', 'users']);
    });

    it('does not remap reserved keys', function () {
      const claims = PassportProfileMapper({
        id: '1',
        emails: [{ value: 'a@b.com' }],
        displayName: 'X',
        name: { givenName: 'X', familyName: 'Y' },
        _json: { stuff: 'here' }
      }).getClaims();
      expect(claims['http://schemas.passportjs.com/emails']).to.be.undefined;
      expect(claims['http://schemas.passportjs.com/displayName']).to.be.undefined;
      expect(claims['http://schemas.passportjs.com/name']).to.be.undefined;
      expect(claims['http://schemas.passportjs.com/id']).to.be.undefined;
      expect(claims['http://schemas.passportjs.com/_json']).to.be.undefined;
    });
  });

  describe('getNameIdentifier', function () {
    it('uses id when present', function () {
      const ni = PassportProfileMapper({ id: '12345', displayName: 'X' }).getNameIdentifier();
      expect(ni.nameIdentifier).to.equal('12345');
    });

    it('falls back to displayName when id is missing', function () {
      const ni = PassportProfileMapper({ displayName: 'Jane Doe' }).getNameIdentifier();
      expect(ni.nameIdentifier).to.equal('Jane Doe');
    });

    it('returns undefined when neither id nor displayName is present', function () {
      const ni = PassportProfileMapper({}).getNameIdentifier();
      expect(ni.nameIdentifier).to.be.undefined;
    });
  });

  describe('metadata', function () {
    it('includes the five expected claim types', function () {
      const ids = PassportProfileMapper.prototype.metadata.map(m => m.id);
      expect(ids).to.have.members([
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'
      ]);
    });
  });
});
