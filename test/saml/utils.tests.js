const assert = require("assert"),
    utils = require("../lib/utils");
const fs = require("fs");
const {createPublicKey} = require('crypto')

describe("pemToCert", function () {
    it("should not throw when the cert is invalid", function () {
        var cert = utils.pemToCert('abc');
        assert.ok(!cert);
    });
});

describe("fixPemFormatting", () => {
    it("returns the original when the original is not in PEM format", () => {
        let originalCert = fs.readFileSync(__dirname + '/test-auth0.der');
		let standardizedCert = utils.fixPemFormatting(originalCert);
		assert.strictEqual(originalCert.compare(standardizedCert), 0);
    })

	it("handles already correctly formatted PEM content", () => {
        let originalCert = fs.readFileSync(__dirname + '/test-auth0_rsa.pub');
        let standardizedCert = utils.fixPemFormatting(originalCert);
        assert.notStrictEqual(originalCert, standardizedCert);
        assert.deepStrictEqual(createPublicKey(originalCert), createPublicKey(standardizedCert));
	})

    it("handles PEM content with extra data before the cert", () => {
        let originalCert = Buffer.from(`data that should be ignored\n${fs.readFileSync(__dirname + '/test-auth0_rsa.pub').toString()}`)
        let standardizedCert = utils.fixPemFormatting(originalCert);
        assert.notStrictEqual(originalCert, standardizedCert);
        assert.deepStrictEqual(createPublicKey(originalCert), createPublicKey(standardizedCert));
    })

    it("handles PEM content with extra data after the cert", () => {
        let originalCert = Buffer.from(`${fs.readFileSync(__dirname + '/test-auth0_rsa.pub').toString()}\ndata that should be ignored`)
        let standardizedCert = utils.fixPemFormatting(originalCert);
        assert.notStrictEqual(originalCert, standardizedCert);
        assert.deepStrictEqual(createPublicKey(originalCert), createPublicKey(standardizedCert));
    })

    it("handles incorrectly formatted PEM content", () => {
        let originalCert = Buffer.from(fs.readFileSync(__dirname + '/test-auth0_rsa.pub').toString().replaceAll(/[\r\n]/g, ''));
        let standardizedCert = utils.fixPemFormatting(originalCert);
        assert.notStrictEqual(originalCert, standardizedCert);
        let correctCert = createPublicKey(fs.readFileSync(__dirname + '/test-auth0_rsa.pub'))
        assert.deepStrictEqual(correctCert, createPublicKey(standardizedCert));
    })

    it("handles already correctly formatted PEM chains", () => {
        let originalCert = fs.readFileSync(__dirname + '/test-auth0-chain.pem');
        let standardizedCert = utils.fixPemFormatting(originalCert);
        assert.notStrictEqual(originalCert, standardizedCert);
        assert.deepStrictEqual(createPublicKey(originalCert), createPublicKey(standardizedCert));
    })

    it("handles incorrectly formatted PEM chains", () => {
        let originalCert = Buffer.from(fs.readFileSync(__dirname + '/test-auth0-chain.pem').toString().replaceAll(/[\r\n]/g, ''));
        let standardizedCert = utils.fixPemFormatting(originalCert);
        assert.notStrictEqual(originalCert, standardizedCert);
        let correctCert = createPublicKey(fs.readFileSync(__dirname + '/test-auth0-chain.pem'))
        assert.deepStrictEqual(correctCert, createPublicKey(standardizedCert));
    })
})
