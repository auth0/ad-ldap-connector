const nconf = require('nconf');
const ldapjs = require('ldapjs');
const tls = require('tls');
const tlsHelper = require('../lib/tls');
const expect = require('chai').expect;

const ldap = require('../lib/ldap');
const fs = require('fs');

const caFile = 'certs/tempCa.pem';

describe('Connection to ldaps server', function () {

  const PORT=19876;
  const cert = {
    publicKey: '-----BEGIN CERTIFICATE-----\r\nMIIDHjCCAgagAwIBAgIBATANBgkqhkiG9w0BAQUFADB4MQswCQYDVQQGEwJVUzET\r\nMBEGA1UECBMKV2FzaGluZ3RvbjERMA8GA1UEBxMIQmVsbGV2dWUxDjAMBgNVBAoT\r\nBUF1dGgwMR8wHQYDVQQLExZBRCBMREFQIENvbm5lY3RvciBUZXN0MRAwDgYDVQQD\r\nEwdUZXN0IENBMB4XDTE3MDMzMDIwNDgzOVoXDTI3MDMyODIwNDgzOVowADCCASIw\r\nDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMIYhS96xvPNDaq9iV5ddYrtlySr\r\nwktrWyCklH2S6gtJLen8IAwzHlg\/Cf6NbnqQIvusU5nehT0lv5jgNES85CifcBlV\r\nZyUClP48S8+xex6m6XU41PHSaDqpmzL3VdEBibqjv3Xnv+h3Np7JQnersHRMmUNZ\r\nFqzZvGg3yCgcKxpdqQRelB6AZDBQKXPxQ22ZZA2bMJlTfmXr65wkIRb5z8K4isi9\r\nyz4b1lKKkIobPiYY\/N8aki3BopfXSPnmuNOQV8pCjrB8+Ttwi3ukzE83KjtpZi+O\r\nJKqeGb0lHa1KJlTTqD12P3efDNrjKBdjjO39bMNRknlmudkMKtxDs93FlTECAwEA\r\nAaMrMCkwCwYDVR0PBAQDAgXgMBoGA1UdEQQTMBGHBH8AAAGCCWxvY2FsaG9zdDAN\r\nBgkqhkiG9w0BAQUFAAOCAQEAKIVqF\/LDMTiJxz9BoRzbpUV3\/z+T3O8IpRFNc+D5\r\n3JKevdzJRY3ShGivrafNfbS+eeYICR7\/3otnkbx0S9L81pc58R+qCHQYVTD+B\/eY\r\nYpBd\/vpiUE9\/RBSYDE\/O1FgC5ecYznugnWVl+y3wlT7g9XkkXJnZb\/SKvJwjWU6L\r\nF5CI4FwjlTbFIjWjDFUMYmfZXq\/ggj8nkQMHsy7NpqfYMZ6+QocL1V45QL+BBe9C\r\n5cdPptr9XMf3oS7Gy\/cBnjkQd0u4zJ8X2CYYkaJlwDQo+vbES\/Y0sGCwDiqTGDcH\r\ncfoOH7SdUHHKSLmUcrVoopY21mFcd3gZ178OET6UsQMOZw==\r\n-----END CERTIFICATE-----',
    privateKey: '-----BEGIN RSA PRIVATE KEY-----\r\nMIIEowIBAAKCAQEAwhiFL3rG880Nqr2JXl11iu2XJKvCS2tbIKSUfZLqC0kt6fwg\r\nDDMeWD8J\/o1uepAi+6xTmd6FPSW\/mOA0RLzkKJ9wGVVnJQKU\/jxLz7F7HqbpdTjU\r\n8dJoOqmbMvdV0QGJuqO\/dee\/6Hc2nslCd6uwdEyZQ1kWrNm8aDfIKBwrGl2pBF6U\r\nHoBkMFApc\/FDbZlkDZswmVN+ZevrnCQhFvnPwriKyL3LPhvWUoqQihs+Jhj83xqS\r\nLcGil9dI+ea405BXykKOsHz5O3CLe6TMTzcqO2lmL44kqp4ZvSUdrUomVNOoPXY\/\r\nd58M2uMoF2OM7f1sw1GSeWa52Qwq3EOz3cWVMQIDAQABAoIBABw7rtvqMxhxomRM\r\nr7evRpLP3qVx6pBH7HiCGCtv\/GVp3qjjiNHdebOCb\/S8I+7mGoCbX4nJSX5MiGM3\r\nccLx6wpRrt+wgZFrn7qfkLOEcJFT3C+19Zu7bHfkBfRS8AO4Ao3IlegTruGkvag5\r\nRFbd\/YvdPIoEYn0AKxzJyG61MjviVONIJL7PkMk4q2nq12QjtOHp3TM1oSY6rwBE\r\nR585i3TZeQilhVOlvm+i6by47Tw8ljyCc9rsN\/sajoxjs650296MiRMElbs321Dl\r\n13DIzF9pTy654ZIjKvQgQta2LrK1kp8a4BUj03POf8oCH23ufkTmEB1hDQHapL7I\r\nC3ue05UCgYEA7SKNAm7q3e36QHPw3QZAvSpV51W9zcY7JymvMWCj\/izG0h7g6Th1\r\npI4Gu9wWEvJdZSEnEc2d5E4E6EeJnA\/OQ1cZqmbNqed\/r3xU+FfhpE7sP6rWYr5R\r\nW9TOr3U+bV+ts+iToj0Jlq40OlPFRwxNVCyDr2QSPlTqAzkk6lGGIzcCgYEA0Ylw\r\n5MYNdzMfunkUbMTE349ioninKY0xSOttSTQPw9NqRcBupcipY0a\/drNECQoPXWKu\r\nt+ZT13EmCZxBjuPqMO5a\/BexD+dhf3b4Ksui1PMhX8U4ODAdBQlBRT2GAUdQgl8a\r\ncFQSIRV0sW+svE6AsXV4Kx73V5aC0D4Zz+vXDtcCgYEAxsmvAbovw4mKvtsysGZc\r\ngPdreflDmquxzNvB1JfaAepRZbWi\/39oB2FUPcl667knF+7ZzK\/cy5WnwXyu3BfX\r\n5lWu201A3UyGmnqU1Hb\/XfkXTSwOekpm85+LAEU95vxNJkMy989JKXqxp6+v8iZa\r\n8NQ8NBykuoH+hmMyEgfzdbMCgYA0sYyba5b9T\/T9ru9M\/xrHYcabNx5Km8A2J0Zf\r\nb2E7jNIf4mmw9UprteH2VtSYNVhx0pw\/kQOqnUDEj\/AIoBZH4dktpkOXzUc+h8uW\r\n74juZooRDIa70pWpq48ne3ZUofuEHaiHcQzyFvQ2nu\/glxlUB0eGCI6JD0esWMGj\r\nARsfFwKBgBWeWFjgjotC12QZfV0ZMMw9sOnQQtbjxtzEBnalLfL+GjPJsawd9E+z\r\n0R39qIs0tN9\/\/93fw0WGu9BjraIzbFptEPirjT\/oe+p+GzMPztRcoZZ8kvM16BD5\r\n5D2UYsL+GUyeYTeMbd8bsUnE+Ul+We8tIPWxmrePipde9Uts9Qy4\r\n-----END RSA PRIVATE KEY-----',
    ca : '-----BEGIN CERTIFICATE-----\r\nMIIEUTCCAzmgAwIBAgIJAMlqt\/8UuGbMMA0GCSqGSIb3DQEBBQUAMHgxCzAJBgNV\r\nBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMREwDwYDVQQHEwhCZWxsZXZ1ZTEO\r\nMAwGA1UEChMFQXV0aDAxHzAdBgNVBAsTFkFEIExEQVAgQ29ubmVjdG9yIFRlc3Qx\r\nEDAOBgNVBAMTB1Rlc3QgQ0EwHhcNMTcwMzMwMjAzMjE3WhcNMjcwMzI4MjAzMjE3\r\nWjB4MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjERMA8GA1UEBxMI\r\nQmVsbGV2dWUxDjAMBgNVBAoTBUF1dGgwMR8wHQYDVQQLExZBRCBMREFQIENvbm5l\r\nY3RvciBUZXN0MRAwDgYDVQQDEwdUZXN0IENBMIIBIjANBgkqhkiG9w0BAQEFAAOC\r\nAQ8AMIIBCgKCAQEAvAKizExxRjxEKxkboxsE7ErdiOA3YBOaiRXAxjZelANGuuzo\r\nXPYPiwtf5gaHGRzfiJLzJDmIxbJsiR61qPC1\/mcaEWn54OKhwQa05FKusDm6ej8D\r\nWs6\/QDFwZYOukdPbz\/ZpV0In2YPHfdHucx\/JhKE3V5gYFd04U8PcKwn2eH\/fSjIA\r\n1ghSpHBa9F0jIPrBrNe1zPe33AFaE1SKuT\/JcbNaYx1jh1C1KWM7OX5EQ4M\/HUP3\r\n9VWdXVxt48Yj7OoLPrwz4\/5d\/KqCWoznQkcJ2FyA7LJqN1GBP1EoLLAew7yKMGzI\r\n5GCbS8o3F5baLeWJ3jlvylCFE0LDAj0UoxPSUQIDAQABo4HdMIHaMB0GA1UdDgQW\r\nBBTBFNN+vNPh\/ilPbnXsAQa0kAnUuzCBqgYDVR0jBIGiMIGfgBTBFNN+vNPh\/ilP\r\nbnXsAQa0kAnUu6F8pHoweDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0\r\nb24xETAPBgNVBAcTCEJlbGxldnVlMQ4wDAYDVQQKEwVBdXRoMDEfMB0GA1UECxMW\r\nQUQgTERBUCBDb25uZWN0b3IgVGVzdDEQMA4GA1UEAxMHVGVzdCBDQYIJAMlqt\/8U\r\nuGbMMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAFQWabxlItAUN+\/3\r\n2gwDgqSVXrPGJ9XyQfVA3RmrVxD+PZqxo9+preS8SVGDLGzt9bL4MFO8+d\/0IVNM\r\nn+j4CCXRd\/BgKHpg6Cj14PPsrJuoCIhFJv9x5XAYqOoTf8KlkZKTfPXuZ0gAStuh\r\nVpKwC7rYrNjRigj0UIIe1ghtzhs2av5BRbvYFQlBgrQI4uMQKhlm8STPsV9vr8iF\r\nWcwmf2jvSmVVcRNPSjxOoqraYxhaIwCAEpQKKPsyoPUwSvCPcvZqwOmFd2FWwST9\r\nIc+EpvwplAizLJmh8M8mEEXfz1RkeYVsiWgcRV22Edd20lvlbnptRkMSEVbE2XMB\r\n9c2aY1k=\r\n-----END CERTIFICATE-----'
  };

  var server;
  var originalLdapUrl;

  before(function(done) {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED=1;

    originalLdapUrl = nconf.get('LDAP_URL');
    nconf.overrides({
      'LDAP_URL': 'ldaps://127.0.0.1:' + PORT,
      'LDAP_CA_PATH': caFile});

    fs.writeFile(caFile, cert.ca);
    server=ldapjs.createServer({
      key: cert.privateKey,
      certificate: cert.publicKey
    });

    server.bind('cn=root', function(req, res, next) {
      if (req.dn.toString() !== 'cn=root' || req.credentials !== 'secret')
        return next(new ldap.InvalidCredentialsError());
      res.end();
      return next();
    });

    server.listen(PORT, done);
  });


  after(function(done) {
    nconf.overrides({'LDAP_URL': originalLdapUrl, 'LDAP_CA_PATH': undefined});
    fs.unlink(caFile);

    if (server) {
      server.close();
    }
    done();
  });

  it('should connect to custom-CA-signed ldap server', function(done) {
    var client = ldap.createConnection();
    client.bind('cn=root', 'secret', function(err) {
      if (err) {
        throw(err);
      }
      else {
        client.destroy();
        done();
      }
    });
  });
});
