require('colors');

const nconf = require('nconf');
const crypto = require('../lib/crypto');
const program = require('commander');
const async = require('async');
const axios = require('axios');
const urlJoin = require('url-join');
const cas = require('../lib/add_certs');
const firewall = require('../lib/firewall');
const createConnection = require('../lib/ldap').createConnection;
const path = require('path');

//steps
const certificate = require('./steps/certificate');
const configureConnection = require('./steps/configureConnection');
const adLdapSettings = require('./steps/ad-ldap-settings');

program.version(require('../package.json').version).parse(process.argv);

exports.run = function (workingPath, callback) {
  var provisioningTicket, info;

  var emptyVars = ['LDAP_URL', 'LDAP_BASE', 'LDAP_BIND_USER'];

  if (!nconf.get('LDAP_BIND_CREDENTIALS')) {
    emptyVars.concat(['LDAP_BIND_PASSWORD']);
  }

  async.series(
    [
      function (cb) {
        provisioningTicket = nconf.get('PROVISIONING_TICKET');

        if (provisioningTicket) return cb();

        program.prompt('Please enter the ticket number: ', function (pt) {
          provisioningTicket = pt;
          cb();
        });
      },
      function (cb) {
        cas.inject(cb);
      },
      function (cb) {
        var info_url = urlJoin(provisioningTicket, '/info');
        console.log('Loading settings from ticket: ' + info_url);

        axios
          .get(info_url)
          .then((response) => {
            if (response.status == 404) {
              return cb(
                new Error('Wrong ticket. Does this connection still exist?')
              );
            }

            var unexpected_response =
              response.status !== 200 ||
              !~(response.headers['content-type'] || '').indexOf(
                'application/json'
              );

            if (unexpected_response) {
              var message =
                'Unexpected response from ticket information endpoint. ' +
                'Status code: ' +
                response.status +
                ' Content-Type: ' +
                response.headers['content-type'] +
                '.';
              return cb(new Error(message));
            }

            info = response.data;

            cb();
          })
          .catch((err) => {
            if (err) {
              switch (err.code) {
              case 'ECONNREFUSED':
                console.log('Unable to reach Auth0 at ' + ticket);
                break;
              case 'UNABLE_TO_VERIFY_LEAF_SIGNATURE':
              case 'CERT_UNTRUSTED':
                console.error(
                  'The Auth0 server is using a certificate issued by an untrusted Certification Authority.',
                  err
                );
                console.log(
                  'Go to https://auth0.com/docs/connector/ca-certificates for instructions on how to install your CA certificate.'
                );
                break;
              case 'DEPTH_ZERO_SELF_SIGNED_CERT':
                console.error(
                  'The Auth0 server is using a self-signed certificate',
                  err
                );
                console.log(
                  'Go to https://auth0.com/docs/connector/ca-certificates for instructions on how to install your certificate.'
                );
                break;
              default:
                console.error(
                  'Unexpected error while configuring connection:',
                  err
                );
              }
              return cb(err);
            }
          });
      },
      function (cb) {
        var ldap_url = nconf.get('LDAP_URL');
        var ldap_base = nconf.get('LDAP_BASE');

        if (ldap_url) return cb();

        adLdapSettings.discoverSettings(
          info.connectionDomain,
          function (config) {
            var detectedUrl = '';
            var detectedDN = '';
            if (config) {
              detectedUrl = config.LDAP_URL || '';
              detectedDN = config.LDAP_BASE || '';
            }

            if (console.restore) console.restore();

            program.prompt(
              'Please enter your LDAP server URL [' + detectedUrl + ']: ',
              function (url) {
                ldap_url = url && url.length > 0 ? url : detectedUrl;

                program.prompt(
                  'Please enter the LDAP server base DN [' + detectedDN + ']: ',
                  function (dn) {
                    ldap_base = dn && dn.length > 0 ? dn : detectedDN;

                    nconf.set('LDAP_BASE', ldap_base);
                    nconf.set('LDAP_URL', ldap_url);
                    nconf.save();

                    if (console.inject) console.inject();

                    cb();
                  }
                );
              }
            );
          }
        );
      },
      function (cb) {
        function anonymousSearchEnabled(enabled) {
          nconf.set('ANONYMOUS_SEARCH_ENABLED', enabled);
          console.log(
            'Is Anonymous LDAP search enabled? ' + (enabled ? 'yes' : 'no')
          );
          connection.destroy();
          return cb();
        }
        const searchOpts = {
          filter: '(objectclass=person)',
          scope: 'sub',
          sizeLimit: 1,
        };
        const connection = createConnection();
        connection.search(
          nconf.get('LDAP_BASE'),
          searchOpts,
          function (err, res) {
            if (err) {
              return anonymousSearchEnabled(false);
            }

            var searchEntry;
            res
              .once('searchEntry', function (entry) {
                searchEntry = entry;
              })
              .once('end', function (result) {
                const isEnabled = searchEntry && result.status === 0;
                anonymousSearchEnabled(isEnabled);
              })
              .once('error', function (err) {
                // if there are more than one entry matching the search, the server returns the one entry and a SizeLimitExceededError error
                anonymousSearchEnabled(err.name === 'SizeLimitExceededError');
              });
          }
        );
      },
      function (cb) {
        var do_not_configure_firewall =
          nconf.get('FIREWALL_RULE_CREATED') ||
          !info.kerberos ||
          process.platform !== 'win32';

        if (do_not_configure_firewall) {
          return cb();
        }

        // add a firewall rule the first time
        firewall.add_rule({
          name: 'Auth0ConnectorKerberos',
          program: path.resolve(
            path.join(
              __dirname,
              '/../node_modules/kerberos-server/kerberosproxy.net/KerberosProxy/bin/Debug/KerberosProxy.exe'
            )
          ),
          profile: 'private',
        });

        console.log('Firewall rule added.');

        cb();
      },
      function (cb) {
        nconf.set('AD_HUB', info.adHub);
        nconf.set('PROVISIONING_TICKET', provisioningTicket);
        nconf.set('WSFED_ISSUER', info.connectionDomain);
        nconf.set('CONNECTION', info.connectionName);
        nconf.set('CLIENT_CERT_AUTH', info.certAuth);
        nconf.set('KERBEROS_AUTH', info.kerberos);
        nconf.set('FIREWALL_RULE_CREATED', info.kerberos);
        nconf.set('REALM', info.realm.name);
        nconf.set('SITE_NAME', nconf.get('SITE_NAME') || info.connectionName);
        nconf.set(info.realm.name, info.realm.postTokenUrl);
        emptyVars.forEach(function (ev) {
          if (!nconf.get(ev)) nconf.set(ev, '');
        });

        nconf.save(cb);

        console.log('Local settings updated.');
      },
      function (cb) {
        certificate(workingPath, info, cb);
      },
      function (cb) {
        var password = nconf.get('LDAP_BIND_PASSWORD');
        if (password) {
          nconf.clear('LDAP_BIND_PASSWORD');
          nconf.set('LDAP_BIND_CREDENTIALS', crypto.encrypt(password));
        }
        cb();
      },
      function (cb) {
        configureConnection(program, workingPath, info, provisioningTicket, cb);
      },
      function (cb) {
        console.log('Connector setup complete.');
        if (nconf.get('OVERRIDE_CONFIG')) {
          return nconf.save(cb);
        }
        cb();
      },
    ],
    function (err) {
      if (err) return callback(err);
      callback();
    }
  );
};
