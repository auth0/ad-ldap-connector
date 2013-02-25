Identity provider example that uses WS-Federation an SAML and validates against a table in sql server.

It uses [node-wsfed](https://github.com/auth0/node-wsfed) and Passport.js local strategy with a function that validates user name and bcrypted-passwords.

Since it uses [node-sqlserver](https://github.com/WindowsAzure/node-sqlserver) it can run only on windows.
