This is an Security Token Service example that speaks [WS-Federation](http://msdn.microsoft.com/en-us/library/bb498017.aspx) with Saml11 tokens fully implemented in node.js.

Authentication is done with a SQL-Server table where user names and [bcrypted](http://en.wikipedia.org/wiki/Bcrypt) passwords are stored, thus the name **sql**-fs. 

This projects uses [node-wsfed](https://github.com/auth0/node-wsfed) and [Passport.js local strategy](http://passportjs.org/guide/username-password/).

Since it uses [node-sqlserver](https://github.com/WindowsAzure/node-sqlserver) it can run only on Windows for now but you can easily swap this to some other thing like Postgresql or mongodb.