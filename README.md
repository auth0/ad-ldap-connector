This is an Security Token Service example that speaks [WS-Federation](http://msdn.microsoft.com/en-us/library/bb498017.aspx) with Saml11 tokens fully implemented in node.js.

Authentication is done against an **Active Directory** or any server that speaks **LDAP**.

This projects uses [node-wsfed](https://github.com/auth0/node-wsfed) and [passport-windowsauth](https://github.com/auth0/passport-windowsauth).

## Throubleshooting

If you always get invalid username or password, try to search a profile by password with the following command:

```
node -e "require('./lib/initConf'); var Users = require('./lib/users'); var users = new Users(); users._queue.push(function(){users.getByUserName('the-username-you-are-trying', function (err, user) { console.log(user); } ); });"
```

By default the connector search using this query LDAP `(sAMAccountName={0})`, you can override this in the config.json file:

```
	"LDAP_USER_BY_NAME": "(cn={0})",
```

## License

MIT - Auth10 2013