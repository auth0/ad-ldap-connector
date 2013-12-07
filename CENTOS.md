1.  Download the repository:

```
$ curl -Lo - https://github.com/auth0/ad-ldap-connector/tarball/master | tar -xzf -  -C /tmp
```

2.  Move to `/opt`

```
$ mv /tmp/auth0-ad-ldap-connector-*/ /opt/auth0-ad-ldap/
```

3.  Access `/opt/auth0-ad-ldap/` and install modules as follows:

```
$ npm i --production
```

4.  Run the connector for the first time:

```
$ node server.js
```

Add your connector ticket when requested.

5.  Add your LDAP settings to `config.json` file and then run the connector again:

```
$ vi config.json
$ node server.js
```

6.  Verify with the __Try__ button in the dashboard if your connector is working.

7.  Once a your service is working on the dashboard, we are going to configure it as a upstar daemon:

```
# Create a system account:
$ useradd ad-ldap-connector -r

# Create a log file and change the owner to the system account:
$ touch /var/log/ad-ldap-connector.log
$ chown ad-ldap-connector /var/log/ad-ldap-connector.log
```




