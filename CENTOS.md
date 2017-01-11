+  Install Node 4.4.7 with nave:

```
$ curl -o /opt/nave https://raw.github.com/isaacs/nave/master/nave.sh
$ chmod +x /opt/nave
$ /opt/nave install 4.4.7
$ /opt/nave usemain 4.4.7
```

+  Download the repository:

```
$ curl -Lo - https://github.com/auth0/ad-ldap-connector/tarball/master | tar -xzf -  -C /tmp
```

+  Move to `/opt`

```
$ mv /tmp/auth0-ad-ldap-connector-*/ /opt/auth0-ad-ldap/
```

+  Access `/opt/auth0-ad-ldap/` and install modules as follows:

```
$ npm i --production
```

+  Run the connector for the first time:

```
$ node server.js
```

+  Add your connector ticket when requested.

+  Add your LDAP URL and LDAP base DN when requested.

+  Add your LDAP user settings to `config.json` file and then run the connector again:

```
$ vi config.json
$ node server.js
```

+  Verify with the __Try__ button in the dashboard if your connector is working.

+  Once a your service is working with the Try button, we are going to configure it as an upstar daemon:

```
# Create a system account:
$ useradd ad-ldap-connector -r

# Create a log file and change the owner to the system account:
$ touch /var/log/ad-ldap-connector.log
$ chown ad-ldap-connector /var/log/ad-ldap-connector.log

# Change the owner of the connector directory:
$ chown -R ad-ldap-connector /opt/auth0-ad-ldap/
```

+  Create an upstart job in `/etc/init/ad-ldap-connector.conf`:

~~~
env NAME=ad-ldap-connector
env LOG_FILE=/var/log/ad-ldap-connector.log
env USER=ad-ldap-connector
env DIR=/opt/auth0-ad-ldap/
env SCRIPT_FILE=server.js
env NODE_BIN=/usr/local/bin/node

start on started network
stop on stopping network

# Respawn in case of a crash, with default parameters
respawn

script
  cd $DIR
  exec su -s /bin/sh -c 'exec "$0" "$@"' $USER -- $NODE_BIN $SCRIPT_FILE >> $LOG_FILE 2>&1
end script

post-start script
  echo "app $NAME post-start event" >> $LOG_FILE
end script
~~~

+  Start the service

~~~
$ initctl start ad-ldap-connector
~~~

+  You can check the application logs as follows:

~~~
$  tail -f /var/log/ad-ldap-connector.log
~~~
