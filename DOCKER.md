# Using the AD/LDAP Connector with Docker

The AD/LDAP Connector agent can only run in a single host. Therefore, Docker is a perfect tool to run and manage multiple connectors for use cases where you have lots AD/LDAP Connections in Auth0 and associated AD/LDAP directories (or OUs within a directory) to connect to. For example, you may have user identities that are divided up by B2B customer spread across individual directories or OUs.

The `./docker-auth0-adldap.sh` script can be used to perform several workflows to manage one or more AD/LDAP Connector instances as Docker containers.

## Environment

First, set a few variables that will be used with all of the commands:

```bash
IMAGE_NAME=auth0-ad-ldap-connector
CONNECTOR_NAME=acme-ldap
```

* `IMAGE_NAME`: the name of the Docker image that will be used to create the Connector containers
* `CONNECTOR_NAME`: a name that identifies the Connector, which, as a convention can be the name of the associated Auth0 [AD/LDAP Connection](https://auth0.com/docs/connections/enterprise/active-directory-ldap).

## Build a local AD/LDAP Connector image

If you're not using a remote image library, you can build the image locally using the [Dockerfile](./Dockerfile):

```bash
./docker-auth0-adldap.sh build-image ${IMAGE_NAME}
```

> NOTE: If the image already exists, it will be removed and replaced by the new one.

## Run the first Connector container for your AD/LDAP Connection

The very first Connector container will "bootstrap" the associated AD/LDAP Connection such that no other Connector instance can use the provisioning URL again. This is done via the self-signed certificate that a Connector generates and registers with the Auth0 connection.

To set this up, first create a `config.json` file that contains the provisioning ticket URL of the associated AD/LDAP Connection in Auth0 as well as the `LDAP_`* configuration needed to communicate with the associated AD/LDAP server:

```json
{
  "PROVISIONING_TICKET": "AD_LDAP_CONNECTION_PROVISIONING_TICKET_URL",
  "LDAP_URL": "ldap://ldap.forumsys.com",
  "LDAP_BASE": "dc=example,dc=com",
  "LDAP_USER_BY_NAME": "(uid={0})",
  "LDAP_SEARCH_QUERY": "(&(objectClass=person)(uid={0}))",
  "LDAP_SEARCH_ALL_QUERY": "(objectClass=person)"  
}
```

> NOTE: The above `LDAP_`* configuration works with a [free online LDAP test server](https://www.forumsys.com/tutorials/integration-how-to/ldap/online-ldap-test-server/), which makes for easy testing of the Connector without having to stand up your own LDAP server. You may need to use different AD/LDAP Connector [configuration options](https://auth0.com/docs/extensions/ad-ldap-connector/ad-ldap-connector-config-file-schema) (such as `LDAP_BIND_USER` and `LDAP_BIND_PASSWORD`), depending on the requirements of your AD/LDAP server.

Next, create a `profileMapper.js` file in order to [map the desired LDAP attributes to the Auth0 user profile](https://auth0.com/docs/extensions/ad-ldap-connector/map-ad-ldap-profile-attributes-to-auth0) for the given AD/LDAP Connection.

With those files ready, bootstrap and fire up the first Connector:

```bash
./docker-auth0-adldap.sh run-first-connector ${IMAGE_NAME} ${CONNECTOR_NAME}
```

For development, you may only need a single Connector container running, so the above is sufficient. However, if you want to run multiple Connector instances for [high availability](https://auth0.com/docs/extensions/ad-ldap-connector/ad-ldap-high-availability), keep reading.

## Export Connector configuration

Before you can run another Connector container that will be associated with the _same_ AD/LDAP Connection in Auth0, you need to capture the configuration from the first container:

```bash
./docker-auth0-adldap.sh export-connector-config ${IMAGE_NAME} ${CONNECTOR_NAME}
```

This will generate a `config.tar.gz` file, which you can use with the next command.

## Run additional Connector containers for your AD/LDAP Connection

With the configuration exported, you can run this command to create and start an additional Connector container:

```bash
./docker-auth0-adldap.sh run-additional-connector ${IMAGE_NAME} ${CONNECTOR_NAME}-ha1
```

This sub-command takes the same arguments as `run-first-connector`. However, if you are running the additional container in the same Docker instance, you will need to provide a unique suffix (like `-ha1` shown above) so a unique container name is generated.

## Kill all Connector containers

If you simply simply need to wipe out all Connector containers (running or not) in the Docker instance that are associated with your Connector image, you can run this command:

```bash
./docker-auth0-adldap.sh kill-connectors ${IMAGE_NAME}
```
