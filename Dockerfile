FROM node:14

ENV AD_LDAP_CONNECTOR_VERSION=6.1.1

# Create app directory
WORKDIR /opt/auth0-adldap

# Download and install the Connector
RUN depsRuntime=" \
    # tools \
    vim \
    curl \
  " \
  set -x \
  && apt-get update \
  && apt-get install -y --no-install-recommends $depsRuntime \
  && curl -Lo /tmp/adldap.tar.gz https://github.com/auth0/ad-ldap-connector/archive/v$AD_LDAP_CONNECTOR_VERSION.tar.gz \
  && tar -xzf /tmp/adldap.tar.gz -C /opt/auth0-adldap --strip-components=1 \
  && npm install

CMD [ "node", "server.js" ]
