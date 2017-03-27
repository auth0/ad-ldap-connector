FROM node:6
RUN curl -Lo /tmp/adldap.tar.gz https://github.com/auth0/ad-ldap-connector/archive/v3.3.0.tar.gz
RUN mkdir /opt/auth0-adldap
RUN tar -xzf /tmp/adldap.tar.gz -C /opt/auth0-adldap --strip-components=1
WORKDIR /opt/auth0-adldap
RUN npm install
ENTRYPOINT ["node", "server.js"]
