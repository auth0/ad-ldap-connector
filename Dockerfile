FROM node:16-slim AS base
# Install platform tools
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates

FROM base AS builder
ENV AD_LDAP_CONNECTOR_VERSION=6.1.1
ENV NPM_VERSION=7.20.2
WORKDIR /opt/auth0-adldap
# Install build tools
RUN apt-get install -y --no-install-recommends curl tar
# Download Connector
RUN curl -L https://github.com/auth0/ad-ldap-connector/archive/v$AD_LDAP_CONNECTOR_VERSION.tar.gz \
  | tar -xz --strip-components=1
# Install Connector dependencies
RUN npm install --loglevel warn --production

FROM base as production
WORKDIR /opt/auth0-adldap
# Copy builder output
COPY --from=builder /opt/auth0-adldap ./
CMD [ "server.js" ]
