WS Federation middleware for node.js.

[![Build Status](https://travis-ci.org/auth0/node-wsfed.png)](https://travis-ci.org/auth0/node-wsfed)

## Installation

    npm install wsfed

## Introduction

This middleware is meant to generate a valid WSFederation endpoint that talks saml.

The idea is that you will use another mechanism to valida the user first.

The endpoint supports metadata as well in the url ```/FederationMetadata/2007-06/FederationMetadata.xml```.

## Usage

Options

| Name                | Description                                      | Default                                      |
| --------------------|:-------------------------------------------------| ---------------------------------------------|
| cert                | public key used by this identity provider        | REQUIRED                                     |
| key                 | private key used by this identity provider       | REQUIRED                                     |
| getPostURL          | get the url to post the token f(wtrealm, wreply, req, callback)                | REQUIRED                                     |
| issuer              | the name of the issuer of the token              | REQUIRED                                     |
| audience            | the audience for the saml token                  | req.query.wtrealm || req.query.wreply        |
| getUserFromRequest  | how to extract the user information from request | function(req) { return req.user; }           |
| profileMapper       | mapper to map users to claims (see PassportProfileMapper)| PassportProfileMapper |
| signatureAlgorithm  | signature algorithm, options: rsa-sha1, rsa-sha256 | ```'rsa-sha256'``` |
| digestAlgorithm     | digest algorithm, options: sha1, sha256          | ```'sha256'``` |
| wctx                | state of the auth process                        | ```req.query.wctx``` |


Add the middleware as follows:

~~~javascript
app.get('/wsfed', wsfed.auth({
  issuer:     'the-issuer',
  cert:       fs.readFileSync(path.join(__dirname, 'some-cert.pem')),
  key:        fs.readFileSync(path.join(__dirname, 'some-cert.key')),
  getPostUrl: function (wtrealm, wreply, req, callback) { 
                return cb( null, 'http://someurl.com')
              }
}));
~~~~

## WsFederation Metadata

wsfed can generate the metadata document for wsfederation as well. Usage as follows:

~~~javascript
app.get('/wsfed/FederationMetadata/2007-06/FederationMetadata.xml', wsfed.metadata({
  issuer:   'the-issuer',
  cert:     fs.readFileSync(path.join(__dirname, 'some-cert.pem')),
}));
~~~

It also accept two optionals parameters:

-  profileMapper: a class implementing the profile mapper. This is used to render the claims type information (using the metadata property). See [PassportProfileMapper](https://github.com/auth0/node-wsfed/blob/master/lib/claims/PassportProfileMapper.js) for more information.
-  endpointPath: this is the full path in your server to the auth route. By default the metadata handler uses the metadata request route without ```/FederationMetadata/2007..blabla.```

## WsFederation Metadata endpoints ADFS1-like

ADFS v1 uses another set of endpoints for the metadata and the thumbprint. If you have to connect an ADFS v1 client you have to do something like this:

~~~javascript
app.get('/wsfed/adfs/fs/federationserverservice.asmx',
    wsfed.federationServerService.wsdl);

app.post('/wsfed/adfs/fs/federationserverservice.asmx',
    wsfed.federationServerService.thumbprint({
      pkcs7: yourPkcs7,
      cert:  yourCert
    }));
~~~

notice that you need a ```pkcs7``` with the full chain of all certificates. You can generate this with openssl as follows:

~~~bash
openssl crl2pkcs7 -nocrl \
    -certfile your.crt \
    -certfile another-cert-in-the-chain.crt \
    -out contoso1.p7b
~~~ 

## License

MIT - AUTH0 2013!