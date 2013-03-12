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
| callbackUrl         | the callback to post the token                   | REQUIRED                                     |
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
  issuer:   'the-issuer',
  callback: 'http://myapp/callback',
  cert:     fs.readFileSync(path.join(__dirname, 'some-cert.pem')),
  key:      fs.readFileSync(path.join(__dirname, 'some-cert.key')),
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

## Example micro-adfs

This is a demostration how you can configure something as Active Directory Federation Services (ADFS) with few lines of code by assembling some components.


~~~javascript
var express = require('express');
var http = require('http');
var wsfed = require('wsfed');

var serverSigning = {
  cert:     fs.readFileSync(path.join(__dirname, 'wsfed.test-cert.pem')),
  key:      fs.readFileSync(path.join(__dirname, 'wsfed.test-cert.key'))
};

//configure passport-windowsauth
var passport = require('passport');
var WindowsStrategy = require('passport-windowsauth');

passport.use(new WindowsStrategy({ 
  ldap: {
    url:             'ldap://wellscordoba.wellscordobabank.com/DC=wellscordobabank,DC=com',
    base:            'DC=wellscordobabank,DC=com',
    bindDN:          'someAccount',
    bindCredentials: 'andItsPass'
  }
}, function(profile, done){
  done(err, user);
}));

var app = express();

app.configure(function(){
  this.use(express.cookieParser());
  this.use(express.bodyParser());
  this.use(express.session({ secret: 'keyboard cat' }));
  this.use(passport.initialize());
  this.use(passport.session());
});

app.get('/wsfed/FederationMetadata/2007-06/FederationMetadata.xml',
  wsfed.metadata({
    cert:   serverSigning.cert,
    issuer: 'fixture-test'
  }));

app.get('/wsfed',   
  passport.authenticate('WindowsAuthentication', { session: false }),
  wsfed.auth({
    issuer:      'fixture-test',
    callbackUrl: 'http://office.google.com',
    cert:        serverSigning.cert,
    key:         serverSigning.key
  }));

var server = http.createServer(app).listen(5050, callback);

~~~

Notice that since this use [passport-windowsauth](https://github.com/auth0/passport-windowsauth) it will only runs under IIS/IISNode. However you can use any Passport.js strategy to create a Ws-Federation server.  

## License

MIT - AUTH0 2013!