var express = require('express');
var http = require('http');
var wsfed = require('../../lib');
var xtend = require('xtend');
var fs = require('fs');
var path = require('path');

var fakeUser = {
  id: '12334444444',
  displayName: 'José Romaniello',
  name: {
    familyName: 'Romaniello',
    givenName: 'José'
  },
  emails: [
    {
      type: 'work',
      value: 'jfr@jfr.com'
    }
  ]
};

var credentials = {
  cert:     fs.readFileSync(path.join(__dirname, 'wsfed.test-cert.pem')),
  key:      fs.readFileSync(path.join(__dirname, 'wsfed.test-cert.key')),
  pkcs7:    fs.readFileSync(path.join(__dirname, 'wsfed.test-cert.pb7'))
};

module.exports.options = {};

module.exports.start = function(options, callback){
  module.exports.options = options;
  if (typeof options === 'function') {
    callback = options;
    module.exports.options = {};
  }

  if (!options.credentials) {
    options.credentials = credentials;
  }

  var app = express();

  app.use(function(req,res,next){
    req.user = fakeUser;
    next();
  });

  app.get('/wsfed/FederationMetadata/2007-06/FederationMetadata.xml',
      wsfed.metadata({
        cert:   options.credentials.cert,
        issuer: 'fixture-test'
      }));

  app.get('/wsfed/adfs/fs/federationserverservice.asmx',
      wsfed.federationServerService.wsdl);

  app.post('/wsfed/adfs/fs/federationserverservice.asmx',
      wsfed.federationServerService.thumbprint({
        pkcs7: options.credentials.pkcs7,
        cert:  options.credentials.cert
      }));

  function getPostURL (wtrealm, wreply, req, callback) {
    if(!wreply || wreply == 'http://office.google.com'){
      return callback(null, 'http://office.google.com');
    }
    return callback();
  }

  //configure wsfed middleware
  app.get('/wsfed', function(req, res, next) {
    wsfed.auth(xtend({}, {
      issuer:             'fixture-test',
      getPostURL:         getPostURL,
      cert:               options.credentials.cert,
      key:                options.credentials.key,
    }, module.exports.options))(req, res, function(err){
      if (err) {
        return res.status(400).send(err.message);
      }
      next();
    })
  });
  
  var server = http.createServer(app).listen(5050, callback);
  module.exports.close = server.close.bind(server);
};

module.exports.fakeUser = fakeUser;
module.exports.credentials = credentials;
