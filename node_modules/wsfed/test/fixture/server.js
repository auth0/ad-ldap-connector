var express = require('express');
var http = require('http');
var wsfed = require('../../lib/wsfed');

var fs = require('fs');
var path = require('path');

var fakeUser = {
  id: '12334444444',
  displayName: 'Jose Romaniello',
  name: {
    familyName: 'Romaniello',
    givenName: 'Jose'
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
  key:      fs.readFileSync(path.join(__dirname, 'wsfed.test-cert.key'))
};

module.exports.start = function(callback){
  var app = express();

  app.configure(function(){
    this.use(function(req,res,next){
      req.user = fakeUser;
      next();
    });

    //configure wsfed middleware
    this.use('/wsfed', wsfed({
      issuer:   'fixture-test',
      callback: 'http://office.google.com',
      cert:     credentials.cert,
      key:      credentials.key
    }));

  });

  var server = http.createServer(app).listen(5050, callback);
  module.exports.close = server.close.bind(server);
};

module.exports.fakeUser = fakeUser;
module.exports.credentials = credentials;
