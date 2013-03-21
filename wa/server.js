var http = require('http');
var express = require('express');
var passport = require('passport');

var app = express();

require('./setupPassportForWa');
var wsfederationResponses = require('../wsfederation-responses');

app.configure(function(){
  this.use(passport.initialize());
});

app.get('/wa', 
  passport.authenticate('WindowsAuthentication', { session: false }),
  wsfederationResponses.token);


http.createServer(app).listen(process.env.PORT || 5000);