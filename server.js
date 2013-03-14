var http     = require('http');
var express  = require('express');
var passport = require('passport');
var WsFederationEndpoints = require('./WsFederationEndpoints');

var app = express();

require('./setupPassport');

//configure the webserver
app.configure(function(){
  this.set('view engine', 'ejs');
  this.set('views', __dirname + '/views');
  this.use(express.static(__dirname + '/public'));
  this.use(express.bodyParser());
  this.use(passport.initialize());
  this.use(this.router);
});

app.get('/wsfed/', 
  function (req, res) {
    return res.render('login', {
      title: process.env.SITE_NAME
    });
  });

WsFederationEndpoints.install(app);

http.createServer(app)
    .listen(process.env.PORT || 5000);