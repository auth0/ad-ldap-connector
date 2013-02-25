var http     = require('http');
var express  = require('express');
var passport = require('passport');

var app = express();

require('./setupPassport');
var wsfedMiddleware = require('./setupWsfedMiddleware');

//configure the webserver
app.configure(function(){
  this.set('view engine', 'ejs');
  this.set('views', __dirname + '/views');
  this.use(express.cookieParser());
  this.use(express.bodyParser());
  this.use(express.session({ secret: 'keysec' }));
  this.use(passport.initialize());
  this.use(passport.session());
  this.use(this.router);
});

// wsfederation endpoints
app.get('/FederationMetadata/2007-06/FederationMetadata.xml', 
        wsfedMiddleware.metadataMiddleware);

app.get('/wsfed/', 
  function (req, res, next) {
    return res.render('login', { 
      url: req.url 
    });
  });

app.post('/wsfed/', 
  function (req, res, next) {
    passport.authenticate('local', { 
      failureRedirect: req.url, 
    })(req, res, next);
  }, wsfedMiddleware);

http.createServer(app)
    .listen(process.env.PORT || 5000);