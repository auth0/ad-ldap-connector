var http     = require('http');
var express  = require('express');
var passport = require('passport');


require('./setupPassport');

var cookieSessions = require('cookie-sessions');
var app = express();


//configure the webserver
app.configure(function(){
  this.set('view engine', 'ejs');
  this.set('views', __dirname + '/views');

  this.use(express.static(__dirname + '/public'));
  
  this.use(express.cookieParser());
  this.use(express.bodyParser());
  this.use(cookieSessions({
    session_key:    'sqlfs',
    secret:         process.env.SESSION_SECRET
  }));

  this.use(passport.initialize());
  this.use(this.router);
});


require('./endpoints').install(app);

http.createServer(app)
    .listen(process.env.PORT || 5000);