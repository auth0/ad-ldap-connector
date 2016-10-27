
var nconf = require('nconf');

var HTTP_PROXY = nconf.get('HTTP_PROXY');
if (!HTTP_PROXY || HTTP_PROXY === '') { HTTP_PROXY = process.env.HTTP_PROXY || process.env.http_proxy; };
if (!HTTP_PROXY) { return; }

console.log('Using an http proxy ', HTTP_PROXY);

var url    = require('url');
var tunnel = require('tunnel');
var proxy  = url.parse(HTTP_PROXY);
var localUrls = [];

var httpsAgent = tunnel.httpsOverHttp({
  proxy: {
    host: proxy.hostname,
    port: proxy.port
  }
});

var httpAgent = tunnel.httpOverHttp({
  proxy: {
    host: proxy.hostname,
    port: proxy.port
  }
});


var https = require('https');
var http = require('http');

var oldhttpsreq = https.request;
https.request = function (options, callback) {

  // console.log(options.uri);

  if (localUrls.some(function (u) {
    return ~u.indexOf(options.host);
  })){
    return oldhttpsreq.apply(https, arguments);
  }

  // HTTPs over HTTP tunnel 
  options.agent = httpsAgent;
  options.tunneling = true;

  return oldhttpsreq.call(https, options, callback);
};

// http.request override is only required if we need HTTP over HTTP tunnel. 
// Which is currently not required in connector as all traffic is HTTPS. Kept here for completeness... 
var oldhttpreq = http.request;
http.request = function (options, callback) {

  if (localUrls.some(function (u) {
    return ~u.indexOf(options.host);
  })){
    return oldhttpreq.apply(http, arguments);
  }

  if (options.tunneling) // call http directly as tunnel is currently being created
    return oldhttpreq.apply(http, arguments);

  // Http over Http tunnel 
  options.agent = httpAgent;
  return oldhttpreq.call(http, options, callback);
};