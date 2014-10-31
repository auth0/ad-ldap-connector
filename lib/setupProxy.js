var HTTP_PROXY = process.env.HTTP_PROXY || process.env.http_proxy;

if (!HTTP_PROXY) { return; }

console.log('Using an http proxy ', HTTP_PROXY);

var url    = require('url');
var tunnel = require('tunnel');
var proxy  = url.parse(HTTP_PROXY);
var localUrls = [];

var tunnelingAgent = tunnel.httpsOverHttp({
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

  options.agent = tunnelingAgent;
  return oldhttpsreq.call(null, options, callback);
};

var oldhttpreq = https.request;
http.request = function (options, callback) {

  if (localUrls.some(function (u) {
    return ~u.indexOf(options.host);
  })){
    return oldhttpreq.apply(http, arguments);
  }

  options.agent = tunnelingAgent;
  return oldhttpreq.call(null, options, callback);
};
