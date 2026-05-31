var utils = require('./utils');
var templates = require('./templates');
var URL_PATH = '/wsfed/adfs/fs/federationserverservice.asmx';
var encoders = require('./encoders');

function getLocation (req) {
  return utils.getBaseUrl(req) + req.originalUrl;
}

function getEndpointAddress (req, endpointPath) {
  endpointPath = endpointPath ||
    (req.originalUrl.substr(0, req.originalUrl.length - URL_PATH.length));
  return utils.getBaseUrl(req) + endpointPath;
}

module.exports.wsdl = function (req, res) {
  res.set('Content-Type', 'text/xml; charset=UTF-8');
  if(req.query.wsdl){
    return res.send(templates.federationServerServiceWsdl());
  }
  res.send(templates.federationServerService({
    location: getLocation(req)
  }));
};

module.exports.thumbprint = function (options) {
  return function (req, res) {
    res.set('Content-Type', 'text/xml; charset=UTF-8');
    res.send(templates.federationServerServiceResponse({
      location:   getEndpointAddress(req, options.endpointPath),
      cert:       encoders.removeHeaders(options.pkcs7.toString()),
      thumbprint: encoders.thumbprint(options.cert)
    }));
  };
};
