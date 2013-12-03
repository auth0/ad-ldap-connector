exports.auth     = require('./wsfed');
exports.metadata = require('./metadata');
exports.federationServerService = {};
exports.federationServerService.wsdl = require('./federationServerService').wsdl;
exports.federationServerService.thumbprint = require('./federationServerService').thumbprint;