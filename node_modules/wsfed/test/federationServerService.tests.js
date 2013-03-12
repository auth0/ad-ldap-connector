var expect = require('chai').expect;
var server = require('./fixture/server');
var request = require('request');
var xmldom = require('xmldom');

describe('wsfed federationserverservice', function () {
  before(function (done) {
    server.start(done);
  });
  
  after(function (done) {
    server.close(done);
  });
  
  var doc;

  before(function (done) {
    request.get({
      jar: request.jar(), 
      uri: 'http://localhost:5050/wsfed/adfs/fs/federationserverservice.asmx'
    }, function (err, response, b){
      if(err) return done(err);
      doc = new xmldom.DOMParser().parseFromString(b).documentElement;
      done();
    });
  });

  it('should have the location field', function () {
    var location = doc.getElementsByTagName('soap:address')[0]
                      .getAttribute('location');
    expect(location)
      .to.equal('http://localhost:5050/wsfed/adfs/fs/federationserverservice.asmx');
  });

  it('should have the wsdl url', function () {
    var location = doc.getElementsByTagName('wsdl:import')[0]
                      .getAttribute('location');
    expect(location)
      .to.equal('http://localhost:5050/wsfed/adfs/fs/federationserverservice.asmx?wsdl=wsdl0');
  });

  describe('when loading wsdl', function () {
    var doc;

    before(function (done) {
      request.get({
        jar: request.jar(), 
        uri: 'http://localhost:5050/wsfed/adfs/fs/federationserverservice.asmx?wsdl=wsdl0'
      }, function (err, response, b){
        if(err) return done(err);
        doc = new xmldom.DOMParser().parseFromString(b).documentElement;
        done();
      });
    });

    it('should have have portType', function(){
      var portType = doc.getElementsByTagName('wsdl:portType')[0]
        .getAttribute('name');

      expect(portType)
        .to.equal('ITrustInformationContract');
    });
  });

  describe('when posting to the thumbprint endpoint', function () {
    var doc;

    before(function (done) {
      request.post({
        jar: request.jar(), 
        uri: 'http://localhost:5050/wsfed/adfs/fs/federationserverservice.asmx'
      }, function (err, response, b){
        if(err) return done(err);
        //not sure how to test this yet... 
        console.log(b);
        doc = new xmldom.DOMParser().parseFromString(b).documentElement;
        done();
      });
    });

    it('should have have portType', function(){
      // var portType = doc.getElementsByTagName('wsdl:portType')[0]
      //   .getAttribute('name');

      // expect(portType)
      //   .to.equal('ITrustInformationContract');
    });
  });
});