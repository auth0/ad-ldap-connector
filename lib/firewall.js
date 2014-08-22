var exec    = require('child_process').exec;
var release = require('os').release;
var _       = require('lodash');

var commands = {
  advfirewall: 'netsh advfirewall firewall add rule name="${ name }" dir=in action=allow program="${ program }" profile=${ profile } enable=yes',
  firewall:    'netsh firewall add allowedprogram "${ program }" "${ name }" ENABLE'
};

var firewall = {};

firewall.add_rule = function (param, cb) {
  var command;

  cb = cb || function() {
    console.log('============================');
    console.log('Result of Adding a Firewall rule with:');
    console.log(command);
    console.log(arguments);
    console.log('============================');
  };

  if (parseFloat(release()) >= 6.0) { // vista or higher
    command = _.template(commands.advfirewall, param);
  } else {
    command = _.template(commands.firewall, param);
  }

  exec(command, cb);
};

module.exports = firewall;