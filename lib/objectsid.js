const binary = require('binary');

//This logic was extracted from this implementation:
// https://github.com/pfmooney/node-ldapjs-mangle-proxy/blob/master/lib/objectsid.js

function outputType(type) {
  var buf = Buffer.alloc(6);
  type.copy(buf, 0);
  var output = 0;
  for (var i = 0; i < 6; i++) {
    output = output << 8;
    output = output | buf[i];
  }
  return output;
}

module.exports.parse = function(buffer) {
  if (!Buffer.isBuffer(buffer) || !buffer.length) {
    return;
  }
  try {
    const parser = binary.parse(buffer)
    .word8lu('version')
    .word8lu('fields')
    .buffer('type', 6)
    .loop(function (end, vars) {
      vars.sid = vars.sid || new Array();
      vars.sid.push(this.word32lu('sid_field').vars.sid_field);
      if (vars.sid.length >= vars.fields) {
        end();
      }
    });
    const { version, type, sid } = parser.vars;
    return ['S', version, outputType(type), ...sid].join('-');
  } catch(err) {
    return;
  }
};
