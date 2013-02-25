var ejs = require('ejs');

var fs = require('fs');
var path = require('path');
var formTemplateString = fs.readFileSync(path.join(__dirname, '../templates/wsfedform.ejs')).toString();
var metadataTemplateString = fs.readFileSync(path.join(__dirname, '../templates/metadata.ejs')).toString();

var formTemplate = ejs.compile(formTemplateString);
var metadataTemplate = ejs.compile(metadataTemplateString);

module.exports = {
  form:     formTemplate,
  metadata: metadataTemplate
};