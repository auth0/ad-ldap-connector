var utils = require('./utils');

function getProp(obj, path) {
  return path.split('.').reduce(function (prev, curr) {
    return prev[curr];
  }, obj);
}

function escape (html){
  return utils.escape(html).replace(/'/g, '&#39;')
}

module.exports = function (tmpl) {
  return function (model) {
    return tmpl.replace(/\@\@([^\@]*)\@\@/g,
      function (a, b) {
        var r = getProp(model, b);
        var value = typeof r === 'string' || typeof r === 'number' ? r : a;
        return escape(value);
      }
    );
  };
};