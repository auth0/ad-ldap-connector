var templates   = require('./templates');
var interpolate = require('./interpolate');

module.exports = function (options) {
  // http://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.pdf
  function renderResponse(res, postUrl) {
    options.fault = options.fault || {};

    var fault = templates['soapFault']({
      code:         options.fault.code,
      description:  options.fault.description
    });

    var form = options.formTemplate ?
      interpolate(options.formTemplate) : templates[(!options.plain_form ? 'form' : 'form_el')];

    res.set('Content-Type', 'text/html');
    res.send(form({
      callback: postUrl,
      wctx:     options.wctx,
      wresult:  fault
    }));
  }

  return function (req, res, next) {
    options.getPostURL(req, function (err, postUrl) {
      if (err) return next(err);
      if (!postUrl) return next(new Error('postUrl is required'));
      renderResponse(res, postUrl);
    });
  };
};