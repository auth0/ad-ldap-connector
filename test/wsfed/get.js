module.exports = function get(uriOrOpts, cb) {
  const opts = typeof uriOrOpts === 'string' ? { uri: uriOrOpts } : uriOrOpts;
  fetch(opts.uri, { headers: opts.headers }).then(async function (response) {
    const body = await response.text();
    cb(null, { statusCode: response.status, body: body }, body);
  }).catch(cb);
};
