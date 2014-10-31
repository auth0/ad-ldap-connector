/*
 * Wait 500ms and exit the process with the given code.
 */
module.exports = function (code) {
  setTimeout(function () {
    process.exit(code);
  }, 500);
};