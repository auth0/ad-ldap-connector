const xtend = require('xtend');
const config = require('../lib/config');
const { restartConnectorService, getHashedAdminPassword } = require('./utils');

/**
 * Middleware to require authentication for admin routes. If no admin password is set, redirects to the setup page.
 * If the user is not authenticated, redirects to the login page.
 *
 * @param req
 * @param res
 * @param next
 * @return {Promise<*>}
 */
async function requireAuth(req, res, next) {
  try {
    if (!(await getHashedAdminPassword())) {
      return res.redirect('/setup');
    }
    if (!req.session.authenticated) {
      return res.redirect('/login');
    }
    next();
  } catch (err) {
    next(err);
  }
}

/**
 * Middleware to require that an admin password is set. If not, redirects to the setup page.
 * Used for routes that are accessible without authentication but require an admin password to be set,
 * such as the login page.
 *
 * @param req
 * @param res
 * @param next
 * @return {Promise<*>}
 */
async function requireAdminPasswordSet(req, res, next) {
  try {
    if (!(await getHashedAdminPassword())) {
      return res.redirect('/setup');
    }
    next();
  } catch(err) {
    next(err);
  }
}

/**
 * Merges the current config with any variables passed in from a form submission. This is legacy code and it feels
 * like a lazy nuke-y way to handle form submissions.
 * TODO: Replace this with more explicit handling of form values from specific forms / views.
 *
 * @param req
 * @param res
 * @param next
 * @return {Promise<*>}
 */
async function mergeConfig(req, res, next) {
  try {
    var newConfig = xtend(req.current_config, req.body);
    for (const key of Object.keys(newConfig)) {
      config.set(key, newConfig[key]);
    }
    await config.save();

    if (req.body.LDAP_URL || req.body.PORT || req.body.SERVER_URL) {
      return restartConnectorService().then(() => {
        return res.redirect('/?s=1');
      });
    }

    res.redirect('/');
  } catch(err) {
    next(err);
  }
}

/**
 * Adds all config from the config file and explicitly set at runtime to the request object as current_config,
 * so that it can be used by downstream middleware and route handlers.
 *
 * @param req
 * @param res
 * @param next
 */
function setCurrentConfig(req, res, next) {
  req.current_config = config.getAll();
  next();
}

/**
 * Extracts any errorMessage passed on from a redirectWithError call.
 *
 * @param req
 * @param res
 * @param next
 */
function extractErrorMessage(req, res, next) {
  if (req.session.errorMessage) {
    req.errorMessage = req.session.errorMessage;
    delete req.session.errorMessage;
  }
  next();
}

/**
 * Injects a `redirectWithError` method into the res object which can be used to both redirect and pass on an error.
 * This is complimentary to the extractErrorMessage middleware.
 *
 * @param req
 * @param res
 * @param next
 */
function injectRedirectWithError(req, res, next) {
  res.redirectWithError = ({
    url = '',
    errorMessage,
    anchor
  }) => {
    req.session.errorMessage = errorMessage;
    res.redirect(`/${url}${(anchor ? '#' + anchor : '')}`);
  };
  next();
}

module.exports = {
  requireAuth,
  requireAdminPasswordSet,
  mergeConfig,
  setCurrentConfig,
  extractErrorMessage,
  injectRedirectWithError
};
