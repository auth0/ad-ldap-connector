'use strict';

/**
 * Integration tests for admin/server.js endpoints.
 *
 */

const expect = require('chai').expect;
const request = require('supertest');
const proxyquire = require('proxyquire').noCallThru();
const bcrypt = require('bcryptjs');
const expressSession = require('express-session');
const defaultProfileMapping = require('../../lib/defaultProfileMapping');

// ---------------------------------------------------------------------------
// Profile mapper stub — avoids loading isolated-vm (no native build in tests)
// ---------------------------------------------------------------------------
let savedMappingScript = null;

const mockProfileMapper = {
  loadMappingScript: ({ fallbackToDefaultScript } = {}) => {
    if (savedMappingScript !== null) return savedMappingScript;
    if (fallbackToDefaultScript) return defaultProfileMapping.toString();
    return null;
  },
  saveMappingScript: (script) => { savedMappingScript = script; },
  mapProfile: async (rawProfile) => defaultProfileMapping(rawProfile),
  '@global': true,
};

// ---------------------------------------------------------------------------
// Shared session store — lets tests inspect server-side session contents
// ---------------------------------------------------------------------------
const MemoryStore = expressSession.MemoryStore;
const testStore = new MemoryStore();

/**
 * Parse the session ID from a supertest response's set-cookie header.
 */
function parseSid(res) {
  const raw = (res.headers['set-cookie'] || []).find(c => c.startsWith('connect.sid='));
  if (!raw) return null;
  // cookie value is URL-encoded; the session ID is after "s%3A" and before the first "."
  const val = decodeURIComponent(raw.split(';')[0].split('=')[1]);
  return val.replace(/^s:/, '').split('.')[0];
}

/**
 * Retrieve the session object for a given session ID from the test store.
 */
function getSession(sid) {
  return new Promise((resolve, reject) => {
    testStore.get(sid, (err, session) => {
      if (err) return reject(err);
      resolve(session);
    });
  });
}

async function expectRedirectWithError({
  res,
  url = '/',
  errorMessage
}) {
  const sid = parseSid(res);
  const sessionData = sid ? await getSession(sid) : null;

  const statusCode = res.status || res.statusCode;
  expect(statusCode).to.equal(302);
  expect(res.headers.location).to.equal(url);
  expect(sessionData.errorMessage).to.equal(errorMessage);
}

const TEST_PASSWORD = 'TestPassword123456!';

// ---------------------------------------------------------------------------
// In-memory secure storage — realistic stand-in for the OS credential store
// ---------------------------------------------------------------------------
const keychainStore = new Map();

const mockSecureStorage = {
  store: async (key, value) => keychainStore.set(key, value),
  get: async (key) => keychainStore.get(key) || null,
  clear: async (key) => keychainStore.delete(key),
  keys: {
    AUTH_CERT: 'auth-cert',
    AUTH_CERT_KEY: 'auth-cert-key',
    LDAP_BIND_PASSWORD: 'ldap-bind-password',
    ADMIN_CONSOLE_PASSWORD: 'admin-console-password',
  },
  '@global': true,
};

function setAdminPassword(password) {
  const hash = bcrypt.hashSync(password, 1); // cost=1 for test speed
  keychainStore.set('admin-console-password', hash);
}

// ---------------------------------------------------------------------------
// App factory — minimal stubbing, real middleware pipeline
// ---------------------------------------------------------------------------
function buildApp() {
  // Wrap express-session to inject testStore so tests can inspect sessions
  const sessionStub = (opts) => expressSession({ ...opts, store: testStore });
  sessionStub.MemoryStore = MemoryStore;

  return proxyquire('../../admin/server', {
    // Prevent the HTTP server from binding a port during tests
    '../lib/add_certs': { inject: () => {}, injectAsync: () => Promise.resolve() },
    // No real LDAP server available in test environment
    '../lib/ldap': {
      initialize: () => Promise.resolve(),
      resetCredentials: () => {},
    },
    '../lib/users': function Users() {
      this.list = (q, opts, cb) =>
        cb(null, [{ dn: 'cn=test,dc=example,dc=com' }]);
      this.getByUserName = (q, opts, cb) =>
        cb(null, { dn: 'cn=test,dc=example,dc=com' });
    },
    // Replace the OS secure storage with an in-memory store
    // @global ensures the stub is used by admin/middleware.js too
    '../lib/secureStorage': mockSecureStorage,
    // Stub profileMapper to avoid loading isolated-vm (no native build in tests)
    '../lib/profileMapper': mockProfileMapper,
    // Inject our testStore so tests can inspect session contents
    'express-session': sessionStub,
  });
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/**
 * Parse the CSRF token from a hidden form field rendered by EJS.
 * Handles both attribute orderings produced by the templates:
 *   <input type="hidden" name="_csrf" value="TOKEN">
 *   <input type="hidden" id="csrf" name="_csrf" value="TOKEN">
 */
function extractCsrfToken(html) {
  const m =
    html.match(/name="_csrf"[^>]*value="([^"]+)"/) ||
    html.match(/value="([^"]+)"[^>]*name="_csrf"/);
  if (!m) throw new Error('CSRF token not found in response body');
  return m[1];
}

/**
 * Create a supertest agent, log in with TEST_PASSWORD, and return it.
 * The agent retains cookies (session + _csrf) across subsequent requests.
 */
async function createAuthenticatedAgent(app) {
  const agent = request.agent(app);
  const loginPage = await agent.get('/login');
  const csrfToken = extractCsrfToken(loginPage.text);
  const loginRes = await agent
    .post('/login')
    .type('form')
    .send({ _csrf: csrfToken, password: TEST_PASSWORD });
  expect(loginRes.status, 'login should redirect').to.equal(302);
  return agent;
}

/**
 * Fetch GET / with an already-authenticated agent and return its CSRF token.
 * Used as a source of valid CSRF tokens for protected POST endpoints.
 */
async function getCsrfToken(agent) {
  const res = await agent.get('/');
  expect(res.status, 'GET / should return 200 when authenticated').to.equal(200);
  return extractCsrfToken(res.text);
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------
describe('admin server endpoints (integration)', function () {
  this.timeout(10000);

  let app;

  before(function () {
    app = buildApp();
  });

  beforeEach(function () {
    keychainStore.clear();
    savedMappingScript = null;
  });

  // -------------------------------------------------------------------------
  // GET /setup
  // -------------------------------------------------------------------------
  describe('GET /setup', function () {
    it('renders the setup page when no admin password is set', async function () {
      const res = await request(app).get('/setup');
      expect(res.status).to.equal(200);
      expect(res.text).to.include('Set Admin Password');
    });

    it('redirects to / when an admin password is already set', async function () {
      setAdminPassword(TEST_PASSWORD);
      const res = await request(app).get('/setup');
      expect(res.status).to.equal(302);
      expect(res.headers.location).to.equal('/');
    });
  });

  // -------------------------------------------------------------------------
  // GET /login
  // -------------------------------------------------------------------------
  describe('GET /login', function () {
    it('redirects to /setup when no admin password is set', async function () {
      const res = await request(app).get('/login');
      expect(res.status).to.equal(302);
      expect(res.headers.location).to.equal('/setup');
    });

    it('renders the login form with a CSRF token when password is set', async function () {
      setAdminPassword(TEST_PASSWORD);
      const res = await request(app).get('/login');
      expect(res.status).to.equal(200);
      expect(res.text).to.include('name="_csrf"');
      expect(res.text).to.include('Admin Login');
    });

    it('redirects to / when already authenticated', async function () {
      setAdminPassword(TEST_PASSWORD);
      const agent = await createAuthenticatedAgent(app);
      const res = await agent.get('/login');
      expect(res.status).to.equal(302);
      expect(res.headers.location).to.equal('/');
    });
  });

  // -------------------------------------------------------------------------
  // POST /login — CSRF token must come from GET /login on the same agent
  // -------------------------------------------------------------------------
  describe('POST /login', function () {
    beforeEach(function () {
      setAdminPassword(TEST_PASSWORD);
    });

    it('redirects to / and establishes a session on the correct password', async function () {
      const agent = request.agent(app);
      const loginPage = await agent.get('/login');
      const csrfToken = extractCsrfToken(loginPage.text);

      const res = await agent
        .post('/login')
        .type('form')
        .send({ _csrf: csrfToken, password: TEST_PASSWORD });

      expect(res.status).to.equal(302);
      expect(res.headers.location).to.equal('/');
    });

    it('redirects back to the login form with an error message on wrong password', async function () {
      const agent = request.agent(app);
      const loginPage = await agent.get('/login');
      const csrfToken = extractCsrfToken(loginPage.text);

      const res = await agent
        .post('/login')
        .type('form')
        .send({ _csrf: csrfToken, password: 'totally-wrong-password' });

      await expectRedirectWithError({
        res, url: '/login', errorMessage: 'Invalid password'
      });
    });

    it('rejects the request when the CSRF token is missing', async function () {
      const res = await request(app)
        .post('/login')
        .type('form')
        .send({ password: TEST_PASSWORD });

      await expectRedirectWithError({
        res, errorMessage: 'invalid csrf token'
      });
    });

    it('rejects the request when the CSRF token is invalid', async function () {
      const agent = request.agent(app);
      // Trigger the CSRF cookie to be set
      await agent.get('/login');

      const res = await agent
        .post('/login')
        .type('form')
        .send({ _csrf: 'not-a-real-token', password: TEST_PASSWORD });

      await expectRedirectWithError({
        res, errorMessage: 'invalid csrf token'
      });
    });
  });

  // -------------------------------------------------------------------------
  // GET /logout
  // -------------------------------------------------------------------------
  describe('GET /logout', function () {
    it('redirects to /login', async function () {
      const res = await request(app).get('/logout');
      expect(res.status).to.equal(302);
      expect(res.headers.location).to.equal('/login');
    });

    it('destroys the session so protected routes require login again', async function () {
      setAdminPassword(TEST_PASSWORD);
      const agent = await createAuthenticatedAgent(app);

      // Confirm the session is active
      const beforeLogout = await agent.get('/version');
      expect(beforeLogout.status).to.equal(200);

      await agent.get('/logout');

      // After logout the session is gone — should redirect to /login
      const afterLogout = await agent.get('/version');
      expect(afterLogout.status).to.equal(302);
      expect(afterLogout.headers.location).to.equal('/login');
    });
  });

  // -------------------------------------------------------------------------
  // Protected routes — unauthenticated redirects
  // -------------------------------------------------------------------------
  describe('protected routes redirect to /setup when no password is set', function () {
    const routes = ['/', '/version', '/logs', '/profile-mapper'];

    routes.forEach(function (route) {
      it(`GET ${route} → /setup`, async function () {
        const res = await request(app).get(route);
        expect(res.status).to.equal(302);
        expect(res.headers.location).to.equal('/setup');
      });
    });
  });

  describe('protected routes redirect to /login when not authenticated', function () {
    beforeEach(function () {
      setAdminPassword(TEST_PASSWORD);
    });

    const routes = ['/', '/version', '/logs', '/profile-mapper'];

    routes.forEach(function (route) {
      it(`GET ${route} → /login`, async function () {
        const res = await request(app).get(route);
        expect(res.status).to.equal(302);
        expect(res.headers.location).to.equal('/login');
      });
    });
  });

  // -------------------------------------------------------------------------
  // Authenticated requests
  // -------------------------------------------------------------------------
  describe('authenticated requests', function () {
    let agent;

    before(async function () {
      setAdminPassword(TEST_PASSWORD);
      agent = await createAuthenticatedAgent(app);
    });

    beforeEach(function () {
      setAdminPassword(TEST_PASSWORD);
    });

    describe('GET /version', function () {
      it('returns the package version as plain text', async function () {
        const res = await agent.get('/version');
        expect(res.status).to.equal(200);
        expect(res.headers['content-type']).to.match(/text\/plain/);
        expect(res.text).to.match(/^\d+\.\d+\.\d+/);
      });
    });

    describe('GET /logs', function () {
      it('returns a plain-text response', async function () {
        const res = await agent.get('/logs');
        expect(res.status).to.equal(200);
        expect(res.headers['content-type']).to.match(/text\/plain/);
      });
    });

    describe('POST /logs/clear', function () {
      it('returns 200 with a valid CSRF token', async function () {
        const csrfToken = await getCsrfToken(agent);
        const res = await agent
          .post('/logs/clear')
          .type('form')
          .send({ _csrf: csrfToken });
        expect(res.status).to.equal(200);
      });

      it('returns 403 without a CSRF token', async function () {
        const res = await agent.post('/logs/clear').type('form').send({});
        await expectRedirectWithError({
          res, errorMessage: 'invalid csrf token'
        });
      });
    });

    describe('GET /profile-mapper', function () {
      it('returns a plain-text response', async function () {
        const res = await agent.get('/profile-mapper');
        expect(res.status).to.equal(200);
        expect(res.headers['content-type']).to.match(/text\/plain/);
      });

      it('returns non-empty script contents (falls back to default mapping)', async function () {
        const res = await agent.get('/profile-mapper');
        expect(res.status).to.equal(200);
        expect(res.text.length).to.be.greaterThan(0);
      });
    });

    describe('POST /profile-mapper', function () {
      it('returns 200 when a valid script is submitted with a CSRF token', async function () {
        const csrfToken = await getCsrfToken(agent);
        const res = await agent
          .post('/profile-mapper')
          .type('form')
          .send({ _csrf: csrfToken, code: 'module.exports = function(p) { return p; }' });
        expect(res.status).to.equal(200);
      });

      it('returns 403 without a CSRF token', async function () {
        const res = await agent
          .post('/profile-mapper')
          .type('form')
          .send({ code: 'module.exports = function(p) { return p; }' });
        await expectRedirectWithError({
          res, errorMessage: 'invalid csrf token'
        });
      });
    });

    describe('GET /users/search', function () {
      it('returns a JSON array of matching users', async function () {
        const res = await agent.get('/users/search?query=test');
        expect(res.status).to.equal(200);
        expect(res.headers['content-type']).to.match(/json/);
        expect(res.body).to.be.an('array');
      });
    });

    describe('GET /users/by-login', function () {
      it('returns user data as JSON', async function () {
        const res = await agent.get('/users/by-login?query=test');
        expect(res.status).to.equal(200);
      });
    });

    describe('POST /password', function () {
      it('redirects with an error when the new password is too short', async function () {
        const csrfToken = await getCsrfToken(agent);
        const res = await agent
          .post('/password')
          .type('form')
          .send({
            _csrf: csrfToken,
            current_password: TEST_PASSWORD,
            new_password: 'short',
            confirm_password: 'short',
          });
        await expectRedirectWithError({
          res, errorMessage: 'Password must be at least 15 characters long.', url: '/#security'
        });
      });

      it('redirects with an error when new passwords do not match', async function () {
        const csrfToken = await getCsrfToken(agent);
        const res = await agent
          .post('/password')
          .type('form')
          .send({
            _csrf: csrfToken,
            current_password: TEST_PASSWORD,
            new_password: 'NewSecurePassword123!',
            confirm_password: 'DifferentPassword456!',
          });
        await expectRedirectWithError({
          res, errorMessage: 'Passwords do not match.', url: '/#security'
        });
      });

      it('redirects with an error when the current password is incorrect', async function () {
        const csrfToken = await getCsrfToken(agent);
        const res = await agent
          .post('/password')
          .type('form')
          .send({
            _csrf: csrfToken,
            current_password: 'WrongCurrentPassword!',
            new_password: 'NewSecurePassword123!',
            confirm_password: 'NewSecurePassword123!',
          });
        await expectRedirectWithError({
          res, errorMessage: 'Current password is incorrect.', url: '/#security'
        });
      });

      it('redirects to /?s=1 on a successful password change', async function () {
        const csrfToken = await getCsrfToken(agent);
        const res = await agent
          .post('/password')
          .type('form')
          .send({
            _csrf: csrfToken,
            current_password: TEST_PASSWORD,
            new_password: 'NewSecurePassword123!',
            confirm_password: 'NewSecurePassword123!',
          });
        expect(res.status).to.equal(302);
        expect(res.headers.location).to.equal('/?s=1');
      });

      it('returns 403 without a CSRF token', async function () {
        const res = await agent
          .post('/password')
          .type('form')
          .send({
            current_password: TEST_PASSWORD,
            new_password: 'NewSecurePassword123!',
            confirm_password: 'NewSecurePassword123!',
          });
        await expectRedirectWithError({
          res, errorMessage: 'invalid csrf token'
        });
      });
    });
  });
});
