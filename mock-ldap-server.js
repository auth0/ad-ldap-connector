const ldap = require('ldapjs');
const db = require('./test/resources/mock_ldap_data.json');
const nconf = require('nconf');
const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const BASE_DN = 'dc=example,dc=org';
const LDAP_SERVER_PORT = 4444;
const WEB_PORT = 3000;

nconf.set('LDAP_URL', `ldap://0.0.0.0:${LDAP_SERVER_PORT}`);
nconf.set('LDAP_BASE', 'dc=example,dc=org');
nconf.set('LDAP_BIND_USER', 'cn=admin,dc=example,dc=org');
nconf.set('LDAP_BIND_PASSWORD', 'admin');
nconf.set('LDAP_USER_BY_NAME', '(&(objectClass=inetOrgPerson)(uid={0}))');
nconf.set(
  'LDAP_SEARCH_QUERY',
  '(&(objectClass=inetOrgPerson)(|(cn={0})(givenName={0})(sn={0})(uid={0})))'
);
nconf.set('LDAP_SEARCH_ALL_QUERY', '(objectClass=inetOrgPerson)');
nconf.set('LDAP_SEARCH_GROUPS', '(member={0})');

// This is an in-memory LDAP server used to run unit/integration tests
// It is based on the example of the ldapjs library: http://ldapjs.org/examples.html
const server = ldap.createServer();

server.bind(BASE_DN, function (req, res, next) {
  if (!req.credentials || req.credentials === '') {
    return next(new ldap.InvalidCredentialsError());
  }
  
  var dn = req.dn.format({ skipSpace: true });
  if (!db[dn]) return next(new ldap.NoSuchObjectError(dn));

  if (!db[dn].userPassword)
    return next(new ldap.NoSuchAttributeError('userPassword'));

  if (db[dn].userPassword !== req.credentials)
    return next(new ldap.InvalidCredentialsError());

  res.end();
  return next();
});

server.search(BASE_DN, function (req, res, next) {
  var dn = req.dn.format({ skipSpace: true });
  if (!db[dn]) return next(new ldap.NoSuchObjectError(dn));

  var scopeCheck;

  switch (req.scope) {
  case 'base':
    if (req.filter.matches(db[dn])) {
      res.send({
        dn: dn,
        attributes: db[dn],
      });
    }

    res.end();
    return next();

  case 'one':
    scopeCheck = function (k) {
      if (req.dn.equals(k)) return true;

      var parent = ldap.parseDN(k).parent();
      return parent ? parent.equals(req.dn) : false;
    };
    break;

  case 'sub':
    scopeCheck = function (k) {
      return req.dn.equals(k) || req.dn.parentOf(k);
    };

    break;
  }

  Object.keys(db).forEach(function (key) {
    if (!scopeCheck(key)) return;

    if (req.filter.matches(db[key])) {
      res.send({
        dn: key,
        attributes: db[key],
      });
    }
  });

  res.end();
  return next();
});

server.listen(LDAP_SERVER_PORT, () => {
  console.log(`LDAP server running on ${LDAP_SERVER_PORT}`);
});

// ── Web UI ────────────────────────────────────────────────────────────────────
// A simple login form so you can simulate LDAP binds directly from the browser.
// Test accounts (from mock_ldap_data.json):
//   jdoe / 123   mdoe / 123   admin / admin (uses full DN)
// ─────────────────────────────────────────────────────────────────────────────

const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN || '';
const AUTH0_TENANT_HOST = process.env.AUTH0_TENANT_HOST || '';
const AD_CONNECTION = process.env.AUTH0_CONNECTION || '';
const AUTH0_GRANT_TYPE = process.env.AUTH0_GRANT_TYPE || '';
const DEFAULT_CLIENT_ID = process.env.AUTH0_CLIENT_ID || '';
const DEFAULT_CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET || '';

const LOGIN_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Mock LDAP Login</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, sans-serif; background: #f0f2f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
    .card { background: #fff; border-radius: 8px; box-shadow: 0 2px 12px rgba(0,0,0,.12); padding: 2rem; width: 420px; }
    h1 { font-size: 1.25rem; color: #111; }
    .tabs { display: flex; gap: .5rem; margin: 1.25rem 0 1rem; }
    .tab { flex: 1; padding: .5rem; border: 1px solid #d1d5db; border-radius: 6px; background: #f9fafb; font-size: .85rem; cursor: pointer; text-align: center; }
    .tab.active { background: #6366f1; color: #fff; border-color: #6366f1; }
    .panel { display: none; }
    .panel.active { display: block; }
    label { display: block; font-size: .85rem; color: #555; margin-bottom: .25rem; margin-top: 1rem; }
    input { width: 100%; padding: .6rem .75rem; border: 1px solid #d1d5db; border-radius: 6px; font-size: 1rem; }
    input:focus { outline: none; border-color: #6366f1; box-shadow: 0 0 0 3px rgba(99,102,241,.15); }
    button[type=submit] { margin-top: 1.5rem; width: 100%; padding: .7rem; background: #6366f1; color: #fff; border: none; border-radius: 6px; font-size: 1rem; cursor: pointer; }
    button[type=submit]:hover { background: #4f46e5; }
    .hint { margin-top: 1rem; font-size: .78rem; color: #888; }
    .hint code { background: #f3f4f6; padding: 1px 4px; border-radius: 3px; }
    .alert { margin-top: 1rem; padding: .75rem 1rem; border-radius: 6px; font-size: .9rem; }
    .alert.success { background: #d1fae5; color: #065f46; }
    .alert.error   { background: #fee2e2; color: #991b1b; }
    .badge { display: inline-block; font-size: .7rem; padding: 1px 6px; border-radius: 4px; margin-left: .4rem; vertical-align: middle; }
    .badge.ldap { background: #e0e7ff; color: #3730a3; }
    .badge.auth0 { background: #fef3c7; color: #92400e; }
    pre { margin-top: .5rem; font-size: .78rem; white-space: pre-wrap; word-break: break-all; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Login Test Panel</h1>
    <div class="tabs">
      <div class="tab active" onclick="switchTab('ldap',this)">Direct LDAP <span class="badge ldap">debug</span></div>
      <div class="tab" onclick="switchTab('auth0',this)">Full Flow via Auth0 <span class="badge auth0">e2e</span></div>
    </div>

    <div id="panel-ldap" class="panel active">
      <form method="POST" action="/login">
        <label for="u1">Username (uid)</label>
        <input id="u1" name="username" type="text" placeholder="jdoe" autocomplete="off" required>
        <label for="p1">Password</label>
        <input id="p1" name="password" type="password" placeholder="••••" required>
        <button type="submit">Bind directly to LDAP :4444</button>
      </form>
      <p class="hint">Bypasses the connector — tests LDAP only. Accounts: <code>jdoe / 123</code> &nbsp; <code>mdoe / 123</code></p>
    </div>

    <div id="panel-auth0" class="panel">
      <form method="POST" action="/login-auth0">
        ${DEFAULT_CLIENT_ID ? `<input name="client_id" type="hidden" value="${DEFAULT_CLIENT_ID}">` : `<label for="cid">Client ID</label><input id="cid" name="client_id" type="text" placeholder="your client_id" autocomplete="off" required>`}
        ${DEFAULT_CLIENT_SECRET ? `<input name="client_secret" type="hidden" value="${DEFAULT_CLIENT_SECRET}">` : `<label for="csec">Client Secret</label><input id="csec" name="client_secret" type="password" placeholder="your client secret" autocomplete="off" required>`}
        <label for="u2">Username (uid)</label>
        <input id="u2" name="username" type="text" placeholder="jdoe" autocomplete="off" required>
        <label for="p2">Password</label>
        <input id="p2" name="password" type="password" placeholder="••••" required>
        <button type="submit">Login via Auth0 → Connector → LDAP</button>
      </form>
      <p class="hint">Full e2e login flow through the connector.</p>
    </div>

    {{RESULT}}
  </div>
  <script>
    function switchTab(name, el) {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
      el.classList.add('active');
      document.getElementById('panel-' + name).classList.add('active');
    }
    // Keep active tab after form submit
    const hash = location.hash;
    if (hash === '#auth0') switchTab('auth0', document.querySelectorAll('.tab')[1]);
  </script>
</body>
</html>`;

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));

app.get('/', (req, res) => {
  res.send(LOGIN_HTML.replace('{{RESULT}}', ''));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const userDN = `cn=${username},ou=users,${BASE_DN}`;

  const client = ldap.createClient({ url: `ldap://127.0.0.1:${LDAP_SERVER_PORT}` });

  client.on('error', (err) => {
    const html = `<div class="alert error">Connection error: ${err.message}</div>`;
    res.send(LOGIN_HTML.replace('{{RESULT}}', html));
  });

  client.bind(userDN, password, (bindErr) => {
    if (bindErr) {
      client.destroy();
      const html = `<div class="alert error"><strong>Login failed</strong> — ${bindErr.message}</div>`;
      return res.send(LOGIN_HTML.replace('{{RESULT}}', html));
    }

    // Bind succeeded — search for the user's full attributes
    client.search(BASE_DN, {
      scope: 'sub',
      filter: `(uid=${username})`,
      attributes: ['cn', 'uid', 'mail', 'givenName', 'sn', 'objectClass']
    }, (searchErr, searchRes) => {
      const entries = [];

      searchRes.on('searchEntry', (entry) => entries.push(entry.object));

      searchRes.on('end', () => {
        client.destroy();
        const user = entries[0] || { dn: userDN };
        const html = `
          <div class="alert success">
            <strong>Login successful</strong>
            <pre>${JSON.stringify(user, null, 2)}</pre>
          </div>`;
        res.send(LOGIN_HTML.replace('{{RESULT}}', html));
      });

      if (searchErr) {
        client.destroy();
        const html = `<div class="alert success"><strong>Login successful</strong> (could not fetch user details)</div>`;
        res.send(LOGIN_HTML.replace('{{RESULT}}', html));
      }
    });
  });
});

app.post('/login-auth0', async (req, res) => {
  const { client_id, client_secret, username, password } = req.body;

  try {
    const params = new URLSearchParams({
      grant_type: AUTH0_GRANT_TYPE,
      client_id,
      client_secret,
      username,
      password,
      realm: AD_CONNECTION,
      scope: 'openid profile email',
    });

    const response = await axios.post(`${AUTH0_DOMAIN}/oauth/token`, params, {
      headers: {
        Host: AUTH0_TENANT_HOST,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });

    const { access_token, id_token } = response.data;

    // Decode id_token payload (no verification needed — this is local dev)
    const payload = JSON.parse(Buffer.from(id_token.split('.')[1], 'base64url').toString());

    const html = `
      <div class="alert success">
        <strong>Login successful — identity saved in auth0-server</strong>
        <pre>${JSON.stringify(payload, null, 2)}</pre>
        <details style="margin-top:.5rem">
          <summary style="cursor:pointer;font-size:.8rem">access_token</summary>
          <pre style="font-size:.7rem">${access_token}</pre>
        </details>
      </div>`;
    res.send(LOGIN_HTML.replace('{{RESULT}}', html) + '<script>location.hash="auth0"</script>');

  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data, null, 2) : err.message;
    const html = `<div class="alert error"><strong>Login failed</strong><pre>${detail}</pre></div>`;
    res.send(LOGIN_HTML.replace('{{RESULT}}', html) + '<script>location.hash="auth0"</script>');
  }
});

app.listen(WEB_PORT, () => {
  console.log(`Login UI running at http://localhost:${WEB_PORT}`);
});
