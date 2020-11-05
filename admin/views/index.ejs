<!DOCTYPE html>
<html lang="en">
<head>
  <title>Auth0 | AD LDAP Configuration</title>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="shortcut icon" href="https://auth0.com/auth0-styleguide/img/favicon.png">
  <link rel="stylesheet" type="text/css" href="//fonts.googleapis.com/css?family=Open+Sans:300,400,600,700,800"></head>
  <link rel="stylesheet" type="text/css" href="/main.min.css">
  <link rel="stylesheet" type="text/css" href="/codemirror.css">
  <link rel="stylesheet" type="text/css" href="/codemirror-addon/fold/foldgutter.css">
  <link rel="stylesheet" type="text/css" href="/codemirror-addon/hint/show-hint.css">
  <link rel="stylesheet" type="text/css" href="/codemirror-addon/lint/lint.css">
  <link rel="stylesheet" type="text/css" href="/custom.css">
<body>
  <div id="header">
    <h1>Auth0</h1>
  </div>
  <div id="sidebar" style="display: none;"></div>
  <div class="wrapper">
    <div id="tmp-dialogs"></div>
    <div id="content" style="margin-left: 0;">
      <input type="hidden" id="csrf" name="_csrf" value="<%= locals.csrfToken %>">
      <section id="configuration-section" class="content-page current">
        <div id="content-header">
        <h1>AD LDAP Connector <span id="connector-version"></span> Configuration</h1>
        </div>

        <div class="container-fluid flat">
          <div id="update-available" class="alert alert-success">
            A new update for the AD LDAP Connector is available. Go to the <a id="update-show" href="#update">Update tab</a> to install v<span id="update-version"></span>.
          </div>
          <% include header_alerts %>

          <ul class="nav nav-tabs">
            <li class="active">
              <a href="/#configuration">Configuration</a>
            </li>
            <li>
              <a href="/#profile-mapper">Profile Mapper</a>
            </li>
            <li>
              <a href="/#export">Import / Export</a>
            </li>
            <li>
              <a href="/#troubleshooting">Troubleshooting</a>
            </li>
            <li>
              <a href="/#search-users">Search</a>
            </li>
            <% if (process.platform === 'win32') { %>
            <li>
              <a id="update-tab" href="/#update">Update</a>
            </li>
            <% } %>
          </ul>

          <div class="tab-content">
            <div class="tab-pane active" id="configuration">
              <div class="widget-box">
                <div class="widget-title">
                  <h5>Settings</h5>
                </div>
                <div class="widget-content">
                  <% if (locals.PROVISIONING_TICKET) { %>
                  <% include form %>
                  <% } else { %>
                  <% include form_ticket %>
                  <% } %>

                  <% if (locals.LDAP_RESULTS) { %>
                  <% include test_result %>
                  <% } %></div>
              </div>

              <% if (locals.SERVER_URL && (locals.KERBEROS_AUTH || locals.CLIENT_CERT_AUTH)) { %>
              <div class="widget-box">
                <div class="widget-title">
                  <h5>Advanced Settings</h5>
                </div>
                <div class="widget-content">
                  <% include form_server %></div>
              </div>
              <% } %>
            </div>

            <div class="tab-pane" id="profile-mapper">
              <div class="widget-box">
                <div class="widget-title">
                  <h5>Editor</h5>
                </div>
                <div class="widget-content">
                  <% include form_profilemapper %>
                </div>
              </div>
            </div>

            <div class="tab-pane" id="export">
              <div class="widget-box">
                <div class="widget-title">
                  <h5>Import</h5>
                </div>
                <div class="widget-content">
                  <% include form_import %>
                </div>
              </div>
              <div class="widget-box">
                <div class="widget-title">
                  <h5>Export</h5>
                </div>
                <div class="widget-content">
                  <% include form_export %>
                </div>
              </div>
            </div>

            <div class="tab-pane" id="troubleshooting">
              <div class="widget-box">
                <div class="widget-title">
                  <h5>Troubleshooter</h5>
                </div>
                <div class="widget-content">
                  <% include troubleshooter %>
                </div>
              </div>
              <div class="widget-box">
                <div class="widget-title">
                  <h5>Logs</h5>
                </div>
                <div class="widget-content">
                  <% include logs %>
                </div>
              </div>
            </div>

            <div class="tab-pane" id="search-users">
              <div class="widget-box">
                <div class="widget-title">
                  <h5>Find User by Login</h5>
                </div>
                <div class="widget-content">
                  <% include find_user_login %>
                </div>
              </div>
              <div class="widget-box">
                <div class="widget-title">
                  <h5>Search Users</h5>
                </div>
                <div class="widget-content">
                  <% include search_users %>
                </div>
              </div>
            </div>

            <% if (process.platform === 'win32') { %>
            <div class="tab-pane" id="update">
              <div class="widget-box">
                <div class="widget-title">
                  <h5>Updater</h5>
                </div>
                <div class="widget-content">
                  <% include update_run %>
                </div>
              </div>
              <div id="update-logs-widget" class="widget-box" style="display: none">
                <div class="widget-title">
                  <h5>Update Logs</h5>
                </div>
                <div class="widget-content">
                  <% include update_logs %>
                </div>
              </div>
            </div>
            <% } %>
          </div>
        </div>
        </section>
    </div>
  </div>
  <script src="/jshint.js"></script>
  <script src="/jquery.min.js"></script>
  <script src="/bootstrap.min.js"></script>
  <script src="/codemirror.js"></script>
  <script src="/codemirror-javascript.js"></script>
  <script src="/codemirror-addon/edit/closebrackets.js"></script>
  <script src="/codemirror-addon/edit/closetag.js"></script>
  <script src="/codemirror-addon/comment/comment.js"></script>
  <script src="/codemirror-addon/comment/continuecomment.js"></script>
  <script src="/codemirror-addon/fold/foldgutter.js"></script>
  <script src="/codemirror-addon/lint/lint.js"></script>
  <script src="/codemirror-addon/hint/javascript-hint.js"></script>
  <script src="/codemirror-addon/lint/javascript-lint.js"></script>
  <script src="/codemirror-addon/edit/matchbrackets.js"></script>
  <script src="/codemirror-addon/edit/matchtags.js"></script>
  <script src="/codemirror-addon/hint/show-hint.js"></script>
  <script src="/codemirror-addon/display/placeholder.js"></script>
  <script src="/site.js"></script>
</body>
</html>
