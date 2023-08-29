# AD Server Interactions

AD LDAP Connector helps facilitate proxied interactions to an LDAP server. The connector provides a set of
APIs that mirrors the interactions with other connections e.g. Custom Database Connections.

In the diagrams below the following names will be used to indicate the defined participants:

- CIC: The environment of Okta CIC (Auth0) that is being interacted with
- Connector: A running instance of the application defined in this repository
- AD: An active directory implementation that is the backend for the Auth0 connection

All three components act as servers, only the first two act as clients.

## Boot

### Client Instantiation

```mermaid
sequenceDiagram
  Connector ->> AD : Create Connection
  Connector ->> AD : Bind Connection
  Note right of Connector: referred to as Client
  Connector ->> AD : Create Connection
  Note right of Connector: referred to as Binder
```

### Health Check

```mermaid
sequenceDiagram
  Connector ->> AD : Create Connection
  loop HealthCheck
    Connector ->> AD : Bind Connection
    Connector ->> AD : Search
    Connector ->> Connector : Update Health
  end
```

## HTTP Server

- Source: [endpoints.js](endpoints.js)
- Handled by Password WindowsAuthentication implementation:
  - https://github.com/auth0/passport-windowsauth

### Login

- Endpoint: `/wsfed`

### List Users

- Endpoint: `/users`

## Proxied Interactions

- Source: [ws_validator.js](ws_validator.js)
- Ingress: Websocket

### Authenticate User

- Event: `authenticate_user`
```mermaid
sequenceDiagram
  Auth0 ->> Connector : Authenticate User
  note right of Auth0 : Username, Password
  Connector ->> AD : Search with Client
  AD ->> Connector : User
  alt if user found
  Connector ->> AD : Bind with Binder
  alt not successful
  Connector ->> Auth0 : Error
  else
  alt if groups enabled
  Connector ->> Connector : Check Cache
  alt if cache empty
  Connector ->> AD : Search with Client
  AD ->> Connector : Groups
  end
  end
  Connector ->> Auth0 : User
  end
  end
```

### Search Users

- Event: `search_users`

```mermaid
sequenceDiagram
  Auth0 ->> Connector : Search Users
  Connector ->> AD : Search with Client
  AD ->> Connector : Users
  alt if groups enabled
  Connector ->> Connector : Check Cache
  alt if cache empty
  Connector ->> AD : Search with Client
  AD ->> Connector : Groups
  end
  end
```

### Change Password

- Event: `change_password`

```mermaid
sequenceDiagram
  Auth0 ->> Connector : Change Password
  note right of Auth0 : Username, Password  
  Connector ->> AD : Search
  AD ->> Connector : Users
  alt if user found
  Connector ->> AD : Modify
  alt if groups enabled
  Connector ->> Connector : Check Cache
  alt if cache empty
  Connector ->> AD : Search with Client
  AD ->> Connector : Groups
  end
  end
  Connector ->> Connector : Create Profile
  Connector ->> Auth0 : User
  else
  Connector ->> Auth0 : Error
  end
```

### List Groups

- Event: `list_groups`

```mermaid
sequenceDiagram
  Auth0 ->> Connector : List Groups
  Connector ->> AD : Search with Client
  AD ->> Connector : Groups
  Connector ->> Auth0 : Groups
```
