# delegation-proxy-server

A self-contained Go demo of the [Delegated Access Token spec](../../spec/delegated-access-token.md).

Run it with no configuration — a `config.json` is created automatically on first run.

```
go run .
```

### Using the Makefile

The project includes a `Makefile` for managing the proxy server and VS Code server:

```
make help              # Show all available targets
make dev              # Start VS Code server and proxy server
make dev-server       # Start proxy server only (assumes VS Code is running)
make vscode           # Start VS Code server only
make clean            # Kill VS Code server and clean up socket
```

**VS Code Server Setup:**

The proxy requires a VS Code server running on a Unix socket. Start it with:

```
make vscode
```

This runs:
```
code serve-web --socket-path /tmp/vscode.sock --without-connection-token --server-base-path /code/
```

Then in another terminal, start the proxy with:

```
make dev-server
```

Or use `make dev` to start both (though they'll run in the same process; use separate terminals for better control).

---

## The Flow

### 1. Agent hits the API — rejected

The agent makes a request to a protected endpoint without a valid grant.
The server responds `401` with an RFC 7807 problem body containing a `delegation_url`.

```
GET /api/whoami
→ 401 application/problem+json
  { "delegation_url": "http://localhost:8080/delegate?token=…" }
```

The agent opens `delegation_url` in the user's browser (or presents it as a link).

---

### 2. Principal opens the delegation URL

The user (principal) opens the `delegation_url` in their browser.
The server verifies the signed token and renders a grant-approval page showing:
- the resource being requested (host + path + method)
- the scopes required
- who is approving (their principal ID, derived from a long-lived cookie)

The principal chooses a grant duration:

| Duration  | Effect                                         |
|-----------|------------------------------------------------|
| `once`    | Single use — revoked immediately after access  |
| `session` | Valid until the agent's session cookie expires |
| `agent`   | Persists across sessions until manually revoked |

---

### 3. Principal submits the form

Clicking **Approve** posts to `/grant` (CSRF protected).
The server stores the grant and shows a confirmation page.
The principal can close the browser tab and tell the agent to retry.

Clicking **Deny** discards the request.

---

### 4. Agent hits the API — approved

The agent retries the same request.
The server finds a matching active grant and calls the handler.

```
GET /api/whoami
→ 200 application/json
  { "agent_id": "…", "session_id": "…", "delegation_id": "…", "principal_id": "…", … }
```

---

## Endpoints

| Method | Path              | Description                              |
|--------|-------------------|------------------------------------------|
| GET    | `/api/whoami`     | Protected demo endpoint — returns identity |
| GET    | `/delegate`       | Grant approval UI (requires `?token=…`)  |
| POST   | `/grant`          | Processes the approval form              |
| GET    | `/sessions`       | Lists all active grants                  |
| POST   | `/revoke`         | Revokes a grant                          |

---

## Configuration

`config.json` is read at startup. If missing it is created with random secrets.

```json
{
  "listen_addr":   "127.0.0.1:8080",
  "jwt_secret":    "<256-bit hex>",
  "server_secret": "<UUIDv4 used as UUIDv5 namespace>"
}
```

| Key             | Description                                               |
|-----------------|-----------------------------------------------------------|
| `listen_addr`   | TCP address the server binds to                           |
| `jwt_secret`    | HMAC-SHA256 key used to sign delegation request tokens    |
| `server_secret` | UUIDv5 namespace for deriving stable IDs from cookie values |

Keep `jwt_secret` and `server_secret` private. Rotating `server_secret` invalidates all existing cookie-derived IDs.

---

## ⚠️ SECURITY WARNING

**This is a demonstration server. It is NOT suitable for production.**

### Critical Issues

1. **Permissive Scope Authorizer**: The `PermissiveScopeAuthorizer` allows ANY principal to grant themselves ANY scopes. Anyone can approve their own delegation requests.

2. **Remote Shell Access**: The `/code/*` endpoints proxy to a VS Code server, which provides full remote shell access to the machine.

3. **localhost Only**: This server is bound to `127.0.0.1:8080` by default. **Do NOT change this to `0.0.0.0` without replacing `PermissiveScopeAuthorizer` with a real identity/authorization system.**

### Before Production

- Replace `PermissiveScopeAuthorizer` with a real authorization system that validates:
  - Principal identity (LDAP, SAML, OAuth, etc.)
  - Scope eligibility (per-user permissions, org policy, etc.)
- Bind to a secure network interface or require TLS + mutual authentication
- Remove or secure the VS Code proxy endpoint
- Audit and test scope enforcement thoroughly
- Use proper secrets management (don't hardcode in `config.json`)

---

## Identity Model

Cookies are never stored directly. Each cookie value is hashed with the `server_secret` via UUIDv5 to produce a stable opaque ID:

| Cookie           | Derived ID     | Lifetime              |
|------------------|----------------|-----------------------|
| `agent_cookie`   | `agent_id`     | 1 year (persistent)   |
| `session_cookie` | `session_id`   | Browser session       |
| `principal_cookie` | `principal_id` | 1 year (persistent) |

`agent` grants match on `agent_id` alone — they survive session restarts.
`session` and `once` grants require both `agent_id` and `session_id`.


## Authors

- Aaron Goldman - [@aarongoldman](https://github.com/aarongoldman)

## Links

- [Specification](spec/delegated-access-token.md)
- [RFC7807 - Problem Details for HTTP APIs](https://datatracker.ietf.org/doc/html/rfc7807)

---

**Status:** Draft - Specification complete, reference implementations in progress