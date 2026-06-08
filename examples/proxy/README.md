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
| GET    | `/delegations/ask?token=…` | Human-facing grant approval UI |
| POST   | `/delegations/grant` | Processes the approval form              |
| GET    | `/delegations/self-service` | Self-service delegation registration and grant |
| POST   | `/delegations/self-service` | Process self-service key registration |
| GET    | `/delegations`    | Lists all active grants                  |
| POST   | `/delegations/revoke` | Revokes a grant                          |

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

## OAuth Self-Service (GitHub & Google)

### Overview

Enable self-service identity verification by adding OAuth login via GitHub or Google. This allows principals to authenticate themselves without requiring a pre-configured cookie, replacing the permissive scope authorizer with a real identity system.

### Setup

Add OAuth credentials to `config.json`:

```json
{
  "listen_addr":   "127.0.0.1:8080",
  "jwt_secret":    "<256-bit hex>",
  "server_secret": "<UUIDv4 used as UUIDv5 namespace>",
  "oauth": {
    "github": {
      "client_id":     "YOUR_GITHUB_CLIENT_ID",
      "client_secret": "YOUR_GITHUB_CLIENT_SECRET",
      "redirect_uri":  "http://127.0.0.1:8080/auth/github/callback"
    },
    "google": {
      "client_id":     "YOUR_GOOGLE_CLIENT_ID",
      "client_secret": "YOUR_GOOGLE_CLIENT_SECRET",
      "redirect_uri":  "http://127.0.0.1:8080/auth/google/callback"
    }
  }
}
```

### GitHub OAuth Setup

1. Go to [GitHub Settings → Developer settings → OAuth Apps](https://github.com/settings/developers)
2. Click **New OAuth App**
3. Fill in:
   - **Application name**: `Delegation Proxy Server`
   - **Homepage URL**: `http://127.0.0.1:8080`
   - **Authorization callback URL**: `http://127.0.0.1:8080/auth/github/callback`
4. Copy the **Client ID** and **Client Secret** into `config.json`

### Google OAuth Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable the **Google+ API**
4. Go to **Credentials** → **Create Credentials** → **OAuth 2.0 Client IDs**
5. Choose **Web application**
6. Add authorized redirect URI: `http://127.0.0.1:8080/auth/google/callback`
7. Copy the **Client ID** and **Client Secret** into `config.json`

### New Endpoints

| Method | Path                              | Description                          |
|--------|-----------------------------------|--------------------------------------|
| GET    | `/auth/github`                    | Initiates GitHub OAuth flow          |
| GET    | `/auth/github/callback`           | GitHub OAuth callback handler        |
| GET    | `/auth/google`                    | Initiates Google OAuth flow          |
| GET    | `/auth/google/callback`           | Google OAuth callback handler        |
| GET    | `/login`                          | Self-service login page              |
| POST   | `/logout`                         | Clears principal session             |

### Usage Flow

1. Principal visits `/login` and sees login options (GitHub / Google)
2. Clicking an option redirects to that provider's login page
3. After authorization, the provider redirects back to `/auth/{provider}/callback`
4. Server verifies the OAuth token and sets the `principal_cookie`
5. Principal is redirected to `/delegate?token=…` (if there was a pending delegation request)
6. Delegation flow proceeds normally

### Identity Extraction

- **GitHub**: Uses `login` (username) as the stable principal identifier
- **Google**: Uses `sub` (subject claim) or email as the principal identifier

These are hashed with `server_secret` via UUIDv5 to produce a stable `principal_id`, consistent with the existing cookie-based model.

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
## Troubleshooting

### Path Pattern Matching Issue

If you're experiencing issues with the `/code` endpoint not loading correctly, make sure that any delegation grants for this endpoint use the wildcard pattern `/code/*` instead of just `/code`. This is because the `/code/` endpoint expects to match all sub-paths under `/code/`.

Example:
- ✅ Correct: Grant path pattern = `/code/*`
- ❌ Incorrect: Grant path pattern = `/code`

This ensures that requests like `/code/anything` will properly match against the delegation grant.

**Status:** Draft - Specification complete, reference implementations in progress


#### example otp secret uri:
`otpauth://totp/ACME%20Co:jdoe@example.com?secret=AUSJD7LZ5H27TAC7NW2IJMATDMVDUPUG&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30`

* ACME Co: jdoe@example.com
  * secret=AUSJD7LZ5H27TAC7NW2IJMATDMVDUPUG
  * issuer=ACME%20Co
  * algorithm=SHA1
  * digits=6
  * period=30

`urn:posix:group:<group_name>`