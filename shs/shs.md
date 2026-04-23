# SHS

SHS is an SSH-inspired remote shell over HTTPS.

## Name

We have a history of putting an "s" before protocols over SSH, e.g. sftp.
We have a history of putting an "s" after protocols over TLS, e.g. https, ftps.
If SSH is a shell over an SSH channel, then SHS is a shell over a TLS channel.

## Why HTTPS?

The world is more set up to secure and route HTTPS than any other protocol. Proxies and reverse proxies are built to route HTTPS.

If you have a web server that you wish to administer, you almost certainly already have HTTPS being routed to that server. The server is very likely to have a domain name already for service discovery. If some kind of server pinning is happening, you are able to shell into the same server the web traffic is going to.

## Wire Protocol

The connection is a message-framed stream over WSS (WebSockets over TLS). Each message has a type (shell data, file chunk, port-forward data) and a stream ID, providing multiplexing without depending on HTTP/2 stream semantics.

This maximizes reverse proxy compatibility: WSS works over HTTP/1.1, survives proxy downgrades, and has first-class support in every major proxy (nginx, Caddy, Traefik, HAProxy, Cloudflare, AWS ALB). The only nginx caveat is three extra config lines to pass the `Upgrade` header, which is well-documented.

HTTP/3 is not required. Since HTTP/3 falls back to HTTP/2 which falls back to HTTP/1.1, and many environments block UDP, there is no value in depending on it.

## Goals

* Remote shell access. A CLI that can remote into the server: `shs https://example.com/path/to/service`
  * Drop the user into the shell for that user.
  * Remote user determined by the credential passed, not the URL.
* Bidirectional file transfer
  * Put files on the remote filesystem from the local filesystem.
  * Pull files from the remote filesystem to the local filesystem.
  * Sync: hash the directories and make one side mirror the other.
    * rsync-inspired.
    * Minimize bandwidth when the directories are mostly in sync.
* Port forwarding between the local localhost and the remote localhost.
* Identity
  * The user logs in as a user on the server.
  * The server maps the principal (user + groups from JWT) to a local OS user via ACL.
* UI
  * CLI installed in the path; uses delegated cookies.
  * Browser: uses delegated cookies; can be integrated with OIDC/FIDO via proxy.
  * Non-goal: browser/CLI username and password.
* Single open connection
  * File transfers, shell interactions, and port forwarding are broken into relatively small messages and sent over the connection so they don't block each other.

## Architecture

SHS uses a three-tier delegation model with cookies (client ↔ middleware) and JWTs (middleware ↔ daemon):

```
┌──────────────────────────────────────────────────────────────────┐
│                                                                  │
│  User's Machine             Delegation Proxy            Server   │
│                                                                  │
│  ┌──────────┐              ┌──────────────┐        ┌──────────┐ │
│  │   shs    │              │ Delegation   │        │ shs      │ │
│  │  client  │              │   Proxy      │        │ daemon   │ │
│  │ (binary) │              │ (middleware) │        │          │ │
│  └────┬─────┘              └──────┬───────┘        └────┬─────┘ │
│       │                           │                     │       │
│       │ Request + cookies         │                     │       │
│       ├──────────────────────────>│                     │       │
│       │  (cached from            │                     │       │
│       │   cookie jar)            │                     │       │
│       │                           │                     │       │
│       │              ┌────────────────────┐            │       │
│       │              │ Validate cookies   │            │       │
│       │              │ Map to principal   │            │       │
│       │              │ Generate JWT with: │            │       │
│       │              │  - user principal  │            │       │
│       │              │  - group principals│            │       │
│       │              │  - scopes          │            │       │
│       │              │  - host/path/methods           │       │
│       │              │  - short TTL       │            │       │
│       │              └────────────────────┘            │       │
│       │                           │                     │       │
│       │                    Request + JWT               │       │
│       │                    in Authorization header     │       │
│       │                           ├────────────────────>       │
│       │                           │                     │       │
│       │                           │         ┌──────────────────┐
│       │                           │         │ Verify JWT:      │
│       │                           │         │ - Signature      │
│       │                           │         │ - Expiry         │
│       │                           │         │ - Host/path match│
│       │                           │         │ - Map principals │
│       │                           │         │   to OS user     │
│       │                           │         │ Execute request  │
│       │                           │         └──────────────────┘
│       │                           │                     │       │
│       │                      Response                   │       │
│       │                           │<─────────────────────       │
│       │<──────────────────────────┤                     │       │
│       │                           │                     │       │
│       │        [cache cookies if present]               │       │
│       │         (agent_cookie, session_cookie)          │       │
│       │                                                 │       │
└──────────────────────────────────────────────────────────────────┘
```

**Key separation:**
- **Client ↔ Middleware:** Cookies (persistent, stored in `~/.shs/cookies.jar`)
- **Middleware ↔ Daemon:** JWTs (short-lived, generated per-request, signed with middleware's private key, validated with middleware's public key in ACL)

## Identity and ACL

The SHS daemon receives a signed JWT from the delegation proxy containing:

- **User principal:** `urn:contoso:corpuser:aagoldma` — identifies the individual
- **Group principals:** `urn:contoso:groupPrincipal(ALL-ENGINEERS)`, `urn:contoso:groupPrincipal(SGP-CREW-260-MEMBERS)`, etc. — group memberships
- **Request context:** `hostPattern`, `pathPattern`, `methods`, `expiresAt` — what the delegation permits

The ACL maps these principals to local OS users. The daemon validates the JWT signature before trusting any claims.

### `servers` — client-side trust

The client uses this to decide whether to trust the server it is connecting to. The domain must appear in the server cert's SAN. On first connect the client prompts trust-on-first-use (like SSH) and records the fingerprint here.

```yaml
servers:
  example.com:
    - sha256-a3b1c2d4e5f6...
```

### `clients` — server-side access rules

The key is a local OS username or group. Each entry maps principal patterns to the OS user they can log in as:

1. **`middleware_public_key`** — public key of the delegation proxy (required once per proxy; safe to bake into Docker images)
2. **`principals`** — list of principal URNs that match this OS user. User and group principals are combined with OR logic.

```yaml
middleware_public_key: ed25519-MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
clients:
  # Single user — match by user principal
  aaron:
    - principals:
        - "urn:contoso:corpuser:aagoldma"

  # Group-based access — anyone in ALL-ENGINEERS gets this OS user
  eng-team:
    - principals:
        - "urn:contoso:groupPrincipal(ALL-ENGINEERS)"

  # Multiple matching rules for same user
  #  (e.g., different proxies or organizational structures)
  bob:
    - principals:
        - "urn:contoso:corpuser:robert"
    - principals:
        - "urn:contoso:groupPrincipal(PLATFORM-ONCALL)"
        - "urn:contoso:groupPrincipal(INFRA-TEAM)"

  # On-call users: match users in a specific group
  # (group provides membership management; SHS just maps group → OS user)
  oncall-user:
    - principals:
        - "urn:contoso:groupPrincipal(FEED-PLATFORM-ONCALL)"
```

**How matching works:**
1. JWT arrives with principals: `["urn:contoso:corpuser:aagoldma", "urn:contoso:groupPrincipal(ALL-ENGINEERS)", "urn:contoso:groupPrincipal(SGP-CREW-260-MEMBERS)"]`
2. Daemon checks each OS user entry in `clients`
3. If ANY of the JWT principals match ANY principal in an entry, that OS user is authorized
4. The first matching entry is used; login proceeds as that OS user

This model keeps SHS simple: group membership is managed externally by the delegation proxy (which checks LDAP, group systems, etc.); SHS just maps whatever principals it receives to local OS users.

## CLI

### Client commands

The host argument is a bare `domain/path` — no scheme prefix. SHS is always WSS. The path lets multiple SHS endpoints coexist on the same domain behind a reverse proxy.

```sh
shs example.com                                          # remote shell
shs example.com/path/to/endpoint                        # remote shell via specific path
shs example.com/path/to/endpoint whoami                 # run a single command, no interactive shell
shs example.com get $local_destination $remote_source        # copy remote → local
shs example.com get . path/to/remote/file.ext                # local . = $PWD; drops file.ext into current directory
shs example.com get --mirror $local_destination $remote_source # make local an exact replica of remote (may delete local files)
shs example.com put $local_source $remote_destination        # copy local → remote
shs example.com put ./file.txt .                             # remote . = logged-in user's ~; no remote shell session exists to have a CWD
shs example.com put --mirror $local_source $remote_destination # make remote an exact replica of local (may delete remote files)
shs example.com sync $local_directory $remote_directory             # sync: newer mtime wins; mtime tie with differing content → skip + stderr
shs example.com sync --safe $local_directory $remote_directory       # copy missing files both ways; skip (stderr) anything that exists on both sides
shs example.com sync --safe-local $local_directory $remote_directory  # never overwrite local when file exists on both sides
shs example.com sync --safe-remote $local_directory $remote_directory # never overwrite remote when file exists on both sides
# if no ":" in local or remote, defaults to localhost:$port
shs example.com port $local_address:$local_port $remote_address:$remote_port
```

### Auth commands

Authentication is delegated to the proxy; SHS only manages local ACL configuration:

```sh
shs auth rm  urn:contoso:corpuser:aagoldma          # remove user from ACL
shs auth rm  urn:contoso:groupPrincipal\(ENG-ALL\)  # remove group from ACL
shs auth ls                                     # list principals authorized for the current OS user
```

Principals are added manually by editing `~/.shs/acl.yaml` (see [Identity and ACL](#identity-and-acl) section).

### Daemon

```sh
shs daemon                             # start with default ACL (~/.shs/acl.yaml), listen on port 443
shs daemon --acl acl.yaml              # specify ACL file
shs daemon --port 8443                 # listen on a specific port (default: 443)
shs daemon --webui                     # also enable the web UI
shs daemon --dangerously-run-as-root   # allow running as root (not recommended)
```

The daemon listens on port 443 by default (HTTPS). Use `--port` to bind to a different port. To bind port 443 as an unprivileged user, use `setcap cap_net_bind_service+ep /usr/local/bin/shs`.

#### JWT Validation

The daemon expects requests to arrive with a signed JWT in the `Authorization: Bearer <jwt>` header (set by the delegation proxy). It validates:

1. **Signature** — verify using the `middleware_public_key` from the ACL
2. **HostPattern** — request host must match the JWT's `hostPattern`
3. **PathPattern** — request path must match the JWT's `pathPattern`
4. **Methods** — request HTTP method must be in the JWT's `methods` array
5. **ExpiresAt** — JWT must not be expired

If all checks pass, the daemon extracts the principals (`user` and `groups`) from the JWT and maps them to a local OS user via the `clients` section of the ACL. The request proceeds as that user.

`shs auth ls` shows only principals that allow login to the current OS user. These principals are defined in the ACL and may come from direct user assignment or group membership managed by the delegation proxy.

```
Principals authorized for current OS user (aaron):
  urn:contoso:corpuser:aagoldma
  urn:contoso:groupPrincipal(ALL-ENGINEERS)
  urn:contoso:groupPrincipal(SGP-CREW-260-MEMBERS)
```

The daemon refuses to start if running as root unless `--dangerously-run-as-root` is passed. Use `setcap cap_net_bind_service+ep /usr/local/bin/shs` to allow binding port 443 as an unprivileged user.

## Defaults

Good defaults matter because people don't configure things.

* **Port 443 for HTTPS** — standard secure port for web traffic.
* **Server cert auto-generation:** if no `server.key.pem` and `server.full.pem` are found when the daemon starts, they are generated automatically. The fingerprint is printed so clients can pin it.
* **Delegation via proxy:** client authentication is delegated to a proxy (middleware); SHS does not generate client certs.
* Default file locations, resolved against `$HOME` of the running user:

| File | Default path | Secret? |
|---|---|---|
| ACL | `~/.shs/acl.yaml` | No — safe to bake into Docker images |
| Server cert | `~/.shs/server.full.pem` | No — public |
| Server private key | `~/.shs/server.key.pem` | Yes — mount at runtime |

## Client Flow

### First Access (No Cookie)

```
$ shs example.com
# 1) Client makes request to middleware
# 2) Middleware has no cookie for this domain/path → 401
# 3) Middleware sets agent_cookie + session_cookie
# 4) Middleware returns delegation_url with token parameter

Authorization required.
Please visit: https://example.com/delegate?token=eyJhbGci...
# (OR shows QR code, pushes link to agent's notification system, etc.)

$ shs example.com
# Now user has visited delegation URL and approved
# Client sends request with cached cookies
# 5) Middleware validates cookies
# 6) Middleware generates short-lived JWT with user+group principals
# 7) Middleware proxies to shs daemon with JWT in Authorization header
# 8) Daemon validates JWT signature, host/path/methods, expiry
# 9) Daemon maps principals to OS user
# 10) Shell drops

$
```

### Subsequent Requests

Client reuses cached cookies from the cookie jar. Middleware validates them and mints a fresh short-lived JWT for each request.

### Cookie Jar

The shs binary maintains a cookie jar (like curl, wget, browsers) to cache cookies across invocations:

| File | Default path | Secret? |
|---|---|---|
| Cookie jar | `~/.shs/cookies.jar` | Yes — contains session tokens |

### Web UI

> Disabled by default. Enable with `shs daemon --webui`.

The browser connects through the middleware using the same cookie-based delegation flow. After the user approves the delegation, they access a VS Code-like environment with:

* A shell
* A local file tree
* A remote file tree
* A tab for port forwards
* An editor

## TODO

* [ ] Cookie jar implementation: Implement cookie persistence compatible with net/http.Cookie or similar (max-age, secure flag, etc.)
* [ ] JWT validation: Implement JWT signature verification using the middleware's public key from ACL
* [ ] Principal matching: Implement principal-based ACL matching (user + group ORing logic)
* [ ] Delegation proxy reference implementation: Build the middleware that handles cookie validation, JWT generation, principal extraction from external identity system
* [ ] PAM integration. SSH runs the PAM session stack (`pam_open_session`) on login, which handles home directory mounting, `lastlog` updates, account restrictions, and other site-local policy. SHS MVP skips PAM — it resolves the user via `os/user`, sets UID, primary GID, and all supplementary groups, then execs the shell. This is sufficient for most environments but will break on systems that rely on PAM for session setup (e.g. SSSD, home-on-NFS, access restrictions via `pam_access`). PAM support needs to be added before SHS is suitable for those environments.

