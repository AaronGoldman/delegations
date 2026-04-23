# SHS Implementation Plan

Language: Go

## Engineering Principles

- **Standard library first.** Use the Go standard library wherever it covers the need. Prefer a few extra lines of stdlib code over pulling in a third-party package.
- **Minimize dependencies.** Every third-party dependency is a supply chain risk, a build complexity, and a future maintenance burden. Justify each one explicitly.
- **Dependency justification file.** All non-standard-library dependencies are listed in `deps.md` at the repo root. Each entry has: the import path, the specific use(s) in this project, and a paragraph explaining why the standard library is insufficient. If a dependency already has an entry and you add a new use for it, append the new use to the existing entry rather than creating a duplicate.

## Phase 1: Remote Shell

The foundation everything else builds on. Establish the WebSocket connection, PTY, and message framing.

### Server
- On startup, check `os.Getuid() == 0`. If running as root and `--dangerously-run-as-root` was not passed, print an error and exit. Use `setcap cap_net_bind_service+ep` on the binary instead to allow binding port 443 as a non-root user.
- HTTP server with TLS on port 443
- WebSocket upgrade handler at a configurable path
- Allocate a PTY and spawn the user's shell
- Bidirectional copy: PTY output → WebSocket, WebSocket → PTY stdin
- Handle terminal resize messages (SIGWINCH)
- Graceful shutdown on shell exit

### Client
- `shs example.com/path` connects via WSS — the argument is always a bare domain+path, never a URL scheme
- Put local terminal in raw mode
- Bidirectional copy: stdin → WebSocket, WebSocket → stdout
- Send resize messages when local terminal size changes
- Restore terminal on exit

### Non-interactive exec
- `shs $host 'cmd'` follows SSH convention: no PTY, stdin/stdout/stderr piped through, remote exit code returned locally
- Shell pipelines work: `shs $host 'true && false'` — the shell on the remote side interprets the pipeline

### Application-level multiplexing
The WebSocket connection carries multiple logical streams (shell data, file chunks, port-forward data) simultaneously. Each WebSocket message contains an application-level header:

```
| 1 byte type | 4 byte stream ID | N bytes payload |
```

Types: `SHELL_DATA`, `SHELL_RESIZE`, `FILE_CHUNK`, `PORT_DATA`, `CONTROL`, `ERROR`

WebSocket handles transport framing and delivery. This header lives inside the WebSocket message payload and is how the application distinguishes shell output from a concurrent file transfer or port-forward on the same connection.

`ERROR` messages carry a stream ID (identifying which operation failed), an error code, and a human-readable string. Any operation — file transfer, port bind, shell spawn — may send an `ERROR` on its stream ID to signal failure; the receiver tears down that stream.

### Connection lifecycle
- Each WebSocket connection is independent; the daemon handles multiple simultaneous connections (multiple users and multiple concurrent connections from the same user) each in their own goroutine set.
- When the shell process exits, the server sends a `CONTROL` message with the exit code and then closes the WebSocket. All in-flight file transfers and port-forward tunnels on that connection are torn down — the shell is the lifecycle anchor for the connection.
- Port-forward listeners bound for a connection are released when the connection closes.

### Host addressing
The host argument is a bare domain+path, always over WSS. No scheme prefix required — SHS is always WSS.

```
shs example.com                          # connects to wss://example.com/
shs example.com/path/to/endpoint         # connects to wss://example.com/path/to/endpoint
shs example.com/path/to/endpoint whoami  # non-interactive exec
```

The path component lets multiple SHS endpoints coexist behind the same reverse proxy on the same domain. The daemon's `--path` flag sets the path it listens on (default `/`).

### Milestone
`shs $host` drops you in a shell. `shs $host 'cmd'` runs a command and returns output.

---

## Phase 2: File Transfer and Sync

Build on the multiplexed connection from Phase 1.

### `shs $host get $local $remote`
- Client sends a `FILE_GET` control message with the remote path
- Server walks the path, streams file chunks over the connection
- Client reassembles and writes to local path
- `.` for local = `$PWD`; `.` for remote = logged-in user's `~`
- Support directories (recursive)
- `--mirror`: after copying, delete any local files not present in the remote source — makes local an exact replica of remote

### `shs $host put $local $remote`
- Client reads local path, streams chunks to server
- Server writes to remote path
- `.` for local = `$PWD`; `.` for remote = logged-in user's `~`
- Support directories (recursive)
- `--mirror`: after copying, delete any remote files not present in the local source — makes remote an exact replica of local

### `shs $host sync $local $remote`
Client and server each build a manifest (file path + SHA256 + mtime) and exchange them. Sync behaviour depends on flags:

**Default (no flags) — mtime wins:**
- File exists on one side only → copy it to the other side
- File exists on both sides, hashes equal → skip (already in sync)
- File exists on both sides, hashes differ, mtimes differ → newer mtime wins
- File exists on both sides, hashes differ, mtimes equal → conflict; print to stderr and skip that file; continue syncing all other files; exit non-zero at the end if any conflicts were skipped

**`--safe` — additive only, never overwrite:**
- File exists on one side only → copy it to the other side
- File exists on both sides (any content, any mtime) → skip with a message to stderr; do not overwrite either side

**`--safe-local` — protect local copies:**
- File exists on one side only → copy it to the other side
- File exists on both sides → local copy is authoritative; do not overwrite local; remote may be overwritten if local is newer

**`--safe-remote` — protect remote copies:**
- File exists on one side only → copy it to the other side
- File exists on both sides → remote copy is authoritative; do not overwrite remote; local may be overwritten if remote is newer

Sync never deletes files. Use `put --mirror` or `get --mirror` when you need one side to exactly match the other.

### Milestone
All three file commands work for files and directories.

---

## Phase 3: Port Forwarding

### `shs $host port $local $remote`
- Parse `local` and `remote` as `address:port`; bare port defaults to `localhost:port`
- Determine direction: if `local` has a `remote:` prefix, listener is on the server side
- **Local forward:** client binds the local port, accepts connections, tunnels each as a new stream over the WebSocket
- **Remote forward:** client sends a `PORT_BIND` control message; server binds the remote port, tunnels connections back

### Multiplexing
Each forwarded connection gets a unique stream ID. `PORT_DATA` messages carry the stream ID so multiple tunnels coexist on one WebSocket.

### Milestone
`shs $host port 5432 5432` reaches a remote database. `shs $host port remote:8080 8080` exposes a local dev server.

---

## Phase 4: Auth (Delegation-based)

Client authentication is delegated to an external middleware (proxy). The SHS daemon trusts a signed JWT from the proxy, rather than validating client certificates directly.

### Architecture

```
┌─────────┐    cookies      ┌──────────────┐      JWT      ┌──────────┐
│ shs     │←───────────────→│ Delegation   │←─────────────→│ shs      │
│ client  │  + delegation   │ Proxy        │  + principal  │ daemon   │
│ (CLI)   │  URLs on first  │ (middleware) │  mapping      │ (server) │
└─────────┘     access      └──────────────┘               └──────────┘
```

### Server-side setup
- **Server cert:** auto-generated on first daemon start if `~/.shs/server.full.pem` and `~/.shs/server.key.pem` are not found. Fingerprint is printed so clients can pin it. Used only for HTTPS transport layer, not for authentication.
- **ACL configuration:** Add the delegation proxy's public key to `~/.shs/acl.yaml`. The daemon uses this key to verify JWT signatures from the proxy.
- **Principal mapping:** Define which principals (user + group URNs) map to which local OS users in the `clients` section of the ACL.

### JWT validation (SHS daemon)
When a request arrives with a JWT in the `Authorization: Bearer` header:

1. **Verify signature** — using the middleware's public key from ACL
2. **Check expiry** — JWT must not be expired
3. **Validate request context** — JWT's hostPattern, pathPattern, methods must match the incoming request
4. **Extract principals** — get user + group principals from JWT
5. **Map to OS user** — check ACL `clients` section to find a matching principal entry
6. **Process spawning** — resolve user with `user.Lookup()`, get supplementary groups with `user.GroupIds()`, set `syscall.Credential` with UID, primary GID, and all supplementary GIDs, exec the user's shell or command
7. **Note:** MVP skips the PAM session stack (`pam_open_session`). Sufficient for most environments but will break on systems relying on PAM for session setup (SSSD, home-on-NFS, `pam_access`).

### Client-side cookie jar
- Default location: `~/.shs/cookies.jar` (resolved against the user's `$HOME`)
- Persist cookies (agent_cookie, session_cookie) across invocations
- On first access to a new domain/path: server returns 401 + cookies + delegation_url; client displays URL to user
- User visits delegation URL in browser, approves the delegation
- Client reuses cached cookies on retry
- Middleware validates cookies and mints short-lived JWT for each request

### Server-side ACL file
- Default location: `~/.shs/acl.yaml` (resolved against the daemon user's `$HOME`)
- Load on startup; watch for changes and reload without restart
- Specified with `--acl` flag: `shs daemon --acl /path/to/acl.yaml`
- Three elements:
  - **`middleware_public_key`** — public key (RSA, ECDSA, or EdDSA) used to verify JWT signatures from the proxy
  - **`servers`** — client-side trust: domain → list of trusted server cert fingerprints (for client to verify daemon's HTTPS cert via trust-on-first-use)
  - **`clients`** — server-side access rules: local OS username or group → list of principal entries

### Principal matching
For each entry in `clients`:
1. Extract user and group principals from the JWT
2. Check if ANY principal in the JWT matches ANY principal in the entry's `principals` list
3. If a match is found, log in as the key (OS username or group member)
4. Use the first matching entry; subsequent entries are not checked

Example:
```yaml
clients:
  aaron:
    - principals:
        - "urn:contoso:corpuser:aagoldma"
  
  eng-team:
    - principals:
        - "urn:contoso:groupPrincipal(ALL-ENGINEERS)"
        - "urn:contoso:groupPrincipal(SGP-CREW-260-MEMBERS)"
```

If the JWT contains `urn:contoso:corpuser:aagoldma`, it matches the `aaron` entry and logs in as `aaron`. If the JWT contains `urn:contoso:groupPrincipal(ALL-ENGINEERS)` but not the user principal, it matches the `eng-team` entry and logs in as `eng-team`.

### `shs auth` commands
- `shs auth rm urn:contoso:corpuser:aagoldma` — remove a user principal from the ACL
- `shs auth rm urn:contoso:groupPrincipal\(GROUP-NAME\)` — remove a group principal from the ACL
- `shs auth ls` — list principals authorized for the current OS user

Principals are added by manually editing `~/.shs/acl.yaml`, not via CLI.

### Milestone
Daemon validates JWTs from the proxy and maps principals to OS users. Client maintains a cookie jar and reuses cached cookies. First-time users are prompted with a delegation URL to approve access.

---

## Phase 5: Web UI

> Disabled by default. Enable with `shs daemon --webui`.

### Server
- Serve a single-page app at the SHS endpoint when hit by a browser (detected by `Accept: text/html`)
- Browser goes through the same delegation proxy flow as the CLI: first request returns 401 + cookies + delegation_url; user approves in browser; subsequent requests use cached cookies
- Proxy validates cookies and mints a JWT, which is forwarded to the daemon
- WebSocket backend is the same as the CLI (same message protocol)
- The SPA is served from the same origin (same host, same port 443) as the WebSocket endpoint
- The SPA connects directly to the daemon's WebSocket: `const socket = new WebSocket('wss://example.com/shs');` — the proxy handles authentication on WebSocket upgrade by validating the JWT from the initial HTTP request

#### Authorization flow
When a browser hits the endpoint without a valid delegation:
1. Browser makes request to delegation proxy (middleware)
2. Proxy responds with 401 + cookies + delegation_url
3. SHS Web UI detects 401 and displays delegation_url to the user (as a clickable link or QR code)
4. User clicks the link (or scans QR), opens it in a browser tab
5. Delegation proxy shows the authorization approval page
6. User approves and grants access
7. User returns to original tab and retries
8. Browser now has cached cookies; proxy validates them and allows the connection

This uses the same Principal-Agent Delegation flow defined in delegated-access-token.md.

### Content Security Policy
The daemon generates a random nonce per request and injects it into the `index.html` template and the `Content-Security-Policy` header:

```
Content-Security-Policy:
  default-src 'self';
  script-src 'nonce-<random>';
  style-src 'nonce-<random>';
  connect-src 'self';
  img-src 'self' data:;
  font-src 'self' data:;
  frame-ancestors 'none';
  form-action 'none';
  base-uri 'self'
```

Notes:
- `connect-src 'self'` covers `wss://` to the same origin — no need to list `wss:` explicitly
- The nonce is a cryptographically random value (e.g. 128-bit, base64-encoded), regenerated per request; it is stamped onto `<script>` and `<style>` tags in the HTML template at serve time
- No `'unsafe-inline'` or `'unsafe-eval'` — the nonce replaces both
- `frame-ancestors 'none'` prevents clickjacking
- `index.html` is a Go `html/template`, not a static file, so the nonce can be injected server-side

### Goals
- Terminal tab: xterm.js PTY session with buttons (or keyboard shortcuts) to send `^C` and `^D` — these are easy to fat-finger on mobile or miss on non-US keyboards
- Local file explorer: browse the local filesystem via the browser File System Access API
- Remote file explorer: browse the remote filesystem by running `ls` over the shell stream — no new protocol needed
- Explorer UI drives get/put/sync using the existing file transfer protocol unchanged; the web UI is a graphical front-end to the same wire messages the CLI uses

### Non-goals
- No changes to the WebSocket protocol for the web UI. If the UI needs to list files it runs `ls`; if it needs to transfer files it uses get/put. The protocol does not grow new message types to serve the browser.
- Port forwarding UI is **deferred**. Opening a port forward from a browser has non-trivial security implications (what does "bind on localhost" mean in a browser context, cross-origin exposure, etc.) that need more design work before they belong in an MVP.

### Frontend
- Single HTML file (`index.html` template) + one bundled JS file (`bundle.js`), both embedded in the binary
- WebSocket URL constructed from the page origin: `new WebSocket(location.href.replace(/^https/, 'wss'))`
- Shell tab: xterm.js connected to the WebSocket shell stream
- Local file explorer: browser File System Access API
- Remote file explorer: runs `ls` over the shell stream; get/put/sync drive file transfers

### Build
- Use esbuild to bundle the frontend into a single `bundle.js`
- Embed `web/dist/index.html` and `web/dist/bundle.js` into the Go binary with `//go:embed`
- No separate static file server needed

### Milestone
Hitting the server in a browser gives a working shell and file browser.

---

## Project Structure

```
shs/
├── shs.md               # design doc
├── plan.md              # this file
├── deps.md              # third-party dependency justifications
├── cmd/
│   └── shs/
│       └── main.go      # CLI entrypoint, subcommand dispatch
├── internal/
│   ├── proto/           # wire message types and framing
│   ├── server/          # daemon, TLS, WebSocket handler
│   ├── shell/           # PTY management
│   ├── filetransfer/    # get, put, sync
│   ├── tunnel/          # port forwarding
│   └── auth/            # ACL, cert validation, shs auth commands
└── web/                 # frontend source (Phase 5)
```

## TODO

* [ ] Cookie jar implementation: Implement secure cookie jar compatible with `net/http.Cookie`, respecting secure flags, max-age, expiry
* [ ] JWT validation: Implement JWT signature verification (RSA, ECDSA, EdDSA) using the middleware's public key from ACL
* [ ] Principal matching: Implement ACL matching logic for principals (user + group principals with OR logic)
* [ ] Delegation middleware reference implementation: Build example middleware that handles cookie validation, JWT generation, principal extraction from external identity systems
* [ ] Alternative identity providers: Integrate with OIDC, SAML, LDAP for principal extraction (handled by middleware, not SHS daemon)
* [ ] PAM integration: Add support for `pam_open_session` to handle home directory mounting, account restrictions, and site-local policy
