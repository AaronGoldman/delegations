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

## Phase 4: Auth

### MVP scope: no CA system

For the MVP, both the server and client use self-signed certs. We do not integrate with any CA — no Let's Encrypt, no ACME, no intermediate CAs. Trust is established purely by pinning:

- **Server cert:** auto-generated on first daemon start if `~/.shs/server.full.pem` and `~/.shs/server.key.pem` are not found. Fingerprint is printed so clients can pin it. On first connect to an unknown host, the client shows the domain and fingerprint and prompts the user to confirm:
  ```
  The authenticity of host 'example.com/path' cannot be established.
  Fingerprint: shs-a3b1c2d4e5f6...
  Add to known hosts? [y/N]
  ```
  On confirmation, the fingerprint is appended to the `servers` section of `~/.shs/acl.yaml` under the domain key. On subsequent connects, if the fingerprint matches the stored value the connection proceeds silently. If the fingerprint has changed, the client shows the new fingerprint and prompts again — the user can add the new fingerprint (the old one remains and can be removed with `shs auth rm`).
- **Client cert:** auto-generated on first connect if `~/.shs/client.full.pem` and `~/.shs/client.key.pem` are not found. Bare ECC, no CN, no SAN. Fingerprint is printed as `shs-<hex>` so the server admin can add it to `acl.yaml`.

CA support (`shs auth sign`, CSRs, group ACLs via CA fingerprint) is designed for later but not required for Phase 4 to be functional.

### ACL file
- Default location: `~/.shs/acl.yaml` (resolved against the daemon user's `$HOME`)
- Load on startup; watch for changes and reload without restart
- Specified with `--acl` flag: `shs daemon --acl /path/to/acl.yaml`
- Two sections:
  - **`servers`** — client-side trust: domain → list of trusted server cert fingerprints
  - **`clients`** — server-side trust: local OS username or group → list of credential entries

### Server-side auth algorithm
On TLS handshake, require client to send the full cert chain. For each entry in `clients`:
1. If any cert in the chain matches the entry's `fingerprint` — proceed
2. If `require_patterns` is present — each pattern must match at least one SAN on that cert
3. If `username_pattern` is present — apply regex to SANs, extract `(?P<user>...)`, match against the key (or `--user` if passed)
4. If all checks pass, log in as the key (OS username or group member)

If multiple SANs match `username_pattern`, the client must pass `--user` to disambiguate; the server validates that value is present in the SANs.

### Process spawning
- Resolve user with `user.Lookup()`, get supplementary groups with `user.GroupIds()`
- Set `syscall.Credential` with UID, primary GID, and all supplementary GIDs
- Exec the user's shell (from `/etc/passwd`) or the requested command
- Note: MVP skips the PAM session stack (`pam_open_session`). Sufficient for most environments but will break on systems relying on PAM for session setup (SSSD, home-on-NFS, `pam_access`).

### `shs auth` commands
- `shs auth gen` — generate key + self-signed cert, ECC, no CN, no SAN; save to `~/.shs/client.full.pem` + `~/.shs/client.key.pem`; print `shs-<fingerprint>`
- `shs auth gen --san user@example.com --san urn:li:userPrincipal\(aagoldma\)` — `--san` is repeatable
- `shs auth gen --csr` — generate key + CSR instead
- `shs auth sign --in client.csr --out client.full.pem` — stub only; prints "not yet implemented" and exits non-zero
- `shs auth add client.full.pem` — parse chain, pin leaf fingerprint, append to `acl.yaml`
- `shs auth add shs-<hex>` — append raw fingerprint to `acl.yaml`
- `shs auth rm shs-<hex>` — remove fingerprint from `acl.yaml`
- `shs auth ls` — list policies that apply to the current OS user; two sections: direct policies and group-inherited policies (with the group name and how to remove)

### Milestone
Server rejects connections with no valid cert. `shs auth gen` + `shs auth add` + `shs daemon` is the full setup flow.

---

## Phase 5: Web UI

> Disabled by default. Enable with `shs daemon --webui`.

### Server
- Serve a single-page app at the SHS endpoint when hit by a browser (detected by `Accept: text/html`)
- Browser triggers mTLS client cert selection natively on page load; the WebSocket upgrade reuses the same TLS session — no second cert picker, no JS cert API needed
- WebSocket backend is the same as the CLI (same message protocol)
- The SPA is served from the same origin (same host, same port 443) as the WebSocket endpoint — this eliminates CORS entirely and is what makes the client cert inheritance work

#### Unauthenticated landing page
TLS client cert verification must be set to `tls.RequestClientCert` (optional), not `tls.RequireAnyClientCert`. Auth is enforced at the HTTP handler layer, not the TLS layer — this allows the server to respond with a useful page when no cert is presented rather than dropping the connection during the TLS handshake.

When a browser hits the endpoint with no valid client cert, serve an onboarding page that:
- Explains how to generate and install a client cert in the browser
- Provides a download link for the server's own cert (`~/.shs/server.full.pem`) so the user can inspect or pin it

This is the browser equivalent of CLI trust-on-first-use: the unauthenticated user can retrieve the server cert over HTTPS and decide whether to trust it before installing their client cert. If the server is running behind a domain with a CA-signed cert (e.g. Let's Encrypt), the browser already trusts the server cert natively and only the client cert onboarding instructions are relevant. The CLI is unaffected — it still pins the server cert leaf on first connect regardless.

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

* [ ] Alternative authentication methods: FIDO/WebAuthn, TOTP. How do these interact with the mTLS identity model? Can they be layered on top as a second factor, or used as a primary alternative for environments where managing client certs is impractical? Likely used only to add fingerprints to the acl.yaml
