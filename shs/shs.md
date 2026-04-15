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
  * The client-side credential must be on that user's ACL.
* UI
  * CLI installed in the path.
  * Browser: user installs a mTLS cert.
  * Browser: FIDO.
  * Non-goal: browser/CLI username and password.
* Single open connection
  * File transfers, shell interactions, and port forwarding are broken into relatively small messages and sent over the connection so they don't block each other.

## Identity and ACL

The ACL is a YAML file with three sections. Send the full cert chain on TLS connect — matching is done on fingerprints alone, no CA chain validation required.

### `servers` — client-side trust

The client uses this to decide whether to trust the server it is connecting to. The domain must appear in the server cert's SAN. On first connect the client prompts trust-on-first-use (like SSH) and records the fingerprint here.

```yaml
servers:
  example.com:
    - sha256-a3b1c2d4e5f6...
```

### `clients` — server-side trust

The key is a local OS username or group. Each credential entry is evaluated as:

1. **`fingerprint`** — must match any cert in the presented chain.
2. **`require_patterns`** — each pattern must match at least one SAN on the cert. Omit if no SAN check is needed.
3. **`username_pattern`** — regex with named capture group `(?P<user>...)` applied to the SANs. If present, the extracted username must match the key (or `--user` if passed). Omit if the key itself is the login username.

If all checks pass, login proceeds as the key. If multiple SANs match `username_pattern`, login is ambiguous — the client must pass `--user` to disambiguate, and the server validates that value is present in the SANs.

```yaml
clients:
  # Leaf-pinned self-signed cert — no SAN checks needed, fingerprint IS the identity
  bob:
    - fingerprint: sha256-1c42ddc0285b9c25135be3bf345e6a041271b784b22a6f6cab6588dab93c5980

  # Local OS group — anyone in ENG-ALL can log in, username extracted from cert SAN
  ENG-ALL:
    - fingerprint: sha256-$li_ca
      require_patterns:
        - "urn:li:groupPrincipal(ENG-ALL)"
      username_pattern: 'urn:li:userPrincipal\((?P<user>[a-zA-Z0-9_-]*)\)'

  # Two orgs sharing a box — each CA scopes its own username namespace
  contoso-eng:
    - fingerprint: sha256-$contoso_ca
      require_patterns:
        - "urn:li:groupPrincipal(contoso-eng)"
      username_pattern: 'urn:contoso:userPrincipal\((?P<user>[a-zA-Z0-9_-]*)\)'

  # Eponymous entry — OS user is "aaron", LDAP identity is "aagoldma"
  # no username_pattern — key is the login user
  aaron:
    - fingerprint: sha256-$li_ca
      require_patterns:
        - "urn:li:userPrincipal(aagoldma)"

  # RFC822 (email) SAN — OS user is "bob", cert identity is "robert@mail.example.com"
  # mail.example.com's CA is pinned; no username_pattern — key is the login user
  bob:
    - fingerprint: sha256-$mail_example_ca
      require_patterns:
        - "robert@mail.example.com"

  # RFC822 general case — any user at mail.example.com, local part becomes OS username
  # works when the email local part matches the OS username
  mail-users:
    - fingerprint: sha256-$mail_example_ca
      username_pattern: '(?P<user>[^@]+)@mail\.example\.com'
```

The CA fingerprint scopes which CA is trusted to assert which identity namespace. The li-ca cannot assert `urn:contoso:` identities and vice versa. Safe to bake into Docker images — fingerprints contain no secrets.

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

```sh
shs auth gen                           # generate default client cert → ~/.shs/client.full.pem + ~/.shs/client.key.pem
                                       # self-signed ECC, no CN, no SAN; prints shs-<fingerprint>
shs auth gen --san user@example.com \
             --san urn:li:userPrincipal\(aagoldma\)  # --san is repeatable
shs auth gen --csr                     # generate a CSR instead
shs auth sign --in client.csr \
              --out client.full.pem    # sign a CSR; prints SANs and prompts to confirm (stub: not yet implemented)
shs auth add client.full.pem           # add cert to ACL, reads full chain and pins the leaf
shs auth add shs-<hex>                 # add a raw fingerprint to the ACL
shs auth rm  shs-<hex>                 # remove a fingerprint from the ACL
shs auth ls                            # list policies that apply to the current OS user
```

### Daemon

```sh
shs daemon                             # start with default ACL (~/.shs/acl.yaml)
shs daemon --acl fingerprints.yaml     # specify ACL file
shs daemon --webui                     # also enable the web UI
shs daemon --dangerously-run-as-root   # allow running as root (not recommended)
```

`shs auth ls` shows only policies that apply to the current OS user, in two sections. Group-inherited policies include the group name so the user knows which membership to revoke if they want to remove access.

```
Direct policies:
  bob
    shs-1c42ddc0...

Group-inherited policies:
  ENG-ALL
    shs-a3b1c2d4...   (remove with: gpasswd -d bob ENG-ALL)
  INFOSEC-PLATFORMSEC-PARTNERS-TEAM
    shs-a3b1c2d4...   (remove with: gpasswd -d bob INFOSEC-PLATFORMSEC-PARTNERS-TEAM)
```

The daemon refuses to start if running as root unless `--dangerously-run-as-root` is passed. Use `setcap cap_net_bind_service+ep /usr/local/bin/shs` to allow binding port 443 as an unprivileged user.

## Defaults

Good defaults matter because people don't configure things.

* Port 443 for HTTPS.
* **Client cert auto-generation:** if no client key is found in `~/.shs/` when connecting to a host, one is generated automatically — self-signed ECC, no CN, no SAN. The fingerprint is printed as `shs-<hex>` so the user can add it to the server's ACL.
* **Server cert auto-generation:** if no `server.key.pem` and `server.full.pem` are found when the daemon starts, they are generated automatically. The fingerprint is printed so clients can pin it.
* `shs auth gen` with no args produces the same bare minimum cert: ECC, no CN, no SAN, saved to the default paths.
* Default file locations, resolved against `$HOME` of the running user:

| File | Default path | Secret? |
|---|---|---|
| ACL | `~/.shs/acl.yaml` | No — safe to bake into Docker images |
| Server cert | `~/.shs/server.full.pem` | No — public |
| Server private key | `~/.shs/server.key.pem` | Yes — mount at runtime |
| Client cert | `~/.shs/client.full.pem` | No — public |
| Client private key | `~/.shs/client.key.pem` | Yes — keep out of images |

## UI

### CLI

Hitting the endpoint with the CLI logs in with the default credentials and drops you in a shell. See [Client commands](#client-commands) above.

### Web UI

> Disabled by default. Enable with `shs daemon --webui`.

Hitting the endpoint with the browser triggers the mTLS client cert selector and drops you into a VS Code-like environment with:

* A shell
* A local file tree
* A remote file tree
* A tab for port forwards
* An editor

## TODO

* [ ] Alternative authentication methods: FIDO/WebAuthn, TOTP. How do these interact with the mTLS identity model? Can they be layered on top as a second factor, or used as a primary alternative for environments where managing client certs is impractical?
* [ ] PAM integration. SSH runs the PAM session stack (`pam_open_session`) on login, which handles home directory mounting, `lastlog` updates, account restrictions, and other site-local policy. SHS MVP skips PAM — it resolves the user via `os/user`, sets UID, primary GID, and all supplementary groups, then execs the shell. This is sufficient for most environments but will break on systems that rely on PAM for session setup (e.g. SSSD, home-on-NFS, access restrictions via `pam_access`). PAM support needs to be added before SHS is suitable for those environments.

