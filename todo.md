# To-Do List

## HTTP Client (`examples/http`)

### RFC 6265 Cookie Matching

The original bug report noted that `store.Lookup` ignored both cookie `Domain` and `Path`
attributes. Both are now implemented in `cookies/store.go` (`domainMatch` + `pathMatch` +
Secure filtering). Unit tests exist in `cookies/store_test.go`.

- [x] Implement RFC 6265 cookie domain / subdomain matching
- [x] Implement RFC 6265 cookie path-prefix matching
- [x] Add unit tests for domain, path, and secure filtering

### Broken Integration Test

`integration_test.go` still calls the old 3-arg `Lookup(origin, agent, session)` and 2-arg
`DeleteExpired(origin, agent)` signatures. The current `store.go` requires
`Lookup(scheme, host, reqPath, agent, session)` and `DeleteExpired(agent)`.

- [ ] Update `integration_test.go` to the current `store.go` signatures and add path/domain test cases

### Double-Proxy Pattern

Target data path:
```
agent ←local socket→ http tool ←http→ delegation router ←backhaul→ service
```

- [ ] Wire the http tool to the delegation router over a local Unix socket rather than a direct network call

---

## Proxy (`examples/proxy`)

### Self-Service Registration Endpoints

`reverse-proxy-spec.md` §5.2 lists these as Planned. The `did:key` self-service flow is already
implemented; the following are not.

- [ ] Add a self-service endpoint to register a username (`POST /delegations/register/username`)
- [ ] Add a self-service endpoint to register an email scope (`POST /delegations/register/email`)

### Rename to "Sentinel Gateway" (short name: `sentinel`)

The proxy example is currently named `delegation-proxy-server` throughout the module. It is being
renamed to **Sentinel Gateway**, with the short name **`sentinel`** used for both the Go module
suffix and the produced binary. Renaming requires updating:

- [ ] Module path in `go.mod` → `github.com/aarongoldman/delegations/examples/sentinel`
- [ ] All Go import paths (`flow_test.go`, `api/whoami.go`, `vscodeproxy.go`, `main.go`)
- [ ] Package doc comments in `main.go` (title, usage text, log line)
- [ ] Binary name → `sentinel`. Currently `go build .` names the output after the directory (`proxy`); either rename the dir to `sentinel` or change the Makefile to `go build -o sentinel .` (and `clean` to `rm -f sentinel`)
- [ ] `examples/proxy/README.md` title and body
- [ ] `.gitignore` entries: `examples/proxy/proxy` and the stray `examples/proxy/delegation-proxy-server` (under `# macOS`) → `sentinel` path
- [ ] `examples/http/SKILL.md` references
- [ ] Rename `examples/proxy/` directory itself to `examples/sentinel/` (or keep it and document the new name)

---

## Spec (`.md` files)

### Path Wildcard Convention

The trailing-slash subtree convention was adopted in `delegated-access-token.md`,
`delegation-model.md`, `scope-granting-flows.md`, and `examples/proxy/README.md`.
`reverse-proxy-spec.md` still uses the old `/*` wildcard syntax in several places.

- [ ] `reverse-proxy-spec.md` line ~67: schema comment `"/users/*"` → `"/users/" (subtree)`
- [ ] `reverse-proxy-spec.md` line ~135: "path-prefix wildcard like `/users/*`" → trailing-slash convention
- [ ] `reverse-proxy-spec.md` line ~156: `api.example.com/users/*` → `api.example.com/users/`
- [ ] Verify all remaining spec docs are consistent with the new trailing-slash path convention

### Self-Service Endpoints in Spec

- [ ] `reverse-proxy-spec.md` §5.2: update status from "Planned" to "Implemented" once the endpoints ship

### RFC 6265 Cookie Behavior in Spec

- [ ] `delegation-formats-proposal.md`: document the current domain, path, and secure-filtering
      behavior of the `http` tool's cookie store (currently the spec only describes the ideal
      behavior without noting that it is implemented)

### Rename References in Spec

- [ ] After the "Sentinel Gateway" rename: update all spec documents that reference
      "delegation-proxy-server" or "the proxy"
