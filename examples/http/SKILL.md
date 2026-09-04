---
title: "http binary — Invoke authenticated HTTP requests"
description: |
  Invoke the http binary to make HTTP requests with persistent session cookie
  management. Cookies are stored internally and never exposed to the calling
  process. Use this to test delegation-proxy-server endpoints or make authenticated
  API calls that require session persistence.
scopes:
  - workspace
invocation: "When the user asks to call an HTTP endpoint or test an API"
---

# http Binary Skill

## Purpose

Enable the agent to invoke `/Users/aaron/workspace/delegations/http/http` to make authenticated HTTP requests with secure, persistent session cookie management. The binary:

- Accepts raw HTTP/1.1 requests on stdin
- Injects cookies based on agent/session identifiers
- Forwards requests to the target server
- Strips HttpOnly cookies from responses (keeping them server-side)
- Returns complete response to stdout

## When to Use

- Testing delegation-proxy-server endpoints (`/api/whoami`, `/code/`, etc.)
- Making HTTP calls that require persistent session authentication
- Validating cookie behavior in delegation flows
- Debugging HTTP interactions without exposing session tokens

## Basic Pattern

```bash
printf '<HTTP_REQUEST>' | /Users/aaron/workspace/delegations/http/http \
  --agent <agent_id> --session <session_id>
```

## Flags

- `--agent <identifier>`: Agent identifier (optional; defaults to calling user)
- `--session <identifier>`: Session identifier (optional; defaults to calling user)

If either is omitted, the binary defaults to the calling user's username (via `os.Getuid()`).

## Examples

### GET request to delegation-proxy-server
```bash
printf 'GET /api/whoami HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n' \
  | /Users/aaron/workspace/delegations/http/http --agent testagent --session testsession
```

### POST request with JSON body
```bash
printf 'POST /delegations/grant HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 50\r\nConnection: close\r\n\r\naction=approve&breadth=session&ttl=4h' \
  | /Users/aaron/workspace/delegations/http/http --agent testuser --session testsession
```

### Using caller's username (no flags)
```bash
printf 'GET /api/whoami HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n' \
  | /Users/aaron/workspace/delegations/http/http
```

## Implementation Strategy

1. **Construct the HTTP request**: Build raw HTTP/1.1 with method, host, headers, and body
2. **Determine identifiers**: Use provided `--agent`/`--session` or caller's username
3. **Invoke the binary**: Pipe request via stdin, capture stdout
4. **Parse the response**: Extract status, headers, and body
5. **Handle errors**: Exit codes 1–4 indicate different failure modes

## Exit Codes

| Code | Scenario |
|------|----------|
| 0    | Success |
| 1    | Bad arguments (invalid flags/identifiers) |
| 2    | Invalid HTTP request on stdin |
| 3    | Network or response-write error |
| 4    | Cookie store error |

## Key Constraints

- **Cookie scope**: Each (host, agent, session) has its own cookie jar
- **HttpOnly isolation**: HttpOnly cookies stored server-side, never leak to caller
- **Automatic pruning**: Expired cookies removed before each request
- **Permissions**: `cookies.sqlite3` must have mode `0600` (enforced on startup)

## Related Contexts

- Delegation-proxy-server endpoints: `/api/whoami`, `/delegations/ask`, `/delegations/grant`
- HTTP request construction: method, host header, content-length, connection management
- Cookie lifecycle: Set-Cookie parsing, expiration, scope matching

