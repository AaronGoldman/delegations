# HTTP Tool Requirements

## Overview
A standalone Go binary that acts as an ambient authentication proxy, managing HTTP cookies in a separate process to enable delegated access across multiple agents and sessions.

## Executive Summary
The `http` tool reads HTTP requests from stdin, augments them with cookies from a persistent cookie jar, sends the request, and returns the response with sensitive cookie headers stripped. The cookie jar is maintained in a separate process and keyed by origin, agent, and session to support multi-tenant credential isolation.

## Architecture Goals
- **Credential Isolation**: Cookies stored in a separate process/file, not in the calling application's memory
- **Multi-tenant Support**: Separate cookie namespaces per (origin, agent, session) tuple
- **Security**: Untrusted stdin; trusted CLI parameters only
- **Simplicity**: MVP focuses on single request-response cycles

---

## Functional Requirements

### 1. Binary Invocation
- **Binary Name**: `http`
- **Language**: Go
- **Required Flags**: 
  - `--agent={uuid}` - Agent identifier (required, untrusted callers cannot override)
  - `--session={uuid}` - Session identifier (required, untrusted callers cannot override)
- **Input**: HTTP request via stdin (untrusted)
- **Output**: HTTP response to stdout

### 2. Request Processing
- Read complete HTTP request from stdin (including method, headers, body)
- Extract origin/host from the request
- Lookup cookies in `cookies.sqlite3` by (origin, agent, session)
- Inject matching cookies into request `Cookie` header
  - The persistent cookies from the agent
  - The session cookies from the session
- Send the HTTP request
- Await response

### 3. Response Processing
- Receive HTTP response headers and body
- Strip all `Set-Cookie` headers that have the `HttpOnly` flag
- Preserve all other `Set-Cookie` headers (non-HttpOnly)
  - all Cookie saved in the jar for next request
  - HttpOnly Cookie never sent to the aplication
- Return complete response (headers, body) to stdout
- **Note**: Cookies are persisted; response handling does update the local cookie jar in MVP

### 4. Cookie Jar Management

#### Storage
- **Location**: `cookies.sqlite3` stored in the same directory as the binary, not in caller's PWD
  - http tool should be owned by http user
  - cookies.sqlite3 should be owned by http user
  - http tool should have setuid bit set so it can read and write cookies.sqlite3
  - cookies.sqlite3 should be 600 so that no non http user can read the cookies.sqlite3
- **Key Structure**: `(origin, agent_uuid, session_uuid, cookie_name)` composite key
- **Persistence**: Survives across multiple invocations of the binary

#### Cookie Attributes
- **Origin**: Derived from request host/scheme (same-origin policy)
- **Session Cookies**: Identified by absence of `Expires` or `Max-Age` (matching browser semantics)
  - Scoped to (origin, agent, session)
  - Stored with session_uuid set
  - Deleted when session ends (agent/session pair no longer used)
- **Persistent Cookies**: Identified by `Expires` or `Max-Age` values
  - Scoped to (origin, agent) only — shared across all sessions for that agent
  - Stored with session_uuid = NULL
  - Cleaned up after `Expires`/`Max-Age` is reached
  - Reused across multiple sessions within the same agent

#### Cookie Isolation
Cookies are isolated by origin and agent, with session-level isolation for session cookies only:
- **Session cookies** (no Expires/Max-Age): Scoped to (origin, agent, session) — start fresh each session
- **Persistent cookies** (has Expires/Max-Age): Scoped to (origin, agent) — shared across all sessions for that agent
- No cookie leakage between:
  - Different agents (even with same session)
  - Different origins (standard origin policy)

### 5. Lifecycle (MVP)
- Accept command-line arguments
- Process one HTTP request-response cycle
- Exit with status 0 on success, non-zero on error
- Do not maintain persistent connections or loop for multiple requests

---

## Non-Functional Requirements

### Security
1. **Input Validation**
   - Agent and session UUIDs validated format (must be valid UUIDs)
   - CLI flags are trusted; stdin is not
   - HTTP request parsing must safely handle malformed input
2. **Credential Isolation**: Cookies never leak to the calling process; only the binary accesses the cookie jar
3. **File Permissions**: `cookies.sqlite3` should be readable/writable only by the binary's user (0600 or equivalent) exit with error if Permissions not set.

### Performance
- Single request per invocation (no connection pooling in MVP)
- Minimal overhead for cookie lookup and injection
- Sqlite3 queries should be indexed by (origin, agent, session) for fast lookups
  - mvp no indexes

### Reliability
- Graceful handling of missing/corrupt `cookies.sqlite3` (create if missing)
- Graceful handling of network errors (return error to stdout with non-zero exit code)
- Proper cleanup of resources (connections, DB handles)

### Portability
- Cross-platform Go binary (macOS, Linux, Windows)
- No external dependencies beyond Go stdlib for MVP
- Sqlite3 support via `github.com/mattn/go-sqlite3` or similar

---

## Data Model

### cookies.sqlite3 Schema
```sql
CREATE TABLE cookies (
    origin TEXT NOT NULL,
    agent_uuid TEXT NOT NULL,
    session_uuid TEXT,         -- NULL for persistent cookies, set for session cookies
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    expires INTEGER,           -- Unix timestamp; NULL for session cookies
    path TEXT DEFAULT '/',
    domain TEXT,
    secure BOOLEAN DEFAULT 1,
    http_only BOOLEAN DEFAULT 1,
    same_site TEXT DEFAULT 'Strict',
    created_at INTEGER,
    PRIMARY KEY (origin, agent_uuid, session_uuid, name)
);

CREATE INDEX idx_origin_agent ON cookies(origin, agent_uuid);
CREATE INDEX idx_origin_agent_session ON cookies(origin, agent_uuid, session_uuid);
```

---

## Example Workflows

### Scenario 1: Authenticated Request
```bash
# Agent A, Session 1 requests a protected resource
cat request.txt | ./http --agent=agent-uuid-1 --session=session-uuid-1

# Input (stdin):
# GET /api/user HTTP/1.1
# Host: api.example.com
# User-Agent: my-assistant

# Lookup: cookies where origin=api.example.com AND agent=agent-uuid-1 AND session=session-uuid-1
# Inject: Cookie: auth_token=abc123; session_id=xyz789
# Send request, receive response, strip HttpOnly Set-Cookie headers
# Output (stdout):
# HTTP/1.1 200 OK
# Content-Type: application/json
# Set-Cookie: tracking=foo; SameSite=Strict  (preserved, no HttpOnly)
# 
# {"user": "john"}
```

### Scenario 2: Session vs Persistent Cookies
```bash
# Agent A, Session 1 - receives both session and persistent cookies
cat request.txt | ./http --agent=agent-a --session=session-1
# - Session cookies stored with session_uuid=session-1
# - Persistent cookies stored with session_uuid=NULL

# Agent A, Session 2 - different session, same agent
cat request.txt | ./http --agent=agent-a --session=session-2
# - Gets the same persistent cookies from session-1 (session_uuid=NULL)
# - Session cookies are different (session_uuid=session-2)
# - Persistent cookies carry over between sessions in the same agent

# Agent B, Session 1 - different agent
cat request.txt | ./http --agent=agent-b --session=session-1
# - Completely isolated: no cookies from agent-a
```

---

## Error Handling

| Error | Exit Code | Output |
|-------|-----------|--------|
| Invalid agent UUID format | 1 | Error message to stderr |
| Invalid session UUID format | 1 | Error message to stderr |
| Malformed HTTP request | 2 | Error message to stderr |
| Network error (connection failed) | 3 | Error message to stderr |
| Cookie jar access error | 4 | Error message to stderr |
| HTTP status >= 400 | 0 | Full response to stdout (binary acts as transparent proxy) |

---

## Future Enhancements (Not MVP)
- Persistent connection pooling for multiple requests
- Cookie lifecycle management and rotation policies
- Metrics/observability (request count, latency)

---

## Testing Strategy
- Unit tests for UUID validation
- Unit tests for cookie lookup by (origin, agent, session)
- Integration tests with real sqlite3 database
- End-to-end tests with mock HTTP server
- Security tests for cookie isolation across agents/sessions
- Error cases (missing DB, corrupt data, network failures)

---

## Acceptance Criteria
- [ ] Binary compiles on macOS and Linux
- [ ] CLI flags `--agent` and `--session` are required and validated
- [ ] HTTP request is read from stdin without modification
- [ ] Cookies injected into request based on (origin, agent, session)
- [ ] Response returned to stdout with HttpOnly Set-Cookie headers stripped
- [ ] `cookies.sqlite3` stored next to binary, not in PWD
- [ ] Single request-response cycle completes and exits
- [ ] File permissions on cookie jar restricted (0600)
- [ ] All exit codes match error handling table