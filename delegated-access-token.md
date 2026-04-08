# Delegated Access Token Specification

**Editor:** Aaron Goldman
**Repository:** https://github.com/AaronGoldman/delegations

## Abstract

This specification defines a **Principal-Agent Delegation** mechanism for AI agents and automated systems. A *principal* is the human (or trusted system) who authorizes access; an *agent* is the automated system acting on the principal's behalf. The specification enables agents to request access to protected resources through principal-mediated browser-based authorization, without requiring the agent to handle the principal's credentials directly. The core flow uses HttpOnly cookies, RFC7807-compliant error responses, and JWT-based delegation requests to provide secure, auditable, and principal-controlled authorization.

## Status of this Document

This is a draft specification.

## Table of Contents

1. **[Prerequisites](#1-prerequisites)** - Requirements for agent and principal environment
2. **[Specification Scope](#2-specification-scope)** - What this specification defines
3. **[The Flow](#3-the-flow)** - Complete delegation flow with HTTP trace
4. **[RFC7807 Problem+JSON Format](#4-rfc7807-problemjson-format)** - Error response structure
5. **[JWT Token Format](#5-jwt-token-format)** - Delegation request token payload
6. **[Grant Matching](#6-grant-matching)** - How requests are authorized
7. **[Grant Lifecycle](#7-grant-lifecycle)** - TTL, expiry, and garbage collection
8. **[Appendix: Implementation Guidance](#appendix-implementation-guidance)** - Optional implementation details

---

## 1. Prerequisites

The agent and principal environment MUST meet these requirements:

* The agent MUST be able to preserve a cookie jar
* The agent MUST be able to clear session cookies distinct from agent cookies
* Default behavior is to treat a cookie without an expiration date as a session cookie
* The principal MUST have a way to log in to a browser session

---

## 2. Specification Scope

This specification defines:
* The overall authentication flow (5-step delegation process)
* Cookie handling requirements (agent cookies, session cookies, HttpOnly handling)
* The roles and interactions between Agent, Principal, and Server
* Security boundaries (HttpOnly cookie isolation from agent code)
* RFC7807-compliant error responses for delegation requests
* Grant matching algorithm for authorization
* Grant TTL options and how the requesting server may suggest them
* Grant lifecycle including expiry and garbage collection of inactive delegations

---

## 3. The Flow

### 3.1 Quick Start

1. The agent tries to access a web API
   * The agent is rejected
   * The server sets an agent cookie
   * The server sets a session cookie
   * The server formats a URL for an access delegation request
2. The agent sends the access delegation request URL to the principal
   * Link, QR code, redirect, etc.
3. The principal opens the access delegation request URL in a browser
   * The server displays a grant UI (MUST NOT automatically grant on URL load)
   * The principal actively interacts with the UI (clicks approve button, submits form, etc.)
   * The grant is processed via POST request with CSRF protection
4. The principal informs the agent to retry
5. The agent tries to access a web API
   * Success

### 3.2 Communication Diagram

```
┌───────┐                    ┌───────────┐                    ┌────────┐
│ Agent │                    │ Principal │                    │ Server │
└───┬───┘                    └─────┬─────┘                   └────┬───┘
    │                              │                              │
    │ 1) Try to access API         |                              │
    │─────────────────────────────────────────────────────────── >│
    │                              │                              │
    │ 2) 401 Unauthorized + Cookies + Delegation URL              │
    │< ───────────────────────────────────────────────────────────│
    │                              │                              │
    │ 3) Send delegation URL       │                              │
    │─────────────────────────────>│                              │
    │                              │                              │
    │                              │ 4) Open URL in browser       │
    │                              │─────────────────────────────>│
    │                              │                              │
    │                              │ 5) Show grant UI             │
    │                              │<─────────────────────────────│
    │                              │                              │
    │                              │ 6) Grant permissions         │
    │                              │─────────────────────────────>│
    │                              │ 7) Grant permissions ACK     │
    │                              │<─────────────────────────────│
    │                              │                              │
    │ 8) Principal tells agent to retry                           │
    │<─────────────────────────────│                              │
    │                              │                              │
    │ 9) Retry API access (with cookies)                          │
    │─────────────────────────────────────────────────────────── >│
    │                              │                              │
    │ 10) 200 Success              │                              │
    │< ───────────────────────────────────────────────────────────│
```

### 3.3 Complete HTTP Trace Example

#### Step 1: Agent tries to access API

```http
GET /api/users/123/messages HTTP/1.1
Host: api.example.com
User-Agent: MyAgent/1.0
Accept: application/json
```

#### Step 2: Server rejects with delegation URL

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/problem+json
Set-Cookie: agent_cookie=550e8400-e29b-41d4-a716-446655440000; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000; Path=/
Set-Cookie: session_cookie=6ba7b810-9dad-11d1-80b4-00c04fd430c8; HttpOnly; Secure; SameSite=Strict; Path=/
Cache-Control: no-store

{
  "type": "https://github.com/aarongoldman/delegations#delegation-required",
  "delegation_url": "https://auth.example.com/delegate?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZ2VudF9pZCI6IjU1MGU4NDAwLWUyOWItNDFkNC1hNzE2LTQ0NjY1NTQ0MDAwMCIsInNlc3Npb25faWQiOiI2YmE3YjgxMC05ZGFkLTExZDEtODBiNC0wMGMwNGZkNDMwYzgiLCJob3N0IjoiYXBpLmV4YW1wbGUuY29tIiwicGF0aCI6Ii91c2Vycy8xMjMvbWVzc2FnZXMiLCJtZXRob2RzIjpbIkdFVCJdLCJzY29wZXMiOlsiUkVBRF9ETSJdLCJ0dGwiOlsiNGgiLCIyZCIsIjkwZCIsIjQwMGQiXSwiZXhwaXJlc19hdCI6IjIwMjYtMDItMTlUMTA6MTU6MDBaIiwiaWF0IjoxNzA4MzQ0MDAwfQ.signature",
  "documentation_url": "https://api.example.com/docs/scopes"
}
```

#### Step 3: Agent presents URL to principal

```python
print("Authorization required.")
print("Please visit: https://auth.example.com/delegate?token=eyJhbGci...")
print("Learn more: https://api.example.com/docs/scopes")
```

#### Step 4: Principal opens delegation URL in browser

```http
GET /delegate?token=eyJhbGci... HTTP/1.1
Host: auth.example.com
User-Agent: Mozilla/5.0
Cookie: principal_session=abc123def456...
```

#### Step 5: Server shows grant UI

```http
HTTP/1.1 200 OK
Content-Type: text/html
Set-Cookie: csrf_token=9f8e7d6c5b4a3210; HttpOnly; Secure; SameSite=Strict; Path=/

<!DOCTYPE html>
<html>
<head><title>Authorize Agent</title></head>
<body>
<h1>Agent Authorization Request</h1>
<p><strong>Resource:</strong> api.example.com/users/123/messages</p>
<p><strong>Method:</strong> GET</p>
<p><strong>Scope:</strong> READ_DM - Read direct messages you've received</p>
<form method="POST" action="/delegate/grant">
<input type="hidden" name="token" value="eyJhbGci...">
<input type="hidden" name="csrf_token" value="9f8e7d6c5b4a3210">
<p>Grant term:</p>
<label><input type="radio" name="term" value="once" checked> One time only</label><br>
<label><input type="radio" name="term" value="session"> This session</label><br>
<label><input type="radio" name="term" value="agent"> All sessions for this agent</label><br>
<p>Grant duration:</p>
<label><input type="radio" name="ttl" value="4h" checked> 4 hours</label><br>
<label><input type="radio" name="ttl" value="2d"> 2 days</label><br>
<label><input type="radio" name="ttl" value="90d"> 90 days</label><br>
<label><input type="radio" name="ttl" value="400d"> 400 days</label><br>
<label><input type="radio" name="ttl" value="indefinite"> Indefinite (until revoked)</label><br>
<button type="submit" name="action" value="approve">Approve</button>
<button type="submit" name="action" value="deny">Deny</button>
</form>
</body>
</html>
```

#### Step 6: Principal grants permissions

```http
POST /delegate/grant HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded
Cookie: principal_session=abc123def456...; csrf_token=9f8e7d6c5b4a3210

token=eyJhbGci...&term=session&ttl=2d&csrf_token=9f8e7d6c5b4a3210&action=approve
```

#### Step 8: Principal tells agent to retry

```bash
$ try now
```

#### Step 9: Agent retries API access

```http
GET /api/users/123/messages HTTP/1.1
Host: api.example.com
User-Agent: MyAgent/1.0
Accept: application/json
Cookie: agent_cookie=550e8400-e29b-41d4-a716-446655440000; session_cookie=6ba7b810-9dad-11d1-80b4-00c04fd430c8
```

#### Step 10: Success!

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "messages": [
    {
      "id": "msg_001",
      "from": "user_456",
      "content": "Hello! How are you?",
      "timestamp": "2026-02-19T09:30:00Z"
    }
  ]
}
```

---

## 4. RFC7807 Problem+JSON Format

When the agent attempts to access a protected resource without valid authorization, the server responds with an RFC7807-compliant `application/problem+json` response.

### 4.1 Required Fields

- **type** (string, URI) - REQUIRED
  - URI reference to this specification
  - Fixed value: `"https://github.com/aarongoldman/delegations#delegation-required"`

- **delegation_url** (string, URL) - REQUIRED
  - URL to delegation page with signed JWT token
  - Format: `https://auth.example.com/delegate?token={jwt}`

- **documentation_url** (string, URL) - REQUIRED
  - Link to API documentation explaining scopes and delegation

### 4.2 Security Requirements

> [!CAUTION]
> **CSRF Protection: Principal Interaction Required**
>
> The delegation URL **MUST NOT** automatically grant permissions upon navigation. Following a link is not consent.
>
> **Required:**
> * Delegation URL displays a grant UI that requires explicit principal interaction
> * Principal must actively click "Approve", check boxes, or otherwise interact with a form
> * Permission grant occurs via POST request with CSRF protection (tokens, SameSite cookies, etc.)
> * Simply opening the URL in a browser MUST NOT grant any permissions

---

## 5. JWT Token Format

The JWT in `delegation_url` is signed with HMAC-SHA256 or stronger by the API server and verified by the delegation page.

### 5.1 JWT Payload

```json
{
  "agent_id": "550e8400-e29b-41d4-a716-446655440000",
  "session_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
  "host": "api.example.com",
  "path": "/users/123/messages",
  "methods": ["GET"],
  "scopes": ["READ_DM"],
  "ttl": ["4h", "2d", "90d", "400d"],
  "expires_at": "2026-02-19T10:15:00Z",
  "iat": 1708344000
}
```

### 5.2 Fields

- **agent_id** (UUID): Identifies the agent instance (derived from agent_cookie via UUIDv5)
- **session_id** (UUID): Identifies the session (derived from session_cookie via UUIDv5)
- **host** (string): Host from the rejected request (e.g., "api.example.com")
- **path** (string): Path from the rejected request (e.g., "/users/123/messages")
- **methods** (array[string]): HTTP methods needed (e.g., ["GET", "POST"])
- **scopes** (array[string]): Application-specific scopes needed (e.g., ["READ_DM"])
- **ttl** (array[string], optional): Ordered list of grant lifetime options to present in the UI. The first entry is pre-selected. Valid values: `"4h"`, `"2d"`, `"90d"`, `"400d"`, `"indefinite"`. If absent the UI MUST default to `["4h", "2d", "90d", "400d"]`.
- **expires_at** (ISO 8601): When this delegation *request* expires (i.e., how long the principal has to act on it; typically 5–15 minutes)
- **iat** (number): Issued-at timestamp (standard JWT claim)

---

## 6. Grant Matching

### 6.1 Minimal Database Schema

```sql
CREATE TABLE delegations (
    delegation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Identity
    agent_id    UUID         NOT NULL,
    session_id  UUID         NOT NULL,
    principal_id VARCHAR(255) NOT NULL,

    -- Matching fields
    host_pattern VARCHAR(255) NOT NULL,    -- "api.example.com" or "*.example.com"
    path_pattern VARCHAR(500) NOT NULL,    -- "/users/123/messages" or "/users/*"
    methods      VARCHAR(10)[] NOT NULL,   -- ["GET", "POST"]
    scopes       VARCHAR(100)[] NOT NULL,  -- ["READ_DM", "SEND_DM"]

    -- Grant term
    term         VARCHAR(10) NOT NULL,     -- "once" | "session" | "agent"

    -- Lifecycle
    ttl          VARCHAR(20) NOT NULL,     -- "4h" | "2d" | "90d" | "400d" | "indefinite"
    granted_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ,              -- NULL when ttl = "indefinite"
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,

    -- Index for fast lookups
    INDEX idx_active_delegations (agent_id, session_id)
        WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())
);
```

### 6.2 Authorization Algorithm

When a request arrives with agent_cookie and session_cookie:

1. **Derive identities**
   ```python
   import uuid

   agent_id   = uuid.uuid5(server_secret, agent_cookie)
   session_id = uuid.uuid5(server_secret, session_cookie)
   ```

2. **Fetch active delegations**
   ```sql
   SELECT delegation_id, host_pattern, path_pattern, methods, scopes, scope
   FROM delegations
   WHERE agent_id = $1
     AND revoked_at IS NULL
     AND (expires_at IS NULL OR expires_at > NOW())
   ```

   Note: the query filters only on `agent_id`. The session match is applied in step 3 because `"agent"` term delegations are intentionally session-independent.

3. **For each delegation, check if request matches:**
   - **Session check**: if `term != "agent"`, the delegation's `session_id` MUST equal the request's derived `session_id`
   - **Host matches** host_pattern (exact or wildcard `*.example.com`)
   - **Path matches** path_pattern (exact or wildcard `/users/*`)
   - **Request method** is in methods array
   - **All request scopes** are in delegation scopes array (superset check)

4. **If ANY delegation matches → ALLOW the request**
   - Update `last_used_at = NOW()` for the matched delegation
   - If `term = "once"`, immediately revoke the delegation after use

### 6.3 Grant Term Semantics

- **`"once"`** — Single-use. The delegation is revoked immediately after the first successful use. Requires both `agent_id` and `session_id` to match.
- **`"session"`** — Valid for the lifetime of the current session. Requires both `agent_id` and `session_id` to match. The delegation expires when the session ends (or when its TTL elapses, whichever comes first).
- **`"agent"`** — Valid for all sessions of the same agent. Matches on `agent_id` alone, independent of `session_id`. Survives session expiry and cookie clearing as long as the agent_cookie persists.

### 6.4 Wildcard Matching Examples

**Host patterns:**
- `api.example.com` - exact match only
- `*.example.com` - matches api.example.com, cdn.example.com, etc.

**Path patterns:**
- `/users/123/messages` - exact match only
- `/users/123/*` - matches /users/123/messages, /users/123/profile, etc.
- `/users/*` - matches /users/123/messages, /users/456/posts, etc.

**Method matching:**
- Request method must be in the delegation's methods array
- Example: If delegation has `["GET", "POST"]`, then GET and POST requests are allowed

**Scope matching (superset):**
- ALL scopes required by the endpoint must be present in the delegation
- Example: If endpoint requires `["READ_DM"]` and delegation has `["READ_DM", "SEND_DM"]`, request is allowed
- Example: If endpoint requires `["READ_DM", "SEND_DM"]` but delegation only has `["READ_DM"]`, request is denied

---

## 7. Grant Lifecycle

### 7.1 TTL Values

The following TTL values are defined:

| Value | Grant lifetime |
|---|---|
| `"4h"` | 4 hours from grant time |
| `"2d"` | 2 days from grant time |
| `"90d"` | 90 days from grant time |
| `"400d"` | 400 days from grant time |
| `"indefinite"` | No automatic expiry; subject to garbage collection (see §7.3) |

`expires_at` for a stored delegation is computed at grant time as `granted_at + ttl_duration`. For `"indefinite"` grants, `expires_at` is NULL.

### 7.2 TTL Selection in the UI

The delegation request JWT may include a `ttl` array to suggest appropriate lifetimes for the requested resource. The first entry is presented as the default radio selection. If the JWT contains no `ttl` field, the UI MUST present `["4h", "2d", "90d", "400d"]` as the options (in that order, with `"4h"` pre-selected).

The server generating the JWT SHOULD tailor TTL options to the sensitivity of the resource. For example, a highly sensitive operation might only offer `["4h", "2d"]`, while a read-only background sync might offer `["90d", "400d", "indefinite"]`.

The `"indefinite"` option SHOULD be explicitly included in the JWT `ttl` array when the server considers it appropriate. It MUST NOT appear in the UI unless the JWT includes it or the principal is shown a clear warning about the implications.

### 7.3 Garbage Collection

> [!NOTE]
> **Design trade-off:** Storing delegations forever is operationally expensive and creates long-lived privacy risk — a revoked-but-never-deleted delegation record is a liability. On the other hand, deleting an `"indefinite"` delegation that the principal expected to persist would be a surprising breaking change for the agent.
>
> This specification resolves the tension with an **inactivity-based TTL**: even `"indefinite"` delegations are garbage-collected after a period of non-use.

Any delegation — including those with `ttl = "indefinite"` — MUST be treated as expired and eligible for deletion if it has not been used within **400 days**:

```sql
-- Eligible for garbage collection
WHERE last_used_at < NOW() - INTERVAL '400 days'
   OR (last_used_at IS NULL AND granted_at < NOW() - INTERVAL '400 days')
```

`last_used_at` MUST be updated on every successful request authorized by the delegation (see §6.2 step 4).

**Implications:**
- A delegation that is actively used will never be garbage-collected, regardless of TTL.
- A delegation that falls idle for 400 days will be silently removed. The agent will receive a new 401 and must obtain a fresh delegation.
- This prevents unbounded growth of the delegations table without requiring principals to manually revoke grants they have forgotten.
- Implementations MAY use a shorter inactivity window but MUST document it clearly so principals understand the behavior.

---

## Appendix: Implementation Guidance

This appendix provides optional implementation details and guidance.

### A.1 Cookie Generation

**agent_cookie**: UUIDv4 value, identifies the agent instance across sessions
**session_cookie**: UUIDv4 value, identifies a specific session

The server derives identities using UUIDv5:
```python
import uuid

# Generate derived identities
agent_id   = uuid.uuid5(server_secret, agent_cookie)
session_id = uuid.uuid5(server_secret, session_cookie)
```

**Benefits:**
- Privacy: Agent never sees the actual agent_id or session_id
- Security: Server can verify and derive identities without database lookup
- Deterministic: Same cookie + secret always produces same UUID
- Standard: UUIDv5 is designed for namespace-based UUID generation

### A.1.1 Key Rotation with Overlap Window

To support seamless key rotation, validate against both current and previous secrets:

```python
import uuid

def verify_agent(token_agent_id, agent_cookie, current_secret, previous_secret):
    # Try the current window
    if str(uuid.uuid5(current_secret, agent_cookie)) == token_agent_id:
        return "Validated (Current)"

    # Try the overlap window
    if str(uuid.uuid5(previous_secret, agent_cookie)) == token_agent_id:
        return "Validated (Previous)"

    return "Invalid"
```

**Key rotation process:**
1. Generate new secret, keep old secret as `previous_secret`
2. New grants use new secret
3. Existing grants work with either secret (overlap window)
4. After grace period (e.g., 30 days), drop `previous_secret`

### A.2 Cookie Security

All cookies MUST be:
- **HttpOnly** to prevent XSS access
- **Secure** (HTTPS only)
- **SameSite=Lax** or **SameSite=Strict**

agent_cookie should have long expiration (e.g., 1 year)
session_cookie should have no expiration (expires when browser closes)

### A.3 Grant Expansion Options

When the principal visits the delegation URL, they can broaden the grant along two independent axes: **scope** and **TTL**.

**Term (who the grant applies to):**

| Term | Match condition | Default |
|---|---|---|
| `"once"` | agent_id + session_id, single use | Narrowest |
| `"session"` | agent_id + session_id, until session ends or TTL elapses | — |
| `"agent"` | agent_id only, survives session changes | Broadest |

**Paths and hosts** can also be broadened (narrow to broad):
- Paths: `/users/123/messages` → `/users/123/*` → `/users/*`
- Hosts: `api.example.com` → `*.example.com`
- Methods: `GET` → `GET, POST` → all methods

**TTL (how long the grant lasts):**
Presented in order from the `ttl` array in the JWT (or the default list if absent). First entry is pre-selected. TTL is independent of scope — a `"session"` scope delegation may have a `"90d"` TTL, meaning it is valid for 90 days but only while the original session cookie is presented.

Note: For `"once"` term, TTL is not meaningful since the delegation is consumed on first use. Implementations MAY hide the TTL selector when `"once"` is selected.

### A.4 Scope Documentation

The `documentation_url` SHOULD explain each scope in principal-friendly terms.

**Good scope names:**
- `READ_DM` - Read your direct messages
- `SEND_DM` - Send direct messages on your behalf
- `READ_PUBLIC_POSTS` - View public posts

**Bad scope names:**
- `readonly` - Unclear what can be read
- `write` - Unclear what can be written

### A.5 Sessions Management UX

Principals should be able to:
1. List all active delegations with their granted scopes, TTL, and last-used timestamp
2. Revoke individual delegations or all delegations for an agent
3. View usage history (endpoints accessed, timestamps, IPs)

### A.6 Proxy Implementation

When a proxy receives a request:
1. Extract identities: Derive agent_id and session_id from cookies
2. Fetch delegations: Query database for active delegations
3. Validate scope: Check if request matches any delegation
4. Update last_used_at: Record the access time on the matched delegation
5. Cache result: Cache the authorization decision (5 min TTL recommended)
6. Subscribe to revocations: Listen for revocation events
7. Log usage: Record the request for audit

### A.7 Audit Logging

All of the following SHOULD be logged:
- Delegation requests (who, when, what scopes)
- Delegation approvals/denials (principal, timestamp, decision)
- API access using delegated credentials
- Session revocations

### A.8 Security Considerations

**Secret Management:**
- Use cryptographically strong UUID namespace (random UUID recommended)
- Rotate secrets periodically with overlap window (see A.1.1)
- During rotation, validate against both current and previous secrets

**Request Expiration:**
- Authorization URLs should expire within 5-15 minutes
- Expired requests MUST be rejected

**Rate Limiting:**
- Limit authorization URL generation per agent
- Limit delegation approval attempts per principal
- Limit API requests per (agent_id, session_id)

### A.9 HttpOnly Cookie Isolation

> [!IMPORTANT]
> The HTTP tool for your agent should include `HttpOnly` cookies in requests but must be careful not to expose `HttpOnly` cookies to the agent's code or logs.
>
> We recommend hiding the entire `Cookie` header from the agent and providing a separate API for accessing only the non-HttpOnly cookies that the agent is permitted to read.

### A.10 Why No Redirect Back (Unlike OAuth/OIDC)

This specification intentionally does not provide a redirect back from the authorization server to the requesting agent—unlike OAuth 2.0 and OpenID Connect (OIDC). This design choice reflects hard-won security lessons learned from open redirect vulnerabilities.

**Design Rationale:**

1. **Open Redirect Attack History:**
   The service has a documented history of attacks leveraging open redirects. Traditional OAuth/OIDC flows require a `redirect_uri` parameter, which if improperly validated or used in overly permissive allowlists, can be exploited to redirect principals to attacker-controlled sites. By eliminating the redirect entirely, this specification removes an entire class of attack surface.

2. **Transport-Agnostic Channel Support:**
   This specification is designed to work over *any* text channel—chat, SMS, email, QR codes, push notifications, in-band messaging—without assumptions about channel security or authentication. The channel itself need not be encrypted or verified. Because no secrets traverse the text channel, its trustworthiness is immaterial.

3. **No Secrets Over Untrusted Transport:**
   The JWT token in the delegation URL is signed but deliberately non-secret. It contains only identity information (agent_id, session_id) and request context (host, path, scopes), all of which are safe to share via an unsecured channel. No authentication credentials, authorization codes, or other secrets flow through the text channel.

4. **Identity Separation and Prevention of Impersonation:**
   The agent's identity (agent_cookie) is set directly by the HTTPS API server when it issues the delegation response, establishing identity through a secure channel. The approver's identity is managed by the authorization website using whatever authentication method the website employs (SSO, password, 2FA, etc.). Neither the agent nor the principal requires authentication over the text channel:
   - The agent cannot impersonate a principal because the agent_cookie is set by the server (not by the agent itself).
   - The principal cannot impersonate an agent because the principal authenticates to the authorization website to approve, while the agent authenticates to the API only after the grant is in place.

5. **Simple, Reliable Manual Confirmation:**
   After granting permission, the principal simply notifies the agent to retry—e.g., "done, try again now" via the same text channel. This avoids complex redirect logic, stateful tracking of outstanding redirects, and the entire risk of redirect injection or redirect URI poisoning.

**Comparison with OAuth 2.0/OIDC:**

| Aspect | OAuth/OIDC | Delegated Access Token |
|---|---|---|
| **Redirect mechanism** | Agent provides `redirect_uri`; server redirects back to agent after grant | No redirect; principal tells agent to retry |
| **Transport assumptions** | Assumes secure channel (HTTPS); vulnerable to open redirect if validation is weak | Makes no assumptions; works over any channel (secure or unsecured) |
| **Secrets in URL** | Authorization code (exchanged server-side for tokens) | JWT is signed but not secret; safe to share |
| **Redirect validation** | Must validate `redirect_uri` against allowlist; vulnerable to allowlist bypass | No URI validation needed; eliminates entire attack class |
| **Agent identity** | Can be impersonated if `client_id` is treated as public | Set directly by HTTPS API; cannot be impersonated over unsecured channel |
| **User confirmation** | Automatic via redirect (implicit consent) | Explicit; principal tells agent to retry |
| **Channel security requirement** | HTTPS required (redirect could leak tokens) | Any channel; no secrets in URL |

**Trade-offs:**

- **Convenience:** OAuth/OIDC automatically redirects the user back without manual action. This specification requires the principal to explicitly notify the agent to retry. In practice, this is a one-line message to the same channel that delivered the authorization URL, so the friction is minimal.
- **Flexibility:** The cost of eliminating redirect attacks is paid in simplicity. The specification gains the ability to work over *any* communication channel and avoids validating URIs, which is a well-known hard problem in security.

---

**End of Specification**
