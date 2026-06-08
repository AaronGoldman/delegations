# Delegation Formats and Proposals

**Editor:** Aaron Goldman  
**Repository:** https://github.com/AaronGoldman/delegations  

## Abstract

This document defines our proposed formats and concrete data schemas for cookies, identity derivation, and authorization URL requests under the [Delegated Access Token Specification](delegated-access-token.md). It outlines:
* The format of `agent_cookie` and `session_cookie`
* Cryptographic derivation of stable client IDs via UUIDv5
* The JWT token payload structure embedded in the `delegation_url`
* Safe cookie handling practices and robust key rotation algorithms

---

## 1. Cookie Formats and Security Guidelines

To establish identity across calls while keeping client credentials separate from application logic, the service uses two cookies:

### 1.1 `agent_cookie`
* **Purpose:** Identifies a persistent, long-lived agent instance.
* **Format:** UUIDv4 string (e.g., `550e8400-e29b-41d4-a716-446655440000`).
* **Lifetime:** Persistent (typically 1 year max-age).
* **Security Attributes:** `HttpOnly; Secure; SameSite=Lax; Max-Age=31536000; Path=/`

### 1.2 `session_cookie`
* **Purpose:** Identifies the current interactive or transient session.
* **Format:** UUIDv4 string (e.g., `6ba7b810-9dad-11d1-80b4-00c04fd430c8`).
* **Lifetime:** Session-scoped (no Max-Age or Expires; cleared when the browser or HTTP tool session terminates).
* **Security Attributes:** `HttpOnly; Secure; SameSite=Strict; Path=/`

### 1.3 HttpOnly Isolation Requirements

> [!IMPORTANT]
> The HTTP tool used by the agent MUST store and present `HttpOnly` cookies in outgoing requests automatically, but it **MUST NOT** expose `HttpOnly` cookie values to the agent's application code, prompt logs, or debug logs. 
> 
> Hiding the entire `Cookie` header from client-accessible buffers prevents any credential leakage due to application-level vulnerabilities or accidental prompt injection.

---

## 2. Identity Derivation using UUIDv5

To prevent the agent or external systems from learning the raw cookie values (which act as bearer secrets), the server MUST NOT use the cookies directly as identifiers. Instead, the server derives deterministic, opaque identifiers (`agent_id` and `session_id`) using **UUIDv5** with a private namespace/secret.

```python
import uuid

# Server-side derivation
agent_id   = uuid.uuid5(server_secret, agent_cookie)
session_id = uuid.uuid5(server_secret, session_cookie)
```

### Benefits:
1. **Privacy:** The agent only sees derived IDs (e.g., in JWTs) and never the actual raw cookie secret.
2. **Stateless Verification:** The server or proxy can verify identity ownership deterministically without a database lookup.
3. **Impersonation Prevention:** An attacker who discovers an `agent_id` cannot construct the `agent_cookie` because UUIDv5 is a one-way cryptographic hash.

---

## 3. JWT Payload Format in `delegation_url`

When an unauthorized request is rejected, the server returns a signed JWT token inside the `delegation_url` (`https://auth.example.com/delegate?token={jwt}`). The token is signed using HMAC-SHA256 (or stronger) using a private server secret.

### 3.1 Example Payload

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

### 3.2 Payload Schema

| Claim | Type | Description |
|---|---|---|
| `agent_id` | UUID (string) | **REQUIRED.** The derived agent identifier (UUIDv5 of the `agent_cookie`). |
| `session_id` | UUID (string) | **REQUIRED.** The derived session identifier (UUIDv5 of the `session_cookie`). |
| `host` | string | **REQUIRED.** The target host from the rejected request (e.g., `api.example.com`). |
| `path` | string | **REQUIRED.** The absolute path from the rejected request (e.g., `/users/123/messages`). |
| `methods` | array[string] | **REQUIRED.** List of HTTP methods required (e.g., `["GET", "POST"]`). |
| `scopes` | array[string] | **REQUIRED.** Application-specific scopes needed for access (e.g., `["READ_DM"]`). |
| `ttl` | array[string] | **OPTIONAL.** Ordered list of suggested grant lifetimes (e.g. `["4h", "2d", "90d", "400d"]`). The first item is the pre-selected default in the UI. If omitted, the UI defaults to `["4h", "2d", "90d", "400d"]`. |
| `expires_at` | string (ISO 8601) | **REQUIRED.** The expiration time of this delegation request (typically 5–15 minutes from issue). |
| `iat` | integer (Unix epoch) | **REQUIRED.** The time when the request token was issued. |

---

## 4. Key Rotation with Overlap Window

To ensure that rotating the server secret does not invalidate existing sessions or break ongoing delegation requests, implementations SHOULD validate cookie and JWT signatures against both the *current* secret and the *previous* secret within an overlap window.

### 4.1 Validation Algorithm

```python
import uuid

def verify_agent(token_agent_id, agent_cookie, current_secret, previous_secret):
    # 1. Try the current validation secret
    if str(uuid.uuid5(current_secret, agent_cookie)) == token_agent_id:
        return "Validated (Current)"

    # 2. Try the previous validation secret
    if previous_secret and str(uuid.uuid5(previous_secret, agent_cookie)) == token_agent_id:
        return "Validated (Previous)"

    return "Invalid"
```

### 4.2 Key Rotation Lifecycle Steps:
1. **Generate** a new secret key.
2. **Shift** the current secret to `previous_secret` and set the new key as `current_secret`.
3. **Sign** all *new* cookies and JWTs using the `current_secret`.
4. **Validate** incoming requests against both keys.
5. **Retire** the `previous_secret` after a grace period corresponding to the maximum session lifetime (e.g., 30 days).
