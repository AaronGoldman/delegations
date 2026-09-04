# Delegated Access Token Specification

**Editor:** Aaron Goldman  
**Repository:** https://github.com/AaronGoldman/delegations  

## Abstract

Recognize: To know again. The core idea is to set a cookie on first touch and then grant capabilities to that recognizable agent.

This specification defines a **Principal-Agent Delegation** mechanism for AI agents and automated systems. A *principal* is the human (or trusted system) who authorizes access; an *agent* is the automated system acting on the principal's behalf. The specification enables agents to request access to protected resources through principal-mediated browser-based authorization, without requiring the agent to handle the principal's credentials directly. The core flow uses HttpOnly cookies, RFC 7807-compliant error responses, and delegated access loop mechanisms to provide secure, auditable, and principal-controlled authorization.

---

## 1. Prerequisites

The agent and principal environments MUST meet these requirements:

* **Cookie Jar:** The agent MUST be able to preserve a cookie jar across HTTP requests.
* **Cookie Segregation:** The agent MUST be able to clear session cookies distinctly from persistent agent cookies.
* **Standard Expirations:** The agent's HTTP tool should treat cookies without an expiration date as session cookies.
* **Browser Session:** The principal MUST have an active or authenticatable browser session.

---

## 2. Specification Scope

This core specification defines:
* The overall authentication protocol (the 5-step delegation process).
* Cookie boundary handling requirements (agent cookies, session cookies).
* The roles and interactions between Agent, Principal, and Server.
* Multi-user-agent delegation mechanics (using the `delegation_url` on a different browser user-agent to delegate capabilities).
* The RFC 7807 `application/problem+json` error response structure for delegation requests.

### Out of Scope

> [!NOTE]
> * **Cookie & URL Formats:** This specification does **NOT** define the internal formats of the cookies or the parameters encoded inside the `delegation_url`. For our proposed implementation schemas, see [Delegation Formats Proposal](delegation-formats-proposal.md).
> * **Reverse Proxy & ACLs:** This specification does **NOT** define the database schemas, matching algorithms, or self-service registration endpoints of the access-checking gateway. For these proxy implementation details, see [Reverse Proxy Specification](reverse-proxy-spec.md).

---

## 3. The Core Flow

The protocol leverages a multi-user-agent pattern where an agent receives authentication cookies and a delegation URL, hands off authorization to the principal's browser, and retries the request once the principal grants capabilities.

### 3.1 Quick Start

1. **Rejected Access:** The agent attempts to access a protected web API.
   * The server rejects the request.
   * The server sets an `agent_cookie` and a `session_cookie`.
   * The server returns a `delegation_url` in the error response payload.
2. **Handoff:** The agent sends the `delegation_url` to the principal (e.g., via a chat interface, link, or QR code).
3. **Delegation:** The principal opens the `delegation_url` in their web browser.
   * The server displays a consent/grant UI.
   * The principal actively grants the requested capabilities.
4. **Notification:** The principal notifies the agent to retry the operation.
5. **Retry:** The agent retries the API request using its cookie jar.
   * The server authorizes the request and responds with a successful HTTP status code.

### 3.2 Communication Diagram

```
┌───────┐                    ┌───────────┐                   ┌────────┐
│ Agent │                    │ Principal │                   │ Server │
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

### 3.3 HTTP Trace Example

#### Step 1: Agent tries to access API
```http
GET /api/users/123/messages HTTP/1.1
Host: api.example.com
User-Agent: MyAgent/1.0
Accept: application/json
```

#### Step 2: Server rejects with cookies and delegation URL
```http
HTTP/1.1 401 Unauthorized
Content-Type: application/problem+json
Set-Cookie: agent_cookie=550e8400-e29b-41d4-a716-446655440000; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000; Path=/
Set-Cookie: session_cookie=6ba7b810-9dad-11d1-80b4-00c04fd430c8; HttpOnly; Secure; SameSite=Strict; Path=/
Cache-Control: no-store

{
  "type": "https://github.com/aarongoldman/delegations#delegation-required",
  "delegation_url": "https://auth.example.com/delegate?token=1234567",
  "documentation_url": "https://api.example.com/docs/scopes"
}
```

#### Step 3: Agent presents the delegation URL to the principal
```python
print("Authorization required.")
print("Please visit: https://auth.example.com/delegate?token=eyJhbGci...")
```

#### Step 4–7: Principal opens delegation URL and approves capabilities
The principal interacts with the browser UI. The request is processed securely via `POST` with CSRF protection.

#### Step 8: Principal instructs the agent to retry
```bash
$ try now
```

#### Step 9: Agent retries API access using its cookie jar
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
      "content": "Hello! How are you?"
    }
  ]
}
```

---

## 4. RFC 7807 Problem+JSON Format

When an unauthorized agent accesses a protected resource, the server MUST respond with an RFC 7807-compliant `application/problem+json` payload.

### 4.1 Required Fields

* **`type`** (string, URI) - **REQUIRED**
  * A URI reference that identifies this specific delegation-required condition.
  * Fixed value: `"https://github.com/aarongoldman/delegations#delegation-required"`
* **`delegation_url`** (string, URL) - **REQUIRED**
  * The fully-qualified URL where the principal can log in and authorize the requested access.
* **`documentation_url`** (string, URL) - **REQUIRED**
  * A documentation link explaining the required scopes, risks, and permissions.

---

## 5. Capability Discovery via Help Parameters

To enable client agents and principals to interactively and programmatically query protected resources for their required capabilities and documentation (mirroring standard Unix CLI `-h` and `--help` flags), the server MUST support specialized help query parameters.

### 5.1 Query Parameters

Any API endpoint (whether public or protected) SHOULD support the following query parameters:
* **`h=1` (Short Help):** Designed for programmatic agent discovery. Returns a compact, structured JSON response detailing required scopes, allowed HTTP methods, and a brief description.
* **`help=true` (Long Help):** Designed for human review and detailed inspection. Returns a comprehensive documentation page (HTML or Markdown) detailing parameter schemas, payload examples, and edge cases.

### 5.2 Short Help (`?h=1`) Specifications

When a request is made to any URL with the `?h=1` parameter, the server MUST return a response containing structured help metadata. 
* If the agent is authenticated and possesses the required capabilities, the server returns a `200 OK` along with the capability descriptors.
* If the agent is unauthorized, the server returns a `401 Unauthorized` with the standard `application/problem+json` payload (per §4) including the structured help fields in the problem object or returning them in a standard format.

The JSON response for `h=1` MUST include the following fields:
* **`resource`** (string): The path pattern of the resource (e.g., `/api/users/123/messages`).
* **`methods`** (array of strings): The list of HTTP methods supported by the resource.
* **`scopes`** (array of strings): The list of scopes required to successfully invoke the resource.
* **`description`** (string): A short, single-sentence summary of the endpoint's functionality.

#### Example Short Help Response (`GET /api/users/123/messages?h=1`)

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "resource": "/api/users/123/messages",
  "methods": ["GET", "POST"],
  "scopes": ["READ_DM", "SEND_DM"],
  "description": "Retrieves and sends direct messages for the specified user."
}
```

### 5.3 Long Help (`?help=true`) Specifications

When a request is made to a URL with the `?help=true` parameter, the server SHOULD return a `200 OK` response with detailed documentation. 
* By default, it SHOULD return human-friendly HTML or Markdown.
* If the request includes `Accept: application/json`, the server MAY return an extended JSON schema detailing headers, query parameters, request schemas, and concrete response examples.

---

## 6. Security & Delegation Boundaries

### 6.1 Cookie-Based Authentication Decisions
The server uses the presence of the `agent_cookie` and `session_cookie` to recognize the requesting agent. When a request matches an active record in the server's database, the server makes an authorization decision based on the cookie combination: 
* If only the `agent_cookie` matches a permanent grant, the request succeeds.
* If a session-scoped grant is used, both `agent_cookie` and `session_cookie` MUST match for the request to succeed.

### 6.2 Browser Interaction & CSRF Rules

> [!CAUTION]
> **Active Consent Required**
> 
> Navigation to the `delegation_url` **MUST NOT** automatically grant permissions. Simply opening or pre-fetching a link does not constitute consent.
> * The `delegation_url` MUST load a visual user interface that lists the requested host, path, methods, and scopes.
> * The principal MUST explicitly interact with the UI (e.g., clicking "Approve") to perform a POST form submission.
> * The authorization POST endpoint MUST utilize CSRF protection mechanisms (e.g., anti-forgery tokens, SameSite cookies).

### 6.3 Handoff to Different User-Agents

Because AI agents typically run inside a text terminal, headless daemon, or background sandbox, they lack standard web browser capabilities (such as interactive HTML rendering or cookie management for identity providers).

The multi-user-agent delegation pattern addresses this by:
* Isolating the agent's identity (`agent_cookie` and `session_cookie` stored in its programmatic HTTP tool).
* Performing principal authentication and capability approval in a secure, fully-featured browser environment.
* Merging these capabilities back on the server side using the cookie-derived identifiers, removing any need for the agent to coordinate secrets or redirects.

---

## Appendix: Comparison with OAuth/OIDC Redirects

Unlike standard OAuth 2.0 or OpenID Connect (OIDC), this specification intentionally avoids using a direct redirect URI to return the user from the authorization site to the agent.

| Design Aspect | Standard OAuth 2.0 / OIDC | Delegated Access Token |
|---|---|---|
| **Return Loop** | Server performs automatic redirect to `redirect_uri` | Principal explicitly confirms completion (e.g., "try now") |
| **Transport** | Requires a secure, registered HTTPS callback URI | Transport-agnostic; works over chat, console, or QR codes |
| **Redirect Attack Surface** | Vulnerable to open-redirector bugs and bypasses | Completely eliminated; no redirects are evaluated |
| **Impersonation Risk** | Vulnerable to code injection if credentials traverse client | Cookies set directly via HTTPS; agent cannot steal principal credentials |

For a full analysis of standard OAuth comparisons, see [Appendix A.10 in the original project documentation].
