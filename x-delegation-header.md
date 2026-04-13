# Delegation Bearer Token Specification

**Editor:** Aaron Goldman
**Repository:** https://github.com/AaronGoldman/delegations

## Abstract

This specification defines how a delegation middleware proxy communicates an approved delegation to a protected API endpoint using the standard `Authorization: Bearer` header with EdDSA (Ed25519) signed JWT tokens. While the [Delegated Access Token](delegated-access-token.md) specification handles principal approval of delegations via browser-based UI, this specification addresses the orthogonal problem: once a delegation is approved and stored, how does the proxy prove to the endpoint that the delegation is valid?

The delegation bearer token uses EdDSA (Ed25519) signatures to enable stateless, cryptographically verified delegation tokens without requiring the endpoint to query a database or shared state.

---

## 1. Overview

### 1.1 The Problem

A proxy middleware must:
1. Check if a stored delegation permits the request
2. Communicate the delegation to the protected endpoint
3. Do so without the endpoint needing access to the delegation store

### 1.2 The Solution

The proxy:
1. Verifies the request against stored delegations (using [Delegated Access Token](delegated-access-token.md) matching rules)
2. Signs the approved delegation as a compact EdDSA JWT
3. Sets the `X-Delegation` header with the signed JWT
4. Forwards the request to the endpoint

The endpoint:
1. Reads the `X-Delegation` header
2. Verifies the EdDSA signature using the proxy's public key
3. Extracts delegation details (agent_id, session_id, scopes, etc.)
4. Uses this information for logging, audit, or secondary authorization

---

## 2. JWT Format

The X-Delegation header contains a compact serialized EdDSA JWT.

### 2.1 Header

```json
{
  "alg": "EdDSA",
  "typ": "JWT"
}
```

Base64url-encoded: `eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9`

### 2.2 Payload

The payload is the full **Delegation** object (as defined in delegated-access-token.md §6.1), serialized to JSON and base64url-encoded.

```json
{
  "agent_id": "550e8400-e29b-41d4-a716-446655440000",
  "session_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
  "principal_id": "user-456",
  "host": "api.example.com",
  "path": "/users/123/messages",
  "methods": ["GET"],
  "scopes": ["READ_DM"],
  "breadth": "session",
  "iat": 1708344000,
  "expires_at": "2026-02-19T10:15:00Z"
}
```

### 2.3 Signature

The signature is computed using Ed25519:

```
signature = Ed25519_sign(
    private_key,
    base64url(header) || "." || base64url(payload)
)
```

The final token is:
```
X-Delegation: base64url(header).base64url(payload).base64url(signature)
```

---

## 3. Proxy Behavior

### 3.1 Authorization Check

When a request arrives with agent_cookie and session_cookie:

1. Derive agent_id and session_id from cookies (per delegated-access-token.md §6.2)
2. Query the delegation store for active delegations matching the request
3. If a matching delegation is found, proceed to §3.2
4. If no match is found, return 401 + delegation_url (delegated-access-token.md §4)

### 3.2 Setting Authorization Header

```pseudocode
if delegation matches request:
    token = Ed25519_sign(private_key, delegation)
    request.headers["Authorization"] = "Bearer " + token
    
    // For "once" breadth, revoke after setting header
    if delegation.breadth == "once":
        store.revokeDelegation(delegation.delegation_id)
    
    forward_request_to_endpoint(request)
```

---

## 4. Endpoint Behavior

### 4.1 GetAuthInfo Function

The endpoint library provides a function to extract and verify delegation from the Authorization header:

```go
func GetAuthInfo(r *http.Request, pubKey ed25519.PublicKey) *Delegation {
    auth := r.Header.Get("Authorization")
    if auth == "" {
        return nil  // No Authorization header
    }
    
    // Extract token from "Bearer <token>"
    parts := strings.SplitN(auth, " ", 2)
    if len(parts) != 2 || parts[0] != "Bearer" {
        return nil  // Invalid Authorization header format
    }
    token := parts[1]
    
    d, err := DelegationFromSignedJWT(pubKey, token)
    if err != nil {
        return nil  // Invalid signature or malformed token
    }
    
    return d
}
```

### 4.2 Usage in Handlers

```go
func myHandler(w http.ResponseWriter, r *http.Request, pubKey ed25519.PublicKey) {
    delegation := GetAuthInfo(r, pubKey)
    if delegation == nil {
        http.Error(w, "no valid delegation", http.StatusUnauthorized)
        return
    }
    
    // Use delegation.AgentID, delegation.SessionID, delegation.Scopes, etc.
    log.Printf("Request from agent %s with scopes %v", 
        delegation.AgentID, delegation.Scopes)
    
    // Handle the request...
}
```

---

## 5. Security Considerations

### 5.1 Signature Verification

- MUST use Ed25519 signature verification with constant-time comparison
- MUST reject tokens with invalid signatures
- MUST reject expired tokens (check `expires_at` field)

### 5.2 Public Key Distribution

The endpoint MUST obtain the proxy's Ed25519 public key through a secure, out-of-band channel:

- Configuration file or environment variable
- PKI certificate chain
- Key rotation with overlap windows (see delegated-access-token.md A.1.1)

Do NOT fetch public keys dynamically without verification.

### 5.3 Token Replay Prevention

The delegation bearer token provides no replay prevention. If replay attacks are a concern:

- Use a nonce stored in the delegation store
- Track used tokens and reject duplicates within a time window
- Combine with request signing (e.g., sign the HTTP method + path in the token)

### 5.4 No Secrets in JWT

The X-Delegation JWT contains no secrets—only signed identity information:
- agent_id, session_id, principal_id (all IDs, not secrets)
- host, path, methods, scopes (request context)
- iat, expires_at (timestamps)

This is safe to log, forward, and store in non-secret backends.

---

## 6. Token Lifecycle

### 6.1 Issuance

The proxy issues an X-Delegation token when forwarding an authorized request:
1. A delegation from the store matches the request
2. The proxy signs the delegation
3. The proxy sets the X-Delegation header
4. The proxy forwards the request

### 6.2 Expiration

The token expires at the delegation's `expires_at` timestamp. The endpoint MUST check this field and reject expired tokens.

### 6.3 Revocation

If a delegation is revoked in the store:
- The proxy will no longer issue X-Delegation tokens for that delegation
- Previously issued tokens remain valid until `expires_at`
- No revocation list or callback mechanism exists (stateless design)

If immediate revocation is required, use a shorter TTL or implement a revocation list in the endpoint.

---

## 7. Implementation Example

### 7.1 Go Implementation

```go
package delegation

import (
    "crypto/ed25519"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "net/http"
    "strings"
)

// DelegationFromSignedJWT verifies the Ed25519 signature and returns the delegation
func DelegationFromSignedJWT(pubKey ed25519.PublicKey, token string) (*Delegation, error) {
    parts := strings.SplitN(token, ".", 3)
    if len(parts) != 3 {
        return nil, fmt.Errorf("malformed token")
    }
    
    // Verify signature
    sig, err := base64.RawURLEncoding.DecodeString(parts[2])
    if err != nil {
        return nil, fmt.Errorf("decode signature: %w", err)
    }
    
    signingInput := parts[0] + "." + parts[1]
    if !ed25519.Verify(pubKey, []byte(signingInput), sig) {
        return nil, fmt.Errorf("invalid signature")
    }
    
    // Decode payload
    payload, err := base64.RawURLEncoding.DecodeString(parts[1])
    if err != nil {
        return nil, fmt.Errorf("decode payload: %w", err)
    }
    
    var d Delegation
    if err := json.Unmarshal(payload, &d); err != nil {
        return nil, fmt.Errorf("unmarshal: %w", err)
    }
    
    return &d, nil
}

// GetAuthInfo reads and verifies the Authorization: Bearer header
func GetAuthInfo(r *http.Request, pubKey ed25519.PublicKey) *Delegation {
    auth := r.Header.Get("Authorization")
    if auth == "" {
        return nil
    }
    
    // Extract token from "Bearer <token>"
    parts := strings.SplitN(auth, " ", 2)
    if len(parts) != 2 || parts[0] != "Bearer" {
        return nil
    }
    token := parts[1]
    
    d, err := DelegationFromSignedJWT(pubKey, token)
    if err != nil {
        return nil  // Log error in production
    }
    return d
}
```

---

## 8. Comparison with Alternatives

| Approach | Secrets in Token | Revocation | Endpoint Complexity | Notes |
|---|---|---|---|---|
| **X-Delegation JWT (this spec)** | No | Soft (TTL-based) | Low | Stateless, cryptographically verified |
| **Opaque token + DB lookup** | No | Hard (immediate) | Medium | Requires endpoint to query delegation store |
| **OAuth 2.0 token introspection** | No | Hard (via introspection) | Medium | Requires endpoint to call authorization server |
| **Mutual TLS** | Yes | Hard | High | Requires client certificates |

**X-Delegation JWT is optimal for:** Stateless architectures where the endpoint cannot query the delegation store and TTL-based revocation is acceptable.

---

**End of Specification**
