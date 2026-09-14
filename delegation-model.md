# Delegation Model Specification

This document outlines the delegation authorization model used in this system, particularly how host-based access control works.

## Host-Based Authorization Rules

### Localhost Access (127.0.0.1/::1)
When making requests to localhost addresses (127.0.0.1 or ::1), the system allows broader delegation capabilities:

- **Full Domain Access**: Users can delegate scopes for any domain, not just the specific host
- **Flexible Patterns**: No restrictions on path patterns when targeting localhost
- **Development Convenience**: This relaxed model supports development workflows where users need to access various resources

### External Hosts (Non-localhost)
When making requests to external hosts (non-127.x.x.x or non-::1 addresses):

- **Domain-Specific Scopes**: Users can only delegate scopes they already have on the target domain
- **Authorization Boundaries**: The system enforces that delegation grants cannot exceed existing permissions
- **Security Boundary**: This prevents privilege escalation by requiring users to prove their existing access

## Path Pattern Enforcement

### Special Endpoints
Certain endpoints require specific path patterns:

#### `/code/` Endpoint
- **Required Pattern**: `/code/`
- **Reason**: This endpoint proxies requests to a VS Code server and needs to match all sub-paths under `/code/`
- **Example**: 
  - ✅ Correct: Grant path pattern = `/code/`
  - ❌ Incorrect: Grant path pattern = `/code`

### General Path Pattern Rules
- Path patterns must be explicitly defined when granting access
- A trailing `/` grants the subtree: `/code/` covers `/code` and every sub-path past the `/`
- A path without a trailing `/` matches exactly and nothing more
- The system validates that requested paths match the granted patterns

## Scope Authorization Flow

1. **Request**: Agent makes request to protected endpoint
2. **Authentication**: System checks if agent has valid delegation token
3. **Authorization**:
   - For localhost: Full access based on delegation grant
   - For external hosts: Must have existing scope for that domain
4. **Grant Validation**: 
   - Path patterns are validated against the delegation grant
   - Scopes must match between request and grant

## Example Usage

### Localhost Request (Relaxed Model)
```
GET http://127.0.0.1:8080/api/whoami
→ Can use any valid scope pattern since this is localhost
```

### External Host Request (Strict Model)  
```
GET https://api.example.com/users/123
→ Must have existing scopes for api.example.com
→ Delegation grant must match the domain and path pattern
```

## Security Considerations

The delegation system implements a layered security model:
- **Localhost**: Development convenience with relaxed access rules
- **External Hosts**: Strict authorization boundaries to prevent privilege escalation
- **Path Matching**: Ensures precise control over resource access