# To-Do List / Issues

## Bug: Cookie handling differs from RFC 6265 (Standard Web Browsers)

The custom `http` tool, which acts as an ambient authentication proxy, deviates from standard RFC 6265 cookie matching and scopes. This can cause issues with authenticating across subdomains or when path-based cookie restrictions are expected.

### 1. Subdomain / Domain Matching Mismatch
* **Standard Behavior (RFC 6265):** Cookies set with a `Domain` attribute (e.g. `Domain=example.com`) are valid for the domain and all of its subdomains (e.g. `api.example.com`).
* **Tool Behavior:** The database lookup (`store.Lookup`) queries strictly by the request's `origin` (`scheme://hostname`). This isolates cookies strictly by exact hostname. A cookie set by `https://example.com` with `Domain=example.com` will never be sent to `https://api.example.com`.

### 2. Path-Level Filtering Mismatch
* **Standard Behavior (RFC 6265):** Cookies set with a `Path` attribute (e.g. `Path=/api`) are only sent to requests matching that path prefix.
* **Tool Behavior:** The tool parses and saves the `Path` attribute but completely ignores it during lookup (`store.Lookup`). All cookies registered under the exact `origin` are injected regardless of whether the request path matches the cookie's `Path` parameter.

### Required Actions
- [ ] Implement RFC 6265 compliant cookie domain matching (e.g., match request host against cookie `domain` attribute using subdomain matching rules instead of strictly exact `origin` matching).
- [ ] Implement RFC 6265 compliant cookie path prefix matching (e.g., check request path against cookie `path` before injecting).
- [ ] Add unit tests specifically validating cookie domain/subdomain matching and path matching against standard RFC 6265 test cases.

## Self-Service Registration Endpoints

- [ ] Add a self-service endpoint to register a username.
- [ ] Add a self-service endpoint to register an email scope.


## dubble proxiy pattern 
agent <-local socet-> http tool <-http-> deligation roter <-back haul-> service

## rename the deligatoin example server proxie to sentinal gate.