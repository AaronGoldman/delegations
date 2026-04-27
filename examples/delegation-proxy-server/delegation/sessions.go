package delegation

import (
	"crypto/ed25519"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"
)

// SessionsServer handles all human-facing UI endpoints for delegation approval:
// GET  /delegations/ask          — show delegation approval form (breadth + TTL selection)
// POST /delegations/grant        — process the approval form
// GET  /delegations              — list active delegations
// GET  /delegations/key          — returns the Ed25519 public key for verifying Authorization: Bearer headers
// POST /delegations/revoke       — revoke a delegation
// GET  /delegations/self-service — prove key ownership + create a self-granted delegation
// POST /delegations/self-service — process the self-service form
type SessionsServer struct {
	DelegationURLSecret    []byte
	IdDerivationSecret     string
	DelegationHeaderPubKey ed25519.PublicKey
	Store                  DelegationStore
	ScopeStore             PrincipalScopeStore // stores principal-owned did:key scopes
	ScopeAuthorizer        ScopeAuthorizer     // validates principal authorization for requested scopes
}

var tmplFuncs = template.FuncMap{
	"join": strings.Join,
	"toJSON": func(v any) (string, error) {
		b, err := json.MarshalIndent(v, "", "  ")
		return string(b), err
	},
	"timeRemaining": func(expiresAt string) string {
		t, err := time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			return "unknown"
		}
		remaining := time.Until(t)
		if remaining <= 0 {
			return "expired"
		}

		// Format as "Xd Yh Zm" or simplify for short durations
		days := int(remaining.Hours()) / 24
		hours := int(remaining.Hours()) % 24
		minutes := int(remaining.Minutes()) % 60

		if days > 0 {
			return fmt.Sprintf("%dd %dh", days, hours)
		} else if hours > 0 {
			return fmt.Sprintf("%dh %dm", hours, minutes)
		} else {
			return fmt.Sprintf("%dm", minutes)
		}
	},
}

// ── /delegate — grant approval UI ────────────────────────────────────────────

//go:embed pages/delegate.template.html
var delegateHTML string

var delegateTemplate = template.Must(template.New("delegate").Funcs(tmplFuncs).Parse(delegateHTML))

//go:embed pages/deny.template.html
var denyPage []byte

//go:embed pages/granted.template.html
var grantedPage []byte

// delegatePageData is a Delegation (from the JWT) plus the two fields only
// needed by the approval form: the raw JWT token and the CSRF token.
type delegatePageData struct {
	Delegation
	Token       string
	CSRFToken   string
	HostOptions []string // ordered from narrowest to broadest
	PathOptions []string // ordered from narrowest to broadest
}

// hostExpansionOptions returns progressively broader wildcard host patterns,
// ordered from narrowest (exact) to broadest (widest wildcard).
// Examples:
//
//	"staging.localhost:8080"     → ["staging.localhost:8080", "*.localhost:8080"]
//	"sub.example.com"           → ["sub.example.com", "*.example.com"]
//	"a.b.example.com"           → ["a.b.example.com", "*.b.example.com", "*.example.com"]
func hostExpansionOptions(host string) []string {
	hostname, port, hasPort := strings.Cut(host, ":")
	portSuffix := ""
	if hasPort {
		portSuffix = ":" + port
	}

	base := strings.TrimPrefix(hostname, "*.")
	labels := strings.Split(base, ".")
	options := []string{host}

	// Generate wildcard variants (skip bare TLD for 3+ labels)
	for i := 1; i < len(labels); i++ {
		if i == len(labels)-1 && len(labels) > 2 {
			break
		}
		w := "*." + strings.Join(labels[i:], ".") + portSuffix
		if w != host {
			options = append(options, w)
		}
	}
	return options
}

// pathExpansionOptions returns progressively broader wildcard path patterns,
// ordered from narrowest (exact) to broadest (/*).
// Example: "/a/b/c" → ["/a/b/c", "/a/b/*", "/a/*", "/*"]
func pathExpansionOptions(path string) []string {
	if path == "" {
		return nil
	}

	// Normalize: remove trailing "/" and "/*", handle root case
	norm := strings.TrimSuffix(path, "/*")
	norm = strings.TrimSuffix(norm, "/")
	if norm == "" {
		norm = "/"
	}

	// Split into segments, skipping empty
	var segments []string
	if norm != "/" {
		for _, s := range strings.Split(norm, "/") {
			if s != "" {
				segments = append(segments, s)
			}
		}
	}

	options := []string{path}
	seen := map[string]bool{path: true}

	// If path doesn't already end with /*, add that as an option
	if !strings.HasSuffix(path, "/*") && norm != "/" {
		pathWithWildcard := norm + "/*"
		if !seen[pathWithWildcard] {
			options = append(options, pathWithWildcard)
			seen[pathWithWildcard] = true
		}
	}

	// Generate wider wildcard patterns by replacing trailing segments with "/*"
	for i := len(segments) - 1; i >= 0; i-- {
		prefix := "/" + strings.Join(segments[:i], "/")
		w := prefix + "/*"
		if prefix == "/" {
			w = "/*"
		}
		if !seen[w] {
			options = append(options, w)
			seen[w] = true
		}
	}

	return options
}

// showGrantUI handles GET /delegate?token=...
func (s *SessionsServer) showGrantUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token parameter", http.StatusBadRequest)
		return
	}
	claims, err := DelegationFromJWT(s.DelegationURLSecret, token)
	if err != nil {
		http.Error(w, "invalid or expired delegation token: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Issue or refresh the principal_cookie — identifies the human approving the grant.
	principalVal := NewUUIDv4()
	if c, _ := r.Cookie(principalCookieName); c != nil {
		principalVal = c.Value
	}
	http.SetCookie(w, &http.Cookie{
		Name:     principalCookieName,
		Value:    principalVal,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   365 * 24 * 60 * 60, // 1 year, refreshed on each visit
	})
	principalID, err := deriveID(s.IdDerivationSecret, principalVal)
	if err != nil {
		log.Printf("ERROR deriveID(principal): %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	csrfToken, err := RandomHex(16)
	if err != nil {
		log.Printf("ERROR generating CSRF token: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   600, // 10 minutes, matches spec's 5–15 min window
	})

	d := *claims
	d.PrincipalID = principalID
	data := delegatePageData{
		Delegation:  d,
		Token:       token,
		CSRFToken:   csrfToken,
		HostOptions: hostExpansionOptions(d.HostPattern),
		PathOptions: pathExpansionOptions(d.PathPattern),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := delegateTemplate.Execute(w, data); err != nil {
		log.Printf("ERROR rendering delegate template: %v", err)
	}
}

// processGrant handles POST /grant.
func (s *SessionsServer) processGrant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// CSRF double-submit validation.
	csrfC, _ := r.Cookie("csrf_token")
	csrfForm := r.FormValue("csrf_token")
	if csrfC == nil || csrfC.Value != csrfForm {
		http.Error(w, "CSRF validation failed", http.StatusForbidden)
		return
	}

	token := r.FormValue("token")
	action := r.FormValue("action")
	breadth := r.FormValue("breadth")
	ttl := r.FormValue("ttl")

	claims, err := DelegationFromJWT(s.DelegationURLSecret, token)
	if err != nil {
		http.Error(w, "invalid or expired delegation token: "+err.Error(), http.StatusBadRequest)
		return
	}

	if action == "deny" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(denyPage)
		return
	}
	if action != "approve" {
		http.Error(w, "invalid action", http.StatusBadRequest)
		return
	}

	switch breadth {
	case "once", "session", "agent":
		// valid
	default:
		http.Error(w, "invalid breadth", http.StatusBadRequest)
		return
	}

	switch ttl {
	case "4h", "2d", "90d", "400d", "indefinite":
		// valid
	default:
		http.Error(w, "invalid ttl", http.StatusBadRequest)
		return
	}

	var principalVal string
	if c, _ := r.Cookie(principalCookieName); c != nil {
		principalVal = c.Value
	}
	principalID, err := deriveID(s.IdDerivationSecret, principalVal)
	if err != nil {
		log.Printf("ERROR deriveID(principal): %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Determine the requested host and path patterns (original if not overridden)
	requestedHostPattern := claims.HostPattern
	requestedPathPattern := claims.PathPattern

	// Apply user-selected wildcard overrides (broader than what the JWT requested).
	if hp := r.FormValue("host_pattern"); hp != "" {
		valid := false
		for _, o := range hostExpansionOptions(claims.HostPattern) {
			if o == hp {
				valid = true
				break
			}
		}
		if !valid {
			http.Error(w, "invalid host_pattern", http.StatusBadRequest)
			return
		}
		requestedHostPattern = hp
	}
	if pp := r.FormValue("path_pattern"); pp != "" {
		valid := false
		for _, o := range pathExpansionOptions(claims.PathPattern) {
			if o == pp {
				valid = true
				break
			}
		}
		if !valid {
			http.Error(w, "invalid path_pattern", http.StatusBadRequest)
			return
		}
		requestedPathPattern = pp
	}

	// Validate that the principal is authorized to delegate these scopes.
	if s.ScopeAuthorizer != nil {
		authorized, reason, err := s.ScopeAuthorizer.AuthorizeScopes(
			principalID, claims.Scopes,
			claims.HostPattern, claims.PathPattern,
			requestedHostPattern, requestedPathPattern,
		)
		if err != nil {
			log.Printf("ERROR AuthorizeScopes: %v", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if !authorized {
			log.Printf("DENIED principal=%s host=%s path=%s requested_host=%s requested_path=%s: %s",
				principalID, claims.HostPattern, claims.PathPattern, requestedHostPattern, requestedPathPattern, reason)
			http.Error(w, "not authorized: "+reason, http.StatusForbidden)
			return
		}
	}

	// Apply the validated patterns to the delegation
	claims.HostPattern = requestedHostPattern
	claims.PathPattern = requestedPathPattern

	claims.DelegationID = NewUUIDv4()
	claims.PrincipalID = principalID
	claims.Breadth = breadth

	if err := s.Store.AddDelegation(*claims); err != nil {
		log.Printf("ERROR AddDelegation: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("GRANT agent=%s session=%s %s %s%s breadth=%s delegation=%s",
		claims.AgentID, claims.SessionID,
		strings.Join(claims.Methods, ","), claims.HostPattern, claims.PathPattern,
		claims.Breadth, claims.DelegationID)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(grantedPage)
}

// ── /sessions — active grants list ───────────────────────────────────────────

//go:embed pages/sessions.template.html
var sessionsHTML string

var sessionsTemplate = template.Must(template.New("sessions").Funcs(tmplFuncs).Parse(sessionsHTML))

type sessionsPageData struct {
	PrincipalID string
	Grants      []Delegation
	CSRFToken   string
}

func (s *SessionsServer) listGrants(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract principal ID from cookie
	principalID := ""
	if c, _ := r.Cookie(principalCookieName); c != nil {
		if id, err := deriveID(s.IdDerivationSecret, c.Value); err == nil {
			principalID = id
		}
	}

	csrfToken, err := RandomHex(16)
	if err != nil {
		log.Printf("ERROR generating CSRF token: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "sessions_csrf",
		Value:    csrfToken,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   600,
	})

	delegations, err := s.Store.ListDelegations()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := sessionsTemplate.Execute(w, sessionsPageData{PrincipalID: principalID, Grants: delegations, CSRFToken: csrfToken}); err != nil {
		log.Printf("ERROR rendering sessions template: %v", err)
	}
}

// ── /revoke — revoke a grant ──────────────────────────────────────────────────

func (s *SessionsServer) revokeGrant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	csrfC, _ := r.Cookie("sessions_csrf")
	csrfForm := r.FormValue("csrf_token")
	if csrfC == nil || csrfC.Value != csrfForm {
		http.Error(w, "CSRF validation failed", http.StatusForbidden)
		return
	}

	delegationID := r.FormValue("delegation_id")
	if delegationID == "" {
		http.Error(w, "missing delegation_id", http.StatusBadRequest)
		return
	}

	if err := s.Store.RevokeDelegation(delegationID); err != nil {
		log.Printf("ERROR RevokeDelegation(%s): %v", delegationID, err)
		http.Error(w, "delegation not found", http.StatusNotFound)
		return
	}

	log.Printf("REVOKE delegation=%s", delegationID)
	http.Redirect(w, r, "/delegations", http.StatusSeeOther)
}

// getPublicKey handles GET /delegations/key.
func (s *SessionsServer) getPublicKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("ed25519-" + hex.EncodeToString(s.DelegationHeaderPubKey)))
}

// ── /delegations/scopes — principal did:key scope management ────────────────

//go:embed pages/scopes.template.html
var scopesHTML string

var selfServiceTemplate = template.Must(template.New("self-service").Funcs(tmplFuncs).Parse(scopesHTML))

type selfServicePageData struct {
	PrincipalID string
	AgentID     string
	Scopes      []string
	CSRFToken   string
	Error       string
}

// scopeClaimPayload is the JWT payload of a self-issued scope claim signed by a did:key.
type scopeClaimPayload struct {
	Host     string   `json:"host"`
	Path     string   `json:"path"`
	Scopes   []string `json:"scopes"`
	IssuedAt int64    `json:"iat"`
}

// verifyScopeClaimJWT verifies a self-signed JWT where the first scope is a did:key.
// The JWT must be signed by the private key corresponding to that did:key, proving
// the submitter controls the key. Returns the verified did:key on success.
func verifyScopeClaimJWT(token string) (string, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("malformed JWT (expected 3 parts)")
	}
	// Decode the payload before signature verification to extract the did:key.
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode payload: %w", err)
	}
	var payload scopeClaimPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return "", fmt.Errorf("unmarshal payload: %w", err)
	}
	if len(payload.Scopes) == 0 {
		return "", fmt.Errorf("no scopes in payload")
	}
	didKey := payload.Scopes[0]
	pubKey, err := ParseDIDKey(didKey)
	if err != nil {
		return "", fmt.Errorf("parse did:key: %w", err)
	}
	// Now verify the signature with the extracted public key.
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("decode signature: %w", err)
	}
	signingInput := parts[0] + "." + parts[1]
	if !ed25519.Verify(pubKey, []byte(signingInput), sig) {
		return "", fmt.Errorf("invalid signature")
	}
	// Reject tokens that are too old or issued in the future (prevents replay).
	iat := time.Unix(payload.IssuedAt, 0)
	age := time.Since(iat)
	if age < -30*time.Second || age > 5*time.Minute {
		return "", fmt.Errorf("token age %v is outside the ±5 minute window", age.Round(time.Second))
	}
	return didKey, nil
}

// selfServiceHandler dispatches GET/POST /delegations/self-service.
func (s *SessionsServer) selfServiceHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.showSelfService(w, r)
	case http.MethodPost:
		s.processSelfService(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// showSelfService handles GET /delegations/self-service.
func (s *SessionsServer) showSelfService(w http.ResponseWriter, r *http.Request) {
	// Issue or refresh agent_cookie — identifies this device.
	agentVal := NewUUIDv4()
	if c, _ := r.Cookie(agentCookieName); c != nil {
		agentVal = c.Value
	}
	http.SetCookie(w, &http.Cookie{
		Name:     agentCookieName,
		Value:    agentVal,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   365 * 24 * 60 * 60,
		Path:     "/",
	})
	agentID, err := deriveID(s.IdDerivationSecret, agentVal)
	if err != nil {
		log.Printf("ERROR deriveID(agent): %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	// Issue or refresh session_cookie.
	sessionVal := NewUUIDv4()
	if c, _ := r.Cookie(sessionCookieName); c != nil {
		sessionVal = c.Value
	}
	setSessionCookie(w, sessionVal)
	// Issue or refresh principal_cookie — identifies the human.
	principalVal := NewUUIDv4()
	if c, _ := r.Cookie(principalCookieName); c != nil {
		principalVal = c.Value
	}
	http.SetCookie(w, &http.Cookie{
		Name:     principalCookieName,
		Value:    principalVal,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   365 * 24 * 60 * 60,
	})
	principalID, err := deriveID(s.IdDerivationSecret, principalVal)
	if err != nil {
		log.Printf("ERROR deriveID(principal): %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	csrfToken, err := RandomHex(16)
	if err != nil {
		log.Printf("ERROR generating CSRF token: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "scopes_csrf",
		Value:    csrfToken,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   600,
	})
	scopes, err := s.ScopeStore.GetPrincipalScopes(principalID)
	if err != nil {
		log.Printf("ERROR GetPrincipalScopes: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := selfServiceTemplate.Execute(w, selfServicePageData{
		PrincipalID: principalID,
		AgentID:     agentID,
		Scopes:      scopes,
		CSRFToken:   csrfToken,
	}); err != nil {
		log.Printf("ERROR rendering self-service template: %v", err)
	}
}

// processSelfService handles POST /delegations/self-service.
func (s *SessionsServer) processSelfService(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// CSRF double-submit validation.
	csrfC, _ := r.Cookie("scopes_csrf")
	csrfForm := r.FormValue("csrf_token")
	if csrfC == nil || csrfC.Value != csrfForm {
		http.Error(w, "CSRF validation failed", http.StatusForbidden)
		return
	}
	// Require principal cookie.
	principalVal := ""
	if c, _ := r.Cookie(principalCookieName); c != nil {
		principalVal = c.Value
	}
	if principalVal == "" {
		http.Error(w, "no principal cookie — visit /delegations/self-service first", http.StatusUnauthorized)
		return
	}
	principalID, err := deriveID(s.IdDerivationSecret, principalVal)
	if err != nil {
		log.Printf("ERROR deriveID(principal): %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	// Require agent cookie.
	agentVal := ""
	if c, _ := r.Cookie(agentCookieName); c != nil {
		agentVal = c.Value
	}
	if agentVal == "" {
		http.Error(w, "no agent cookie — visit /delegations/self-service first", http.StatusUnauthorized)
		return
	}
	agentID, err := deriveID(s.IdDerivationSecret, agentVal)
	if err != nil {
		log.Printf("ERROR deriveID(agent): %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	// Session ID (may be empty for breadth=agent grants).
	sessionID := ""
	if c, _ := r.Cookie(sessionCookieName); c != nil {
		if sid, serr := deriveID(s.IdDerivationSecret, c.Value); serr == nil {
			sessionID = sid
		}
	}
	// Verify the self-signed JWT and extract the did:key.
	jwtToken := r.FormValue("jwt")
	if jwtToken == "" {
		http.Error(w, "missing jwt field", http.StatusBadRequest)
		return
	}
	didKey, err := verifyScopeClaimJWT(jwtToken)
	if err != nil {
		log.Printf("REJECT self-service principal=%s: %v", principalID, err)
		http.Error(w, "invalid scope claim JWT: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Register the did:key scope on the principal.
	if err := s.ScopeStore.AddPrincipalScope(principalID, didKey); err != nil {
		log.Printf("ERROR AddPrincipalScope: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	// Validate grant fields.
	hostPattern := strings.TrimSpace(r.FormValue("host_pattern"))
	pathPattern := strings.TrimSpace(r.FormValue("path_pattern"))
	methods := r.Form["methods"]
	breadth := r.FormValue("breadth")
	ttl := r.FormValue("ttl")
	if hostPattern == "" || pathPattern == "" {
		http.Error(w, "host_pattern and path_pattern are required", http.StatusBadRequest)
		return
	}
	if len(methods) == 0 {
		http.Error(w, "at least one method is required", http.StatusBadRequest)
		return
	}
	validMethods := map[string]bool{
		"GET": true, "HEAD": true, "POST": true, "PUT": true,
		"PATCH": true, "DELETE": true, "OPTIONS": true,
	}
	for _, m := range methods {
		if !validMethods[m] {
			http.Error(w, "invalid method: "+m, http.StatusBadRequest)
			return
		}
	}
	switch breadth {
	case "once", "session", "agent":
	default:
		http.Error(w, "invalid breadth", http.StatusBadRequest)
		return
	}
	var expiresAt string
	switch ttl {
	case "4h":
		expiresAt = time.Now().Add(4 * time.Hour).UTC().Format(time.RFC3339)
	case "2d":
		expiresAt = time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	case "90d":
		expiresAt = time.Now().Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339)
	case "400d":
		expiresAt = time.Now().Add(400 * 24 * time.Hour).UTC().Format(time.RFC3339)
	case "indefinite":
		expiresAt = ""
	default:
		http.Error(w, "invalid ttl", http.StatusBadRequest)
		return
	}
	// Create and store the delegation.
	d := Delegation{
		DelegationID: NewUUIDv4(),
		PrincipalID:  principalID,
		AgentID:      agentID,
		SessionID:    sessionID,
		HostPattern:  hostPattern,
		PathPattern:  pathPattern,
		Methods:      methods,
		Scopes:       []string{didKey},
		Breadth:      breadth,
		IssuedAt:     time.Now().Unix(),
		ExpiresAt:    expiresAt,
	}
	if err := s.Store.AddDelegation(d); err != nil {
		log.Printf("ERROR AddDelegation: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	log.Printf("SELF-SERVICE principal=%s agent=%s did:key=%s %s %s%s breadth=%s delegation=%s",
		principalID, agentID, didKey,
		strings.Join(methods, ","), hostPattern, pathPattern,
		breadth, d.DelegationID)
	http.Redirect(w, r, "/delegations/self-service", http.StatusSeeOther)
}

// RegisterHandlers registers all SessionsServer handlers into the given mux.
// This includes /delegations/ask, /delegations/grant, /delegations, /delegations/key,
// /delegations/revoke, and /delegations/scopes endpoints.
func (s *SessionsServer) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/delegations/ask", s.showGrantUI)
	mux.HandleFunc("/delegations/grant", s.processGrant)
	mux.HandleFunc("/delegations", s.listGrants)
	mux.HandleFunc("/delegations/key", s.getPublicKey)
	mux.HandleFunc("/delegations/revoke", s.revokeGrant)
	mux.HandleFunc("/delegations/self-service", s.selfServiceHandler)
}
