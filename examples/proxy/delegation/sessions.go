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
	"slices"
	"sort"
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
	ScopeAuthorizer        ScopeAuthorizer // validates principal authorization for requested scopes
	ClaimHost              string          // host pattern for group-claim delegations (default "127.0.0.1")
	ClaimPath              string          // path pattern for group-claim delegations (default "/delegations/")
}

var tmplFuncs = template.FuncMap{
	"join": strings.Join,
	"eq":   func(a, b any) bool { return a == b },
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
	Token          string
	CSRFToken      string
	PatternOptions []string // ordered from narrowest to broadest
}

// hostExpansionOptions returns progressively broader wildcard host patterns,
// ordered from narrowest (exact) to broadest (widest wildcard).
// The canonical wildcard is a dot-prefix (e.g. ".example.com").
// Examples:
//
//	"staging.localhost:8080" → ["staging.localhost:8080", ".localhost:8080"]
//	"sub.example.com"        → ["sub.example.com", ".example.com"]
//	"a.b.example.com"        → ["a.b.example.com", ".b.example.com", ".example.com"]
func hostExpansionOptions(host string) []string {
	hostname, port, hasPort := strings.Cut(host, ":")
	portSuffix := ""
	if hasPort {
		portSuffix = ":" + port
	}

	// A concrete host never starts with a wildcard prefix; strip one (legacy "*." or
	// canonical ".") defensively so expanding an already-wildcard host still works.
	base := strings.TrimPrefix(hostname, "*.")
	base = strings.TrimPrefix(base, ".")
	labels := strings.Split(base, ".")
	options := []string{host}

	// Generate canonical dot-prefix wildcard variants (skip bare TLD for 3+ labels)
	for i := 1; i < len(labels); i++ {
		if i == len(labels)-1 && len(labels) > 2 {
			break
		}
		w := "." + strings.Join(labels[i:], ".") + portSuffix
		if w != host {
			options = append(options, w)
		}
	}
	return options
}

// pathExpansionOptions returns progressively broader path patterns, using a
// trailing slash for path-prefix wildcards.
// Example: "/a/b/c" → ["/a/b/c", "/a/b/", "/a/", "/"]
func pathExpansionOptions(path string) []string {
	if path == "" {
		return nil
	}

	// Normalize legacy path/* syntax to path/.
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

	initial := path
	if strings.HasSuffix(path, "/*") {
		initial = norm + "/"
		if norm == "/" {
			initial = "/"
		}
	}
	options := []string{initial}
	seen := map[string]bool{initial: true}

	// Generate wider prefix patterns by removing trailing path segments.
	for i := len(segments) - 1; i >= 1; i-- {
		prefix := "/" + strings.Join(segments[:i], "/") + "/"
		if !seen[prefix] {
			options = append(options, prefix)
			seen[prefix] = true
		}
	}
	if !seen["/"] {
		options = append(options, "/")
	}

	return options
}

// patternExpansionOptions returns combined host/path patterns ordered from
// narrowest to broadest, preserving each dimension's existing expansion order.
func patternExpansionOptions(pattern string) []string {
	host, path := splitPattern(pattern)
	hostOptions := hostExpansionOptions(host)
	pathOptions := pathExpansionOptions(path)
	options := make([]string, 0, len(hostOptions)*len(pathOptions))
	seen := make(map[string]bool)
	for _, hostOption := range hostOptions {
		for _, pathOption := range pathOptions {
			option := joinPattern(hostOption, pathOption)
			if !seen[option] {
				options = append(options, option)
				seen[option] = true
			}
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
	claims.Pattern = normalizePattern(claims.Pattern)

	// Use agent_cookie to identify the principal (human approving the grant).
	// The agent_cookie is set by the middleware and persists across sessions.
	agentVal := ""
	if c, _ := r.Cookie("agent_cookie"); c != nil {
		agentVal = c.Value
	} else {
		agentVal = NewUUIDv4()
		http.SetCookie(w, &http.Cookie{
			Name:     "agent_cookie",
			Value:    agentVal,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			Path:     "/",
			MaxAge:   365 * 24 * 60 * 60, // 1 year
		})
	}
	principalID, err := deriveID(s.IdDerivationSecret, agentVal)
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
		Delegation:     d,
		Token:          token,
		CSRFToken:      csrfToken,
		PatternOptions: patternExpansionOptions(d.Pattern),
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

	// Use agent_cookie to derive principal ID
	agentVal := ""
	if c, _ := r.Cookie("agent_cookie"); c != nil {
		agentVal = c.Value
	}
	principalID, err := deriveID(s.IdDerivationSecret, agentVal)
	if err != nil {
		log.Printf("ERROR deriveID(principal): %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Determine the requested host and path pattern (original if not overridden).
	requestedPattern := normalizePattern(claims.Pattern)
	if submittedPattern := strings.TrimSpace(r.FormValue("pattern")); submittedPattern != "" {
		valid := false
		for _, option := range patternExpansionOptions(claims.Pattern) {
			if option == submittedPattern {
				valid = true
				break
			}
		}
		if !valid {
			http.Error(w, "invalid pattern", http.StatusBadRequest)
			return
		}
		requestedPattern = submittedPattern
	}
	requestedHostPattern, requestedPathPattern := splitPattern(requestedPattern)
	originalHostPattern, originalPathPattern := requestedHostPattern, requestedPathPattern

	// Validate that the principal is authorized to delegate these scopes.
	if s.ScopeAuthorizer != nil {
		authorized, reason, err := s.ScopeAuthorizer.AuthorizeScopes(
			principalID, claims.Scopes, r.Host,
			originalHostPattern, originalPathPattern,
			requestedHostPattern, requestedPathPattern,
		)
		if err != nil {
			log.Printf("ERROR AuthorizeScopes: %v", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if !authorized {
			log.Printf("DENIED principal=%s host=%s path=%s requested_host=%s requested_path=%s: %s",
				principalID, originalHostPattern, originalPathPattern, requestedHostPattern, requestedPathPattern, reason)
			http.Error(w, "not authorized: "+reason, http.StatusForbidden)
			return
		}
	}

	// Apply the validated patterns to the delegation
	claims.Pattern = joinPattern(requestedHostPattern, requestedPathPattern)

	claims.DelegationID = NewUUIDv4()
	claims.PrincipalID = principalID
	claims.Breadth = breadth

	if err := s.Store.AddDelegation(*claims); err != nil {
		log.Printf("ERROR AddDelegation: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("GRANT agent=%s session=%s %s %s breadth=%s delegation=%s",
		claims.AgentID, claims.SessionID,
		strings.Join(claims.Methods, ","), claims.Pattern,
		claims.Breadth, claims.DelegationID)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(grantedPage)
}

func (s *SessionsServer) claimHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.showClaimForm(w, r)
	case http.MethodPost:
		s.processClaim(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *SessionsServer) showClaimForm(w http.ResponseWriter, r *http.Request) {
	csrfToken, err := RandomHex(16)
	if err != nil {
		log.Printf("ERROR generating CSRF token: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "claim_csrf",
		Value:    csrfToken,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   600,
	})

	principalID := ""
	if c, _ := r.Cookie("agent_cookie"); c != nil {
		if id, err := deriveID(s.IdDerivationSecret, c.Value); err == nil {
			principalID = id
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := claimTemplate.Execute(w, claimPageData{PrincipalID: principalID, CSRFToken: csrfToken}); err != nil {
		log.Printf("ERROR rendering claim template: %v", err)
	}
}

func (s *SessionsServer) processClaim(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	csrfC, _ := r.Cookie("claim_csrf")
	csrfForm := r.FormValue("csrf_token")
	if csrfC == nil || csrfC.Value != csrfForm {
		http.Error(w, "CSRF validation failed", http.StatusForbidden)
		return
	}

	groupName := strings.TrimSpace(r.FormValue("group_name"))
	if !IsValidGroupName(groupName) {
		http.Error(w, "invalid group name", http.StatusBadRequest)
		return
	}

	scope := GroupScope(groupName)

	principalID := ""
	agentID := ""
	if c, _ := r.Cookie("agent_cookie"); c != nil {
		if id, err := deriveID(s.IdDerivationSecret, c.Value); err == nil {
			principalID = id
			agentID = id
		}
	}
	if principalID == "" || agentID == "" {
		http.Error(w, "agent identity required", http.StatusUnauthorized)
		return
	}

	delegations, err := s.Store.FindDelegationsByScope(scope)
	if err != nil {
		log.Printf("ERROR FindDelegationsByScope: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	for _, d := range delegations {
		if d.PrincipalID != principalID {
			http.Error(w, "group already claimed", http.StatusConflict)
			return
		}
	}

	sessionID := ""
	if c, _ := r.Cookie(sessionCookieName); c != nil {
		if sid, err := deriveID(s.IdDerivationSecret, c.Value); err == nil {
			sessionID = sid
		}
	}
	if sessionID == "" {
		sessionID = agentID
	}

	d := Delegation{
		DelegationID: NewUUIDv4(),
		PrincipalID:  principalID,
		AgentID:      agentID,
		SessionID:    sessionID,
		Pattern:      joinPattern(s.ClaimHost, s.ClaimPath),
		Methods:      []string{"GET", "POST"},
		Scopes:       []string{scope},
		Breadth:      "agent",
		IssuedAt:     time.Now().Unix(),
		ExpiresAt:    "",
	}
	if err := s.Store.AddDelegation(d); err != nil {
		log.Printf("ERROR AddDelegation: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("CLAIM group=%s principal=%s agent=%s delegation=%s", scope, principalID, agentID, d.DelegationID)
	http.Redirect(w, r, "/delegations", http.StatusSeeOther)
}

// ── /sessions — active grants list ───────────────────────────────────────────

//go:embed pages/sessions.template.html
var sessionsHTML string

//go:embed pages/claim.template.html
var claimHTML string

var sessionsTemplate = template.Must(template.New("sessions").Funcs(tmplFuncs).Parse(sessionsHTML))
var claimTemplate = template.Must(template.New("claim").Funcs(tmplFuncs).Parse(claimHTML))

type sessionTab struct {
	ID     string
	Label  string
	Grants []Delegation
}

type sessionsPageData struct {
	PrincipalID      string
	AuthorizedGroups []string
	Tabs             []sessionTab
	ActiveTab        string
	CSRFToken        string
}

type claimPageData struct {
	PrincipalID string
	CSRFToken   string
	GroupName   string
	Error       string
}

func groupClaimScopes(delegations []Delegation, agentID, claimHost, claimPath string) []string {
	set := make(map[string]struct{})
	for _, d := range delegations {
		if d.AgentID != agentID {
			continue
		}
		if d.Pattern != joinPattern(claimHost, claimPath) {
			continue
		}
		for _, scope := range d.Scopes {
			if strings.HasPrefix(scope, GroupScopePrefix) {
				set[scope] = struct{}{}
			}
		}
	}

	scopes := make([]string, 0, len(set))
	for scope := range set {
		scopes = append(scopes, scope)
	}
	sort.Strings(scopes)
	return scopes
}

func hasScope(scopes []string, target string) bool {
	for _, scope := range scopes {
		if scope == target {
			return true
		}
	}
	return false
}

func (s *SessionsServer) listGrants(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	principalID := ""
	agentID := ""
	if c, _ := r.Cookie("agent_cookie"); c != nil {
		if id, err := deriveID(s.IdDerivationSecret, c.Value); err == nil {
			principalID = id
			agentID = id
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

	authorizedGroups := groupClaimScopes(delegations, agentID, s.ClaimHost, s.ClaimPath)

	tabs := []sessionTab{
		{ID: "from_me", Label: "From me", Grants: nil},
		{ID: "to_me", Label: "To me", Grants: nil},
		{ID: "from_session", Label: "From session", Grants: nil},
		{ID: "to_session", Label: "To session", Grants: nil},
	}
	groupTabs := make(map[string]*sessionTab, len(authorizedGroups))
	for _, scope := range authorizedGroups {
		id := strings.ReplaceAll(scope, ":", "_")
		id = strings.ReplaceAll(id, "/", "_")
		tabs = append(tabs, sessionTab{ID: id, Label: scope, Grants: nil})
		groupTabs[scope] = &tabs[len(tabs)-1]
	}

	for _, d := range delegations {
		if d.AgentID == d.PrincipalID {
			tabs[0].Grants = append(tabs[0].Grants, d)
		}
		if d.AgentID == agentID {
			tabs[1].Grants = append(tabs[1].Grants, d)
		}
		if d.SessionID == d.PrincipalID {
			tabs[2].Grants = append(tabs[2].Grants, d)
		}
		if d.SessionID == agentID {
			tabs[3].Grants = append(tabs[3].Grants, d)
		}
		for _, scope := range authorizedGroups {
			if d.Pattern != joinPattern(s.ClaimHost, s.ClaimPath) {
				continue
			}
			if hasScope(d.Scopes, scope) {
				groupTabs[scope].Grants = append(groupTabs[scope].Grants, d)
			}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := sessionsTemplate.Execute(w, sessionsPageData{
		PrincipalID:      principalID,
		AuthorizedGroups: authorizedGroups,
		Tabs:             tabs,
		ActiveTab:        "to_me",
		CSRFToken:        csrfToken,
	}); err != nil {
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
	if c, _ := r.Cookie("agent_cookie"); c != nil {
		agentVal = c.Value
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "agent_cookie",
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
	// Derive principal ID from agent_cookie (already have agentVal from above)
	principalID, err := deriveID(s.IdDerivationSecret, agentVal)
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
	// Fetch did:key scopes from delegations
	delegations, err := s.Store.ListDelegations()
	if err != nil {
		log.Printf("ERROR ListDelegations: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	var scopes []string
	for _, d := range delegations {
		if d.PrincipalID == principalID {
			for _, scope := range d.Scopes {
				if strings.HasPrefix(scope, "did:key:") && !slices.Contains(scopes, scope) {
					scopes = append(scopes, scope)
				}
			}
		}
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
	// Get principal ID from agent_cookie.
	var agentVal string
	if c, _ := r.Cookie("agent_cookie"); c != nil {
		agentVal = c.Value
	}
	if agentVal == "" {
		http.Error(w, "no agent cookie — visit /delegations/self-service first", http.StatusUnauthorized)
		return
	}
	principalID, err := deriveID(s.IdDerivationSecret, agentVal)
	if err != nil {
		log.Printf("ERROR deriveID(principal): %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	// agentID is the same as principalID (unified from agent_cookie)
	agentID := principalID
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
	// Validate grant fields.
	pattern := strings.TrimSpace(r.FormValue("pattern"))
	hostPattern, pathPattern := splitPattern(pattern)
	methods := r.Form["methods"]
	breadth := r.FormValue("breadth")
	ttl := r.FormValue("ttl")
	if hostPattern == "" || pathPattern == "/" && pattern == "" {
		http.Error(w, "pattern is required", http.StatusBadRequest)
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
		Pattern:      joinPattern(hostPattern, pathPattern),
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
	log.Printf("SELF-SERVICE principal=%s agent=%s did:key=%s %s %s breadth=%s delegation=%s",
		principalID, agentID, didKey,
		strings.Join(methods, ","), joinPattern(hostPattern, pathPattern),
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
	mux.HandleFunc("/delegations/claim", s.claimHandler)
	mux.HandleFunc("/delegations/key", s.getPublicKey)
	mux.HandleFunc("/delegations/revoke", s.revokeGrant)
	mux.HandleFunc("/delegations/self-service", s.selfServiceHandler)
}
