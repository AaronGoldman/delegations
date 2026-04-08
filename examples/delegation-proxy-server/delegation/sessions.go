package delegation

import (
	_ "embed"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"strings"
)

// SessionsServer handles all human-facing UI endpoints:
// GET  /delegations/ask   — delegation approval form
// POST /delegations/grant — process the approval form
// GET  /delegations       — list active delegations
// GET  /delegations/key   — returns the public key for verifying X-Delegation headers
// POST /delegations/revoke — revoke a delegation
type SessionsServer struct {
	DelegationURLSecret    []byte
	IdDerivationSecret     string
	DelegationHeaderPubKey ed25519.PublicKey
	Store                  DelegationStore
}

var tmplFuncs = template.FuncMap{
	"join": strings.Join,
	"toJSON": func(v any) (string, error) {
		b, err := json.MarshalIndent(v, "", "  ")
		return string(b), err
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

// hostScopeOptions returns the selectable host scope levels for a given host
// pattern, ordered from narrowest (exact) to broadest (widest wildcard).
// Examples:
//
//	"staging.localhost:8080"     → ["staging.localhost:8080", "*.localhost:8080"]
//	"sub.example.com"           → ["sub.example.com", "*.example.com"]
//	"a.b.example.com"           → ["a.b.example.com", "*.b.example.com", "*.example.com"]
func hostScopeOptions(host string) []string {
	// Separate port so it doesn't fuse with the last label during splitting.
	hostname, port, hasPort := strings.Cut(host, ":")
	portSuffix := ""
	if hasPort {
		portSuffix = ":" + port
	}

	base := hostname
	if strings.HasPrefix(base, "*.") {
		base = base[2:]
	}
	labels := strings.Split(base, ".")
	options := []string{host}
	for i := 1; i < len(labels); i++ {
		// For multi-label domains (3+ labels) skip the bare-TLD level (e.g. "*.com").
		// For short dev host names like "staging.localhost" (2 labels), allow "*.localhost".
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

// pathScopeOptions returns the selectable path scope levels for a given path
// pattern, ordered from narrowest (exact) to broadest (/*).
// Example: "/a/b/c" → ["/a/b/c", "/a/b/*", "/a/*", "/*"]
func pathScopeOptions(path string) []string {
	if path == "" {
		return nil
	}
	normalized := path
	if strings.HasSuffix(normalized, "/*") {
		normalized = normalized[:len(normalized)-2]
	}
	if normalized == "" {
		normalized = "/"
	}
	var segments []string
	if normalized != "/" {
		for _, s := range strings.Split(normalized, "/") {
			if s != "" {
				segments = append(segments, s)
			}
		}
	}
	options := []string{path}
	for i := len(segments) - 1; i >= 0; i-- {
		prefix := "/" + strings.Join(segments[:i], "/")
		var w string
		if prefix == "/" {
			w = "/*"
		} else {
			w = prefix + "/*"
		}
		seen := false
		for _, o := range options {
			if o == w {
				seen = true
				break
			}
		}
		if !seen {
			options = append(options, w)
		}
	}
	hasStar := false
	for _, o := range options {
		if o == "/*" {
			hasStar = true
			break
		}
	}
	if !hasStar {
		options = append(options, "/*")
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
		HostOptions: hostScopeOptions(d.HostPattern),
		PathOptions: pathScopeOptions(d.PathPattern),
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
	duration := r.FormValue("duration")

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

	switch duration {
	case "once", "session", "agent":
		// valid
	default:
		http.Error(w, "invalid duration", http.StatusBadRequest)
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

	// Apply user-selected scope overrides (broader than what the JWT requested).
	if hp := r.FormValue("host_pattern"); hp != "" {
		valid := false
		for _, o := range hostScopeOptions(claims.HostPattern) {
			if o == hp {
				valid = true
				break
			}
		}
		if !valid {
			http.Error(w, "invalid host_pattern", http.StatusBadRequest)
			return
		}
		claims.HostPattern = hp
	}
	if pp := r.FormValue("path_pattern"); pp != "" {
		valid := false
		for _, o := range pathScopeOptions(claims.PathPattern) {
			if o == pp {
				valid = true
				break
			}
		}
		if !valid {
			http.Error(w, "invalid path_pattern", http.StatusBadRequest)
			return
		}
		claims.PathPattern = pp
	}

	claims.DelegationID = NewUUIDv4()
	claims.PrincipalID  = principalID
	claims.Duration     = duration

	if err := s.Store.AddDelegation(*claims); err != nil {
		log.Printf("ERROR AddDelegation: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("GRANT agent=%s session=%s %s %s%s duration=%s delegation=%s",
		claims.AgentID, claims.SessionID,
		strings.Join(claims.Methods, ","), claims.HostPattern, claims.PathPattern,
		claims.Duration, claims.DelegationID)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(grantedPage)
}

// ── /sessions — active grants list ───────────────────────────────────────────

//go:embed pages/sessions.template.html
var sessionsHTML string

var sessionsTemplate = template.Must(template.New("sessions").Funcs(tmplFuncs).Parse(sessionsHTML))

type sessionsPageData struct {
	Grants    []Delegation
	CSRFToken string
}

func (s *SessionsServer) listGrants(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
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
	if err := sessionsTemplate.Execute(w, sessionsPageData{Grants: delegations, CSRFToken: csrfToken}); err != nil {
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

// RegisterHandlers registers all SessionsServer handlers into the given mux.
// This includes /delegations/ask, /delegations/grant, /delegations, /delegations/key,
// and /delegations/revoke endpoints.
func (s *SessionsServer) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/delegations/ask", s.showGrantUI)
	mux.HandleFunc("/delegations/grant", s.processGrant)
	mux.HandleFunc("/delegations", s.listGrants)
	mux.HandleFunc("/delegations/key", s.getPublicKey)
	mux.HandleFunc("/delegations/revoke", s.revokeGrant)
}
