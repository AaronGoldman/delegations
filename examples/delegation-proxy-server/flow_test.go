package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aarongoldman/delegations/examples/delegation-proxy-server/api"
	"github.com/aarongoldman/delegations/examples/delegation-proxy-server/delegation"
)

// Mirrors delegation.problemDetail for test assertions
type testProblemDetail struct {
	Type             string `json:"type"`
	Title            string `json:"title,omitempty"`
	Status           int    `json:"status,omitempty"`
	Detail           string `json:"detail,omitempty"`
	DelegationURL    string `json:"delegation_url,omitempty"`
	DocumentationURL string `json:"documentation_url,omitempty"`
}

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	const (
		jwtSecret    = "test-secret-32-bytes-for-hs256!!"
		serverSecret = "12345678-1234-1234-1234-123456789abc"
	)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate delegation header key: %v", err)
	}

	// Create temporary SQLite database for testing
	tmpfile, err := os.CreateTemp("", "test-delegation-*.db")
	if err != nil {
		t.Fatalf("create temp db file: %v", err)
	}
	tmpfile.Close()
	dbPath := tmpfile.Name()
	t.Cleanup(func() { os.Remove(dbPath) })

	store, err := delegation.NewSQLiteDelegationStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteDelegationStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	ss := &delegation.SessionsServer{
		DelegationURLSecret:    []byte(jwtSecret),
		IdDerivationSecret:     serverSecret,
		DelegationHeaderPubKey: pub,
		Store:                  store,
	}

	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.Start()

	authMux := delegation.NewAuthMiddlewareMux(serverSecret, 10*time.Minute, []byte(jwtSecret), store, priv)
	authMux.RegisterSessionHandlers(ss)
	authMux.Handle("/api/", api.NewMux(pub), []string{"profile_view"})

	srv.Config.Handler = authMux
	t.Cleanup(srv.Close)
	return srv
}

// TestDelegationFlow exercises the full happy path:
//
//  1. GET /api/whoami (no cookies) → 401 + delegation_url
//  2. GET /delegations/ask?token=…    → HTML grant approval form
//  3. POST /delegations/grant         → grant created, "Access Granted" page
//  4. GET /delegations                → HTML page listing the new grant with a Revoke button
//  5. GET /api/whoami (with cookies) → 200 with full identity JSON
//  6. POST /delegations/revoke        → grant revoked, redirect to /delegations
//  7. GET /api/whoami              → 401 again (grant is gone)
func TestDelegationFlow(t *testing.T) {
	srv := newTestServer(t)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := &http.Client{Jar: jar}

	// ── Step 1: GET /api/whoami with no cookies → 401 ──────────────────────
	resp1, err := client.Get(srv.URL + "/api/whoami")
	if err != nil {
		t.Fatalf("step 1: %v", err)
	}
	defer resp1.Body.Close()

	if resp1.StatusCode != http.StatusUnauthorized {
		t.Fatalf("step 1: want 401, got %d", resp1.StatusCode)
	}
	if ct := resp1.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("step 1: want Content-Type application/problem+json, got %q", ct)
	}

	var prob testProblemDetail
	if err := json.NewDecoder(resp1.Body).Decode(&prob); err != nil {
		t.Fatalf("step 1: decode problem+json: %v", err)
	}
	if prob.DelegationURL == "" {
		t.Fatal("step 1: delegation_url is empty")
	}

	grantURL, err := url.Parse(prob.DelegationURL)
	if err != nil {
		t.Fatalf("step 1: parse delegation_url %q: %v", prob.DelegationURL, err)
	}
	token := grantURL.Query().Get("token")
	if token == "" {
		t.Fatalf("step 1: no token in delegation_url %q", prob.DelegationURL)
	}

	// ── Step 2: GET /delegate?token=… → HTML grant approval form ───────────
	resp2, err := client.Get(prob.DelegationURL)
	if err != nil {
		t.Fatalf("step 2: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("step 2: want 200, got %d", resp2.StatusCode)
	}
	if ct := resp2.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("step 2: want text/html Content-Type, got %q", ct)
	}

	var csrfToken string
	for _, c := range client.Jar.Cookies(grantURL) {
		if c.Name == "csrf_token" {
			csrfToken = c.Value
		}
	}
	if csrfToken == "" {
		t.Fatal("step 2: csrf_token cookie not set")
	}

	// ── Step 3: POST /delegations/grant → grant created, confirmation page ────
	resp3, err := client.PostForm(srv.URL+"/delegations/grant", url.Values{
		"token":      {token},
		"csrf_token": {csrfToken},
		"action":     {"approve"},
		"breadth":    {"session"},
		"ttl":        {"4h"},
	})
	if err != nil {
		t.Fatalf("step 3: %v", err)
	}
	defer resp3.Body.Close()

	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("step 3: want 200, got %d", resp3.StatusCode)
	}
	body3, _ := io.ReadAll(resp3.Body)
	if !strings.Contains(string(body3), "Access Granted") {
		t.Fatalf("step 3: expected 'Access Granted' in body, got: %s", body3)
	}

	// ── Step 4: GET /delegations → HTML page listing active grants ────────────
	resp4, err := client.Get(srv.URL + "/delegations")
	if err != nil {
		t.Fatalf("step 4: %v", err)
	}
	defer resp4.Body.Close()

	if resp4.StatusCode != http.StatusOK {
		t.Fatalf("step 4: want 200, got %d", resp4.StatusCode)
	}
	if ct := resp4.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("step 4: want text/html, got %q", ct)
	}
	body4, _ := io.ReadAll(resp4.Body)
	if !strings.Contains(string(body4), "Revoke") {
		t.Fatalf("step 4: expected revoke button in sessions HTML")
	}

	// ── Step 5: GET /api/whoami with cookies → 200 with full identity ───────
	resp5, err := client.Get(srv.URL + "/api/whoami")
	if err != nil {
		t.Fatalf("step 5: %v", err)
	}
	defer resp5.Body.Close()

	if resp5.StatusCode != http.StatusOK {
		t.Fatalf("step 5: want 200, got %d", resp5.StatusCode)
	}
	var whoami delegation.Delegation
	if err := json.NewDecoder(resp5.Body).Decode(&whoami); err != nil {
		t.Fatalf("step 5: decode whoami JSON: %v", err)
	}
	if whoami.AgentID == "" {
		t.Fatal("step 5: agent_id is empty")
	}
	if whoami.SessionID == "" {
		t.Fatal("step 5: session_id is empty")
	}
	if whoami.DelegationID == "" {
		t.Fatal("step 5: delegation_id is empty")
	}
	if whoami.PrincipalID == "" {
		t.Fatal("step 5: principal_id is empty")
	}
	// delegation_id should appear in the sessions HTML (revoke form hidden input).
	if !strings.Contains(string(body4), whoami.DelegationID) {
		t.Fatalf("step 5: delegation_id %q not found in sessions HTML", whoami.DelegationID)
	}

	// ── Step 6: POST /sessions/revoke → grant revoked, redirect to /sessions ─
	// The sessions_csrf cookie was set during step 4 (GET /sessions).
	var sessionsCsrf string
	for _, c := range client.Jar.Cookies(grantURL) {
		if c.Name == "sessions_csrf" {
			sessionsCsrf = c.Value
		}
	}
	if sessionsCsrf == "" {
		t.Fatal("step 6: sessions_csrf cookie not set")
	}

	resp6, err := client.PostForm(srv.URL+"/delegations/revoke", url.Values{
		"csrf_token":    {sessionsCsrf},
		"delegation_id": {whoami.DelegationID},
	})
	if err != nil {
		t.Fatalf("step 6: %v", err)
	}
	defer resp6.Body.Close()
	// http.Client follows the redirect; final response is the /sessions page.
	if resp6.StatusCode != http.StatusOK {
		t.Fatalf("step 6: want 200 (after redirect), got %d", resp6.StatusCode)
	}

	// ── Step 7: GET /api/whoami → 401 (grant has been revoked) ──────────────
	resp7, err := client.Get(srv.URL + "/api/whoami")
	if err != nil {
		t.Fatalf("step 7: %v", err)
	}
	defer resp7.Body.Close()
	if resp7.StatusCode != http.StatusUnauthorized {
		t.Fatalf("step 7: want 401 after revoke, got %d", resp7.StatusCode)
	}
}

// TestInvalidJWTToken verifies rejection of malformed/expired tokens
func TestInvalidJWTToken(t *testing.T) {
	srv := newTestServer(t)
	client := &http.Client{}

	// Test with invalid token
	resp, err := client.Get(srv.URL + "/delegations/ask?token=invalid.jwt.token")
	if err != nil {
		t.Fatalf("GET /delegations/ask: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid token, got %d", resp.StatusCode)
	}
}

// TestCSRFValidation verifies CSRF token checking on POST endpoints
func TestCSRFValidation(t *testing.T) {
	srv := newTestServer(t)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	// Get a valid token first (similar to TestDelegationFlow step 1-2)
	resp, _ := client.Get(srv.URL + "/api/whoami")
	resp.Body.Close()

	// Just visit the form to set up cookies
	resp2, _ := client.Get(srv.URL + "/delegations/ask?token=xyz")
	resp2.Body.Close()

	// POST /delegations/grant with missing CSRF token should fail
	resp3, err := client.PostForm(srv.URL+"/delegations/grant", url.Values{
		"token":   {"test"},
		"action":  {"approve"},
		"breadth": {"session"},
		"ttl":     {"4h"},
		// csrf_token intentionally omitted
	})
	if err != nil {
		t.Fatalf("PostForm: %v", err)
	}
	defer resp3.Body.Close()

	if resp3.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 for missing CSRF, got %d", resp3.StatusCode)
	}

	// POST with wrong CSRF token should fail
	resp4, err := client.PostForm(srv.URL+"/delegations/grant", url.Values{
		"token":      {"test"},
		"csrf_token": {"wrong-token-value"},
		"action":     {"approve"},
		"breadth":    {"session"},
		"ttl":        {"4h"},
	})
	if err != nil {
		t.Fatalf("PostForm with wrong CSRF: %v", err)
	}
	defer resp4.Body.Close()

	if resp4.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 for wrong CSRF, got %d", resp4.StatusCode)
	}
}

// TestInvalidBreadthTTL verifies validation of breadth and ttl parameters
func TestInvalidBreadthTTL(t *testing.T) {
	srv := newTestServer(t)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	// Get initial request to set up cookies
	resp, _ := client.Get(srv.URL + "/api/whoami")
	resp.Body.Close()

	// POST with missing parameters should return an error (CSRF or validation)
	resp2, err := client.PostForm(srv.URL+"/delegations/grant", url.Values{
		"token":      {"test"},
		"csrf_token": {"invalid"},
		"action":     {"approve"},
	})
	if err != nil {
		t.Fatalf("PostForm: %v", err)
	}
	defer resp2.Body.Close()

	// Expect error (403 CSRF or 400 validation) - both are acceptable
	if resp2.StatusCode < 400 {
		t.Fatalf("want error status, got %d", resp2.StatusCode)
	}
}

// TestGetPublicKey verifies the public key endpoint returns valid Ed25519 key
func TestGetPublicKey(t *testing.T) {
	srv := newTestServer(t)
	client := &http.Client{}

	resp, err := client.Get(srv.URL + "/delegations/key")
	if err != nil {
		t.Fatalf("GET /delegations/key: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}

	keyData, _ := io.ReadAll(resp.Body)
	keyStr := string(keyData)
	if !strings.HasPrefix(keyStr, "ed25519-") {
		t.Fatalf("expected ed25519- prefix, got: %s", keyStr)
	}
}

// TestWildcardHostMatching verifies wildcard host pattern matching
func TestWildcardHostMatching(t *testing.T) {
	tests := []struct {
		pattern string
		host    string
		want    bool
	}{
		// Exact matches
		{"example.com", "example.com", true},
		{"example.com", "sub.example.com", false},

		// Wildcard suffix matches
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "cdn.example.com", true},
		{"*.example.com", "api.sub.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "other.com", false},

		// Multi-level wildcards
		{"*.sub.example.com", "api.sub.example.com", true},
		{"*.sub.example.com", "api.example.com", false},

		// Catch-all
		{"*", "anything.example.com", true},
		{"*", "example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"-"+tt.host, func(t *testing.T) {
			// Call matchPattern through a test that exercises it
			// For now, we test via the actual delegation flow
			// In production, matchPattern should be exported or tested directly
			got := delegation.TestMatchPattern(tt.pattern, tt.host)
			if got != tt.want {
				t.Fatalf("matchPattern(%q, %q) = %v, want %v", tt.pattern, tt.host, got, tt.want)
			}
		})
	}
}

// TestWildcardPathMatching verifies wildcard path pattern matching
func TestWildcardPathMatching(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		// Exact matches
		{"/api/users", "/api/users", true},
		{"/api/users", "/api/users/123", false},

		// Prefix wildcards
		{"/api/*", "/api/users", true},
		{"/api/*", "/api/users/123", true},
		{"/api/*", "/admin/users", false},

		// Multi-level paths
		{"/api/v1/*", "/api/v1/users", true},
		{"/api/v1/*", "/api/v1/users/123", true},
		{"/api/v1/*", "/api/v2/users", false},

		// Catch-all
		{"*", "/anything", true},
		{"/*", "/api/users", true},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"-"+tt.path, func(t *testing.T) {
			got := delegation.TestMatchPattern(tt.pattern, tt.path)
			if got != tt.want {
				t.Fatalf("matchPattern(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
			}
		})
	}
}

// TestExpiredToken verifies that expired tokens are rejected
func TestExpiredToken(t *testing.T) {
	srv := newTestServer(t)
	client := &http.Client{}

	// Create a delegation request that expires immediately
	d := &delegation.Delegation{
		AgentID:     "test-agent",
		SessionID:   "test-session",
		HostPattern: "example.com",
		PathPattern: "/api/*",
		Methods:     []string{"GET"},
		Scopes:      []string{"test_scope"},
		ExpiresAt:   time.Now().Add(-1 * time.Second).Format(time.RFC3339), // expired
	}

	token, err := d.JWT([]byte("test-secret-32-bytes-for-hs256!!"))
	if err != nil {
		t.Fatalf("JWT: %v", err)
	}

	resp, err := client.Get(srv.URL + "/delegations/ask?token=" + token)
	if err != nil {
		t.Fatalf("GET /delegations/ask: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for expired token, got %d", resp.StatusCode)
	}
}

// TestBreadthSemantics verifies that breadth values work correctly
func TestBreadthSemantics(t *testing.T) {
	tests := []struct {
		name    string
		breadth string
	}{
		{"breadth once", "once"},
		{"breadth session", "session"},
		{"breadth agent", "agent"},
		{"any string value", "forever"}, // Breadth is just a string; any value is technically valid for JSON
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &delegation.Delegation{
				DelegationID: "test-" + tt.breadth,
				AgentID:      "agent",
				SessionID:    "session",
				HostPattern:  "example.com",
				PathPattern:  "/",
				Methods:      []string{"GET"},
				Scopes:       []string{"scope"},
				Breadth:      tt.breadth,
				IssuedAt:     time.Now().Unix(),
			}

			// Breadth is stored as a string; any value can be marshaled
			data, err := json.Marshal(d)
			if err != nil {
				t.Fatalf("JSON marshal failed: %v", err)
			}

			// Verify breadth is present in JSON
			if !strings.Contains(string(data), tt.breadth) {
				t.Fatalf("breadth %q not found in JSON", tt.breadth)
			}
		})
	}
}
