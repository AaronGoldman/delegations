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

	store := delegation.NewInMemoryDelegationStore()
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
//	1. GET /api/whoami (no cookies) → 401 + delegation_url
//	2. GET /delegations/ask?token=…    → HTML grant approval form
//	3. POST /delegations/grant         → grant created, "Access Granted" page
//	4. GET /delegations                → HTML page listing the new grant with a Revoke button
//	5. GET /api/whoami (with cookies) → 200 with full identity JSON
//	6. POST /delegations/revoke        → grant revoked, redirect to /delegations
//	7. GET /api/whoami              → 401 again (grant is gone)
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
		"duration":   {"session"},
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
