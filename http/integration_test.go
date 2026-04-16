package main

import (
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/aarongoldman/delegations/http/cookies"
)

func TestCookieStorage(t *testing.T) {
	// Create a temporary database file
	tmpFile := "test_cookies.sqlite3"
	defer os.Remove(tmpFile)

	// Open the store
	store, err := cookies.Open(tmpFile)
	if err != nil {
		t.Fatalf("Failed to open store: %v", err)
	}
	defer store.Close()

	origin := "https://example.com"
	agent := "00000000-0000-0000-0000-000000000001"
	session1 := "00000000-0000-0000-0000-000000000002"
	session2 := "00000000-0000-0000-0000-000000000003"

	// Create a session cookie (no expires)
	sessionCookie := &http.Cookie{
		Name:     "session_id",
		Value:    "session_abc123",
		Path:     "/",
		Secure:   true,
		HttpOnly: false,
		SameSite: http.SameSiteStrictMode,
	}

	// Create a persistent cookie (with expires)
	persistentCookie := &http.Cookie{
		Name:     "persistent_token",
		Value:    "token_xyz789",
		Path:     "/",
		Secure:   true,
		HttpOnly: false,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(24 * time.Hour),
	}

	// Upsert both cookies
	err = store.Upsert(origin, agent, session1, sessionCookie)
	if err != nil {
		t.Fatalf("Failed to upsert session cookie: %v", err)
	}

	err = store.Upsert(origin, agent, session1, persistentCookie)
	if err != nil {
		t.Fatalf("Failed to upsert persistent cookie: %v", err)
	}

	// Lookup cookies in session 1 - should get both
	cookies, err := store.Lookup(origin, agent, session1)
	if err != nil {
		t.Fatalf("Failed to lookup cookies in session 1: %v", err)
	}

	if len(cookies) != 2 {
		t.Fatalf("Expected 2 cookies in session 1, got %d", len(cookies))
	}

	// Lookup cookies in session 2 - should only get persistent cookie
	cookies, err = store.Lookup(origin, agent, session2)
	if err != nil {
		t.Fatalf("Failed to lookup cookies in session 2: %v", err)
	}

	if len(cookies) != 1 {
		t.Fatalf("Expected 1 cookie in session 2 (persistent only), got %d", len(cookies))
	}

	if cookies[0].Name != "persistent_token" {
		t.Fatalf("Expected persistent cookie in session 2, got %s", cookies[0].Name)
	}

	t.Log("✓ Cookie storage and retrieval test passed")
}

func TestExpiredCookieDeletion(t *testing.T) {
	// Create a temporary database file
	tmpFile := "test_cookies_expired.sqlite3"
	defer os.Remove(tmpFile)

	// Open the store
	store, err := cookies.Open(tmpFile)
	if err != nil {
		t.Fatalf("Failed to open store: %v", err)
	}
	defer store.Close()

	origin := "https://example.com"
	agent := "00000000-0000-0000-0000-000000000001"
	session := "00000000-0000-0000-0000-000000000002"

	// Create an expired persistent cookie
	expiredCookie := &http.Cookie{
		Name:     "expired_cookie",
		Value:    "old",
		Path:     "/",
		Secure:   true,
		HttpOnly: false,
		Expires:  time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
	}

	// Create a valid persistent cookie
	validCookie := &http.Cookie{
		Name:     "valid_cookie",
		Value:    "new",
		Path:     "/",
		Secure:   true,
		HttpOnly: false,
		Expires:  time.Now().Add(24 * time.Hour), // Expires in 24 hours
	}

	// Create a session cookie (should never be deleted)
	sessionCookie := &http.Cookie{
		Name:     "session_id",
		Value:    "session123",
		Path:     "/",
		Secure:   true,
		HttpOnly: false,
	}

	// Upsert all cookies
	err = store.Upsert(origin, agent, session, expiredCookie)
	if err != nil {
		t.Fatalf("Failed to upsert expired cookie: %v", err)
	}

	err = store.Upsert(origin, agent, session, validCookie)
	if err != nil {
		t.Fatalf("Failed to upsert valid cookie: %v", err)
	}

	err = store.Upsert(origin, agent, session, sessionCookie)
	if err != nil {
		t.Fatalf("Failed to upsert session cookie: %v", err)
	}

	// Note: Lookup filters out expired cookies automatically
	// So before deletion, Lookup will return only 2 (valid persistent + session)
	cookiesBefore, _ := store.Lookup(origin, agent, session)
	if len(cookiesBefore) != 2 {
		t.Fatalf("Expected 2 cookies before explicit deletion (expired is filtered), got %d", len(cookiesBefore))
	}

	// Delete expired cookies
	err = store.DeleteExpired(origin, agent)
	if err != nil {
		t.Fatalf("Failed to delete expired cookies: %v", err)
	}

	// Should still have 2 cookies: valid persistent and session
	cookiesAfter, err := store.Lookup(origin, agent, session)
	if err != nil {
		t.Fatalf("Failed to lookup cookies: %v", err)
	}

	if len(cookiesAfter) != 2 {
		t.Fatalf("Expected 2 cookies after deletion (valid persistent + session), got %d", len(cookiesAfter))
	}

	// Verify other cookies still exist
	cookieNames := make(map[string]bool)
	for _, c := range cookiesAfter {
		cookieNames[c.Name] = true
	}

	if !cookieNames["valid_cookie"] {
		t.Fatalf("Valid persistent cookie was deleted")
	}
	if !cookieNames["session_id"] {
		t.Fatalf("Session cookie was deleted")
	}

	t.Log("✓ Expired cookie deletion test passed")
}
