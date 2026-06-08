package cookies

import (
	"testing"
)

func TestDomainMatch(t *testing.T) {
	tests := []struct {
		host     string
		domain   string
		expected bool
	}{
		// Exact match
		{"example.com", "example.com", true},
		{"api.example.com", "api.example.com", true},

		// Subdomain match (domain starting with dot)
		{"api.example.com", ".example.com", true},
		{"example.com", ".example.com", true},
		{"api.sub.example.com", ".example.com", true},

		// Subdomain match (domain without dot)
		{"api.example.com", "example.com", true},
		{"example.com", "example.com", true},

		// Should not match
		{"notexample.com", "example.com", false},
		{"example.com", "api.example.com", false},
		{"example.org", "example.com", false},
	}

	for _, tc := range tests {
		t.Run(tc.host+"_"+tc.domain, func(t *testing.T) {
			result := domainMatch(tc.host, tc.domain)
			if result != tc.expected {
				t.Errorf("domainMatch(%q, %q) = %v; want %v", tc.host, tc.domain, result, tc.expected)
			}
		})
	}
}

func TestPathMatch(t *testing.T) {
	tests := []struct {
		reqPath    string
		cookiePath string
		expected   bool
	}{
		// Exact match
		{"/api", "/api", true},
		{"/", "/", true},

		// Prefix match
		{"/api/users", "/api", true},
		{"/api/users", "/", true},
		{"/api/", "/api", true},

		// Must match directory boundary
		{"/api-users", "/api", false},
		{"/api-users", "/api/", false},
		{"/api", "/api/", false}, // Cookie requires trailing slash, request doesn't have it (browsers are strict here)

		// Empty path defaults to matching all
		{"/api", "", true},
		{"/", "", true},
		
		// Unmatched path
		{"/other", "/api", false},
	}

	for _, tc := range tests {
		t.Run(tc.reqPath+"_"+tc.cookiePath, func(t *testing.T) {
			result := pathMatch(tc.reqPath, tc.cookiePath)
			if result != tc.expected {
				t.Errorf("pathMatch(%q, %q) = %v; want %v", tc.reqPath, tc.cookiePath, result, tc.expected)
			}
		})
	}
}

func TestExtractHostFromOrigin(t *testing.T) {
	tests := []struct {
		origin   string
		expected string
	}{
		{"https://example.com", "example.com"},
		{"http://api.example.com", "api.example.com"},
		{"example.com", "example.com"}, // Invalid origin format fallback
	}

	for _, tc := range tests {
		t.Run(tc.origin, func(t *testing.T) {
			result := extractHostFromOrigin(tc.origin)
			if result != tc.expected {
				t.Errorf("extractHostFromOrigin(%q) = %v; want %v", tc.origin, result, tc.expected)
			}
		})
	}
}
