package delegation

import "testing"

func TestSplitPattern(t *testing.T) {
	tests := []struct {
		pattern string
		host    string
		path    string
	}{
		{".example.com/path/to/example/", ".example.com", "/path/to/example/"},
		{"localhost:8080/", "localhost:8080", "/"},
		{"example.com", "example.com", "/"},
	}

	for _, tt := range tests {
		host, path := splitPattern(tt.pattern)
		if host != tt.host || path != tt.path {
			t.Fatalf("splitPattern(%q) = (%q, %q), want (%q, %q)", tt.pattern, host, path, tt.host, tt.path)
		}
	}
}

func TestJoinPattern(t *testing.T) {
	if got := joinPattern(".example.com", "/path/to/example/"); got != ".example.com/path/to/example/" {
		t.Fatalf("joinPattern returned %q", got)
	}
	if got := joinPattern("example.com", "api"); got != "example.com/api" {
		t.Fatalf("joinPattern normalized path to %q", got)
	}
}

func TestDelegationMatchesCombinedPattern(t *testing.T) {
	d := Delegation{
		Pattern: ".example.com/path/to/*",
		Methods: []string{"GET"},
		Scopes:  []string{"read"},
	}
	if !d.matches("api.example.com", "/path/to/item", "GET", []string{"read"}) {
		t.Fatal("combined pattern should match the requested host, path, method, and scope")
	}
	if d.matches("example.com", "/path/to/item", "GET", []string{"read"}) {
		t.Fatal("domain wildcard must not match the base domain")
	}
	if d.matches("api.example.com", "/other/item", "GET", []string{"read"}) {
		t.Fatal("path wildcard must not match a different path")
	}
}
