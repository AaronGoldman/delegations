package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/aarongoldman/delegations/http/cookies"
	"github.com/aarongoldman/delegations/http/proxy"
)

var (
	agentFlag   = flag.String("agent", "", "Agent UUID (required)")
	sessionFlag = flag.String("session", "", "Session UUID (required)")
)

func main() {
	flag.Parse()

	// Validate required flags
	if *agentFlag == "" || *sessionFlag == "" {
		fmt.Fprintf(os.Stderr, "error: both --agent and --session are required\n")
		os.Exit(1)
	}

	// Validate UUID format
	if !isValidUUID(*agentFlag) {
		fmt.Fprintf(os.Stderr, "error: invalid agent UUID format\n")
		os.Exit(1)
	}
	if !isValidUUID(*sessionFlag) {
		fmt.Fprintf(os.Stderr, "error: invalid session UUID format\n")
		os.Exit(1)
	}

	// Get the directory where the binary is located
	binaryPath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to get executable path: %v\n", err)
		os.Exit(4)
	}
	binaryDir := filepath.Dir(binaryPath)
	cookieDBPath := filepath.Join(binaryDir, "cookies.sqlite3")

	// Check/create cookies database
	// If database exists, verify permissions are 0600
	if _, err := os.Stat(cookieDBPath); err == nil {
		// File exists, check permissions
		fi, err := os.Stat(cookieDBPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: failed to check cookie db permissions: %v\n", err)
			os.Exit(4)
		}
		if fi.Mode().Perm() != 0600 {
			fmt.Fprintf(os.Stderr, "error: cookie db has invalid permissions: %o (expected 0600)\n", fi.Mode().Perm())
			os.Exit(4)
		}
	}

	// Open the cookie store
	store, err := cookies.Open(cookieDBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to open cookie store: %v\n", err)
		os.Exit(4)
	}
	defer store.Close()

	// Ensure database file has correct permissions
	if err := os.Chmod(cookieDBPath, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to set cookie db permissions: %v\n", err)
		os.Exit(4)
	}

	// Read HTTP request from stdin
	req, err := proxy.ReadRequest(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to parse HTTP request: %v\n", err)
		os.Exit(2)
	}

	// Extract origin from the request
	origin := proxy.ExtractOrigin(req)

	// Delete expired cookies for this origin/agent
	if err := store.DeleteExpired(origin, *agentFlag); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to delete expired cookies: %v\n", err)
		os.Exit(4)
	}

	// Look up cookies for this origin/agent/session
	cookies, err := store.Lookup(origin, *agentFlag, *sessionFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to lookup cookies: %v\n", err)
		os.Exit(4)
	}

	// Inject cookies into the request
	proxy.InjectCookies(req, cookies)

	// Send the HTTP request
	resp, err := proxy.Send(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to send HTTP request: %v\n", err)
		os.Exit(3)
	}
	defer resp.Body.Close()

	// Separate HttpOnly and non-HttpOnly Set-Cookie headers
	nonHttpOnly, httpOnlySet := proxy.SeparateSetCookies(resp)

	// Save all cookies (both HttpOnly and non-HttpOnly) to the cookie jar
	// Save non-HttpOnly cookies
	for _, c := range nonHttpOnly {
		if err := store.Upsert(origin, *agentFlag, *sessionFlag, c); err != nil {
			fmt.Fprintf(os.Stderr, "error: failed to save cookie: %v\n", err)
			os.Exit(4)
		}
	}
	// Save HttpOnly cookies (these won't be returned to the client)
	for _, c := range httpOnlySet {
		if err := store.Upsert(origin, *agentFlag, *sessionFlag, c); err != nil {
			fmt.Fprintf(os.Stderr, "error: failed to save cookie: %v\n", err)
			os.Exit(4)
		}
	}

	// Strip HttpOnly Set-Cookie headers from the response
	resp = proxy.StripHttpOnlySetCookies(resp)

	// Write the response to stdout
	if err := proxy.WriteResponse(os.Stdout, resp); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to write response: %v\n", err)
		os.Exit(3)
	}

	os.Exit(0)
}

// isValidUUID checks if the string is a valid UUID format.
// Valid format: 8-4-4-4-12 hex digits with hyphens
func isValidUUID(s string) bool {
	pattern := `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`
	re := regexp.MustCompile(pattern)
	return re.MatchString(s)
}
