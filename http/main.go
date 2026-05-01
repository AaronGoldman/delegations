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

const usageText = `http — cookie-managing HTTP proxy for AI agents

SYNOPSIS
  http --agent <uuid> --session <uuid>  (HTTP request on stdin, response on stdout)

WHAT THIS TOOL DOES
  This tool lets an AI agent make authenticated HTTP requests without ever
  seeing or handling session cookies directly.

  The agent provides its identity via --agent and --session UUIDs. The tool:
    1. Reads a raw HTTP/1.1 request from stdin.
    2. Looks up any cookies previously stored for this origin+agent+session
       and injects them into the outgoing request.
    3. Sends the request to the target server.
    4. Saves any Set-Cookie headers from the response into a local SQLite
       cookie store (cookies.sqlite3 next to the binary).
    5. Strips HttpOnly Set-Cookie headers from the response before writing
       it to stdout — the agent never sees those values.

  HttpOnly cookies stay inside this tool for the lifetime of the session.
  They are added automatically on every outbound request and are never
  forwarded back to the caller in any response. This prevents accidental
  leakage of session tokens into logs, tool outputs, or model context.

FLAGS
  --agent   <uuid>   Agent UUID identifying the calling agent (required).
                     Used to scope the cookie store so each agent has its
                     own isolated cookie jar.

  --session <uuid>   Session UUID for this conversation or task (required).
                     Cookies are scoped per agent+session so a new session
                     starts with a clean jar.

COOKIE STORAGE
  Cookies are stored in cookies.sqlite3 in the same directory as the binary.
  The file is created automatically with mode 0600 on first use.
  Expired cookies are pruned automatically before each request.

USAGE EXAMPLE
  printf 'GET /api/whoami HTTP/1.1\r\nHost: example.com\r\n\r\n' \
    | http --agent 11111111-1111-1111-1111-111111111111 \
           --session 22222222-2222-2222-2222-222222222222

EXIT CODES
  0  success
  1  bad arguments (missing or invalid --agent / --session)
  2  could not parse stdin as an HTTP request
  3  network or response-write error
  4  cookie store error

`

var (
	agentFlag   = flag.String("agent", "", "Agent UUID (required)")
	sessionFlag = flag.String("session", "", "Session UUID (required)")
)

func main() {
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usageText)
	}
	flag.Parse()

	// Validate required flags
	if *agentFlag == "" || *sessionFlag == "" {
		fmt.Fprintf(os.Stderr, "error: both --agent and --session are required\n")
		fmt.Fprintf(os.Stderr, "Run 'http -h' for usage.\n")
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
