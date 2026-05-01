// delegation-proxy-server is a self-contained demo of the Delegated Access Token spec.
//
// On first run a config.json is created automatically with randomly generated secrets.
//
// Endpoints:
//
//	GET  /api/whoami              Protected by delegated-access auth. Returns caller identity.
//	GET  /code                    Protected by delegated-access auth. Proxies HTTP/WebSocket to VS Code socket.
//	GET  /delegations/ask?token=… Delegation grant UI (shown to the user in a browser).
//	POST /delegations/grant       Processes the grant form submission (CSRF protected).
//	GET  /delegations             Lists all active grants.
//	GET  /delegations/self-service Prove did:key ownership + create a self-granted delegation.
//	POST /delegations/self-service Process the self-service form (key registration + grant).
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aarongoldman/delegations/examples/delegation-proxy-server/api"
	"github.com/aarongoldman/delegations/examples/delegation-proxy-server/delegation"
)

const usageText = `delegation-proxy-server — Delegated Access Token proxy for AI agents

WHAT THIS TOOL DOES
  This server acts as a secure HTTP proxy between an AI agent and protected
  resources. The agent authenticates with an agent-id and session-id; the
  proxy holds all session cookies internally and injects them on every
  outbound request. Cookies are never forwarded back to the agent caller —
  they stay inside the proxy for the lifetime of the session.

  This lets an AI agent make authenticated requests without ever seeing the
  raw session tokens or HttpOnly cookies, which prevents accidental leakage
  in logs, tool outputs, or model context.

HOW TO USE
  1. Start this server (it auto-generates config.json on first run).
  2. Obtain a delegation token via the self-service or grant flow below.
  3. Your agent sets the Authorization header on every request:

       Authorization: Bearer <delegation-token>

     The delegation token encodes the agent-id and session-id. The proxy
     validates the token, retrieves the matching HttpOnly session cookies,
     attaches them to the upstream request, and strips them from the
     response before returning it to the agent.

  4. To bootstrap a token without human approval, visit:

       GET /delegations/self-service

     The agent proves ownership of its did:key, the server issues a scoped
     delegation token (e.g. profile_view, code_access), and the agent uses
     that token for all subsequent calls.

COOKIE SECURITY MODEL
  - HttpOnly cookies are stored server-side, keyed by session-id.
  - They are injected into upstream requests transparently.
  - They are stripped from all responses before the body reaches the agent.
  - The agent can never read, log, or exfiltrate the raw cookie values.

`

func main() {
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usageText)
		fmt.Fprintf(os.Stderr, "ENDPOINTS (default listen address: http://127.0.0.1:8080)\n\n")
		fmt.Fprintf(os.Stderr, "  GET  /api/whoami                — protected demo endpoint (requires profile_view scope)\n")
		fmt.Fprintf(os.Stderr, "  GET  /code/                     — protected VS Code socket proxy (requires code_access scope)\n")
		fmt.Fprintf(os.Stderr, "  GET  /delegations/ask?token=…  — human-facing grant approval UI\n")
		fmt.Fprintf(os.Stderr, "  POST /delegations/grant         — form submission for grant approval (CSRF protected)\n")
		fmt.Fprintf(os.Stderr, "  GET  /delegations               — list all active grants\n")
		fmt.Fprintf(os.Stderr, "  GET  /delegations/key           — Ed25519 public key for verifying Bearer tokens\n")
		fmt.Fprintf(os.Stderr, "  GET  /delegations/self-service  — register did:key + self-grant a scoped delegation\n")
		fmt.Fprintf(os.Stderr, "  POST /delegations/self-service  — process self-service key registration\n\n")
		fmt.Fprintf(os.Stderr, "FLAGS\n\n")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr)
	}
	flag.Parse()

	const listenAddr = "127.0.0.1:8080"

	// Wrap mux with delegation infrastructure
	authMux, pubKey, err := delegation.Mux()
	if err != nil {
		log.Fatalf("delegation setup: %v", err)
	}

	// Mount API routes with required scopes
	authMux.Handle("/api/", api.NewMux(pubKey), []string{"profile_view"})

	// Mount /code endpoint for VS Code web socket proxy
	authMux.HandleFunc("/code/", VscodeProxyHandler(pubKey), []string{"code_access"})

	baseURL := "http://" + listenAddr
	port := listenAddr[strings.LastIndex(listenAddr, ":"):]
	stagingURL := "http://staging.localhost" + port
	log.Printf("delegation-proxy-server listening on %s", baseURL)
	log.Printf("")
	log.Printf("  Agents authenticate with:  Authorization: Bearer <delegation-token>")
	log.Printf("  Agent-id and session-id are encoded in the token — no extra headers needed.")
	log.Printf("  HttpOnly cookies are managed entirely by this proxy and never sent to the agent.")
	log.Printf("")
	log.Printf("  GET  %s/api/whoami                 — protected demo endpoint (scope: profile_view)", baseURL)
	log.Printf("  GET  %s/api/whoami                 — protected demo endpoint (subdomain)", stagingURL)
	log.Printf("  GET  %s/code/                      — protected VS Code socket proxy (scope: code_access)", baseURL)
	log.Printf("  GET  %s/delegations/ask?token=…   — grant approval UI (open in browser)", baseURL)
	log.Printf("  GET  %s/delegations                — list active grants", baseURL)
	log.Printf("  GET  %s/delegations/key            — Ed25519 public key for verifying Bearer tokens", baseURL)
	log.Printf("  GET  %s/delegations/self-service   — register did:key + self-grant access", baseURL)
	log.Printf("")
	log.Printf("  Run with -h for full usage and cookie security model.")

	srv := &http.Server{
		Addr:         listenAddr,
		Handler:      authMux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}
