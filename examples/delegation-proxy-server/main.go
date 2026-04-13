// delegation-proxy-server is a self-contained demo of the Delegated Access Token spec.
//
// On first run a config.json is created automatically with randomly generated secrets.
//
// Endpoints:
//
//	GET  /api/whoami              Protected by delegated-access auth. Returns caller identity.
//	GET  /delegations/ask?token=… Delegation grant UI (shown to the user in a browser).
//	POST /delegations/grant       Processes the grant form submission (CSRF protected).
//	GET  /delegations             Lists all active grants.
package main

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/aarongoldman/delegations/examples/delegation-proxy-server/api"
	"github.com/aarongoldman/delegations/examples/delegation-proxy-server/delegation"
)

func main() {
	const listenAddr = "127.0.0.1:8080"

	// Wrap mux with delegation infrastructure
	authMux, pubKey, err := delegation.Mux()
	if err != nil {
		log.Fatalf("delegation setup: %v", err)
	}

	// Mount API routes with required scopes
	authMux.Handle("/api/", api.NewMux(pubKey), []string{"profile_view"})

	baseURL := "http://" + listenAddr
	port := listenAddr[strings.LastIndex(listenAddr, ":"):]
	stagingURL := "http://staging.localhost" + port
	log.Printf("delegation-proxy-server listening on %s", baseURL)
	log.Printf("  GET  %s/api/whoami                 — protected demo endpoint", baseURL)
	log.Printf("  GET  %s/api/whoami                 — protected demo endpoint (subdomain)", stagingURL)
	log.Printf("  GET  %s/delegations/ask?token=…   — grant approval UI", baseURL)
	log.Printf("  GET  %s/delegations                — list active grants", baseURL)
	log.Printf("  GET  %s/delegations/key            — Ed25519 public key for Authorization: Bearer", baseURL)

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
