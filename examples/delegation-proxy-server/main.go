// delegation-proxy-server is a self-contained demo of the Delegated Access Token spec.
//
// On first run with no configuration a config.json is created automatically with
// localhost defaults and randomly generated secrets — just run it.
//
// Endpoints:
//
//	GET  /api/whoami        Protected by delegated-access auth. Returns caller identity.
//	GET  /delegate?token=…  Delegation grant UI (shown to the user in a browser).
//	POST /grant             Processes the grant form submission (CSRF protected).
//	GET  /sessions          Lists all active grants.
//
// config.json keys:
//
//	listen_addr    Listen address, e.g. "127.0.0.1:8080"  (default)
//	jwt_secret     HS256 signing key                       (auto-generated)
//	server_secret  UUIDv5 namespace UUID                   (auto-generated)
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	agentCookieName     = "agent_cookie"
	sessionCookieName   = "session_cookie"
	principalCookieName = "principal_cookie"
	delegationPath      = "/delegate"
)

func main() {
	cfg, err := loadOrCreateConfig("config.json")
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	jwtSecret := cfg["jwt_secret"]
	if jwtSecret == "" {
		log.Fatal("jwt_secret missing from config.json")
	}
	serverSecret := cfg["server_secret"]
	if serverSecret == "" {
		log.Fatal("server_secret missing from config.json")
	}
	if _, err := parseUUID(serverSecret); err != nil {
		log.Fatalf("server_secret is not a valid UUID: %v", err)
	}
	listenAddr := cfg["listen_addr"]
	if listenAddr == "" {
		listenAddr = "127.0.0.1:8080"
	}

	store  := NewInMemoryDelegationStore()
	secret := []byte(jwtSecret)

	ss     := &SessionsServer{jwtSecret: secret, serverSecret: serverSecret, store: store}
	apiMux := newAuthMiddlewareMux(serverSecret, 10*time.Minute, secret, store)
	apiMux.HandleFunc("/api/whoami", whoamiHandler, []string{"profile_view"})

	mux := http.NewServeMux()
	mux.HandleFunc("/delegate", ss.showGrantUI)
	mux.HandleFunc("/grant",    ss.processGrant)
	mux.HandleFunc("/sessions", ss.listGrants)
	mux.HandleFunc("/revoke",   ss.revokeGrant)
	mux.Handle("/api/", apiMux)

	baseURL    := "http://" + listenAddr
	port       := listenAddr[strings.LastIndex(listenAddr, ":"):]
	stagingURL := "http://staging.localhost" + port
	log.Printf("delegation-proxy-server listening on %s", baseURL)
	log.Printf("  GET  %s/api/whoami       — protected demo endpoint", baseURL)
	log.Printf("  GET  %s/api/whoami       — protected demo endpoint (subdomain)", stagingURL)
	log.Printf("  GET  %s/delegate?token=… — grant approval UI", baseURL)
	log.Printf("  GET  %s/sessions         — list active grants", baseURL)

	srv := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

// loadOrCreateConfig reads config.json as a flat map[string]string.
// If the file does not exist it is created with localhost defaults and random secrets.
func loadOrCreateConfig(path string) (map[string]string, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := writeDefaultConfig(path); err != nil {
			return nil, fmt.Errorf("create %s: %w", path, err)
		}
		log.Printf("No %s found — created with defaults. Edit it to customize.", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg map[string]string
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return cfg, nil
}

// writeDefaultConfig writes a config.json with localhost defaults and random secrets.
func writeDefaultConfig(path string) error {
	jwtSecret, err := randomHex(32) // 256-bit
	if err != nil {
		return fmt.Errorf("generate jwt_secret: %w", err)
	}
	cfg := map[string]string{
		"jwt_secret":    jwtSecret,
		"server_secret": newUUIDv4(),
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0600)
}