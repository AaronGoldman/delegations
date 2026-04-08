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
//	listen_addr             Listen address, e.g. "127.0.0.1:8080"  (default)
//	delegation_url_secret   HS256 signing key for delegation URL JWTs  (auto-generated)
//	id_derivation_secret    UUIDv5 namespace UUID for agent/session IDs (auto-generated)
//	delegation_header_key   Ed25519 private key hex for X-Delegation header (auto-generated)
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aarongoldman/delegations/examples/delegation-proxy-server/api"
	"github.com/aarongoldman/delegations/examples/delegation-proxy-server/delegation"
)

func main() {
	cfg, err := loadOrCreateConfig("config.json")
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// Fill in any missing secrets and write config back if needed.
	if err := ensureConfigSecrets(cfg, "config.json"); err != nil {
		log.Fatalf("config secrets: %v", err)
	}

	delegationURLSecret := cfg["delegation_url_secret"]
	idDerivationSecret := cfg["id_derivation_secret"]
	if _, err := delegation.ParseUUID(idDerivationSecret); err != nil {
		log.Fatalf("id_derivation_secret is not a valid UUID: %v", err)
	}

	listenAddr := cfg["listen_addr"]
	if listenAddr == "" {
		listenAddr = "127.0.0.1:8080"
	}

	keyBytes, err := hex.DecodeString(cfg["delegation_header_key"])
	if err != nil || len(keyBytes) != ed25519.PrivateKeySize {
		log.Fatalf("delegation_header_key in config.json is invalid (want %d-byte hex)", ed25519.PrivateKeySize)
	}
	delegationHeaderKey := ed25519.PrivateKey(keyBytes)
	delegationHeaderPub := delegationHeaderKey.Public().(ed25519.PublicKey)

	// Set up delegation infrastructure
	store := delegation.NewInMemoryDelegationStore()
	secret := []byte(delegationURLSecret)

	ss := &delegation.SessionsServer{
		DelegationURLSecret: secret,
		IdDerivationSecret:  idDerivationSecret,
		Store:               store,
	}

	authMux := delegation.NewAuthMiddlewareMux(
		idDerivationSecret,
		10*time.Minute,
		secret,
		store,
		delegationHeaderKey,
	)

	// Register API routes (wrapped in authMux)
	api.Register(authMux, delegationHeaderPub)

	// Wire everything together
	mux := http.NewServeMux()
	ss.RegisterHandlers(mux)
	mux.Handle("/api/", authMux)

	baseURL := "http://" + listenAddr
	port := listenAddr[strings.LastIndex(listenAddr, ":"):]
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
// If the file does not exist it is created with defaults and random secrets.
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

// writeDefaultConfig writes a config.json with localhost defaults and all random secrets.
func writeDefaultConfig(path string) error {
	urlSecret, err := delegation.RandomHex(32) // 256-bit HS256 key
	if err != nil {
		return fmt.Errorf("generate delegation_url_secret: %w", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate delegation_header_key: %w", err)
	}
	return writeConfig(path, map[string]string{
		"delegation_url_secret": urlSecret,
		"id_derivation_secret":  delegation.NewUUIDv4(),
		"delegation_header_key": hex.EncodeToString([]byte(priv)),
	})
}

// writeConfig serialises cfg as indented JSON and writes it atomically to path (mode 0600).
func writeConfig(path string, cfg map[string]string) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0600)
}

// ensureConfigSecrets fills in any missing secrets in cfg, writing back if needed.
// Generates missing: delegation_url_secret, id_derivation_secret, delegation_header_key.
func ensureConfigSecrets(cfg map[string]string, path string) error {
	updated := false

	if cfg["delegation_url_secret"] == "" {
		secret, err := delegation.RandomHex(32)
		if err != nil {
			return fmt.Errorf("generate delegation_url_secret: %w", err)
		}
		cfg["delegation_url_secret"] = secret
		updated = true
		log.Printf("Generated delegation_url_secret")
	}

	if cfg["id_derivation_secret"] == "" {
		cfg["id_derivation_secret"] = delegation.NewUUIDv4()
		updated = true
		log.Printf("Generated id_derivation_secret")
	}

	if cfg["delegation_header_key"] == "" {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("generate delegation_header_key: %w", err)
		}
		cfg["delegation_header_key"] = hex.EncodeToString([]byte(priv))
		updated = true
		log.Printf("Generated delegation_header_key")
	}

	if updated {
		if err := writeConfig(path, cfg); err != nil {
			return fmt.Errorf("write config: %w", err)
		}
	}
	return nil
}
