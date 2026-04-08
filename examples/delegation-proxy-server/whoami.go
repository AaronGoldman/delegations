package main

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
)

// newWhoamiHandler returns a handler for GET /api/whoami — the demo protected endpoint.
// pubKey is the Ed25519 public key used to verify the X-Delegation header.
func newWhoamiHandler(pubKey ed25519.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		d := GetAuthInfo(r, pubKey)
		if d == nil {
			// authMiddleware should have rejected unauthorized requests before reaching here.
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(d)
	}
}
