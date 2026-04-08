package api

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"

	"github.com/aarongoldman/delegations/examples/delegation-proxy-server/delegation"
)

// NewMux creates and returns an http.Handler with all API routes registered.
// pubKey is the Ed25519 public key used to verify X-Delegation headers.
func NewMux(pubKey ed25519.PublicKey) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/whoami", whoamiHandler(pubKey))
	return mux
}

// whoamiHandler returns a handler for GET /api/whoami — the demo protected endpoint.
// pubKey is the Ed25519 public key used to verify the X-Delegation header.
func whoamiHandler(pubKey ed25519.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		d := delegation.GetAuthInfo(r, pubKey)
		if d == nil {
			// authMiddleware should have rejected unauthorized requests before reaching here.
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(d)
	}
}
