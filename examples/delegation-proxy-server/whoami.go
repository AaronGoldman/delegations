package main

import (
	"encoding/json"
	"net/http"
)

// whoamiHandler handles GET /api/whoami — the demo protected endpoint.
// Requires a valid delegation; returns the caller's identity.
func whoamiHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	d := GetAuthInfo(r)
	if d == nil {
		// authMiddleware should have rejected unauthorized requests before reaching here.
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(d)
}
