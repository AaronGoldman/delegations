package main

import (
	_ "embed"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"
)

// GetAuthInfo reads and verifies the X-Delegation header set by authMiddlewareMux.
// Returns nil if the header is missing or the Ed25519 signature is invalid.
func GetAuthInfo(r *http.Request, pubKey ed25519.PublicKey) *Delegation {
	token := r.Header.Get("X-Delegation")
	if token == "" {
		return nil
	}
	d, err := DelegationFromSignedJWT(pubKey, token)
	if err != nil {
		log.Printf("GetAuthInfo: %v", err)
		return nil
	}
	return d
}

// problemDetail is an RFC 7807 problem details object.
type problemDetail struct {
	Type             string `json:"type"`
	Title            string `json:"title,omitempty"`
	Status           int    `json:"status,omitempty"`
	Detail           string `json:"detail,omitempty"`
	DelegationURL    string `json:"delegation_url,omitempty"`
	DocumentationURL string `json:"documentation_url,omitempty"`
}

// helpPageData is passed to the endpoint help page template.
type helpPageData struct {
	Host   string
	Path   string
	Scopes []string
}

//go:embed pages/help.template.html
var helpHTML string

var helpTemplate = template.Must(template.New("help").Parse(helpHTML))

// authMiddlewareMux wraps http.ServeMux so that each HandleFunc call carries
// the required scopes for that endpoint. Auth is enforced per-handler.
type authMiddlewareMux struct {
	mux                 *http.ServeMux
	idDerivationSecret  string
	tokenTTL            time.Duration
	delegationURLSecret []byte
	store               DelegationStore
	delegationHeaderKey ed25519.PrivateKey
}

func newAuthMiddlewareMux(idDerivationSecret string, tokenTTL time.Duration, delegationURLSecret []byte, store DelegationStore, delegationHeaderKey ed25519.PrivateKey) *authMiddlewareMux {
	return &authMiddlewareMux{
		mux:                 http.NewServeMux(),
		idDerivationSecret:  idDerivationSecret,
		tokenTTL:            tokenTTL,
		delegationURLSecret: delegationURLSecret,
		store:               store,
		delegationHeaderKey: delegationHeaderKey,
	}
}

// HandleFunc registers handler at path, enforcing delegated-access auth and
// requiring the grant to cover all scopes before the handler is called.
// Requests with ?h=true or ?help=true are intercepted and return a human-readable
// HTML page describing the endpoint's host, path, and required scopes.
func (m *authMiddlewareMux) HandleFunc(path string, handler http.HandlerFunc, scopes []string) {
	m.mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("h") == "true" || q.Get("help") == "true" {
			m.writeHelpPage(w, r, path, scopes)
			return
		}

		agentC, _ := r.Cookie(agentCookieName)
		sessionC, _ := r.Cookie(sessionCookieName)

		if agentC == nil || sessionC == nil {
			var agentVal, sessionVal string
			if agentC == nil {
				agentVal = newUUIDv4()
				http.SetCookie(w, &http.Cookie{
					Name:     agentCookieName,
					Value:    agentVal,
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteLaxMode,
					MaxAge:   365 * 24 * 60 * 60, // 1 year
					Path:     "/",
				})
			} else {
				agentVal = agentC.Value
			}
			if sessionC == nil {
				sessionVal = newUUIDv4()
				setSessionCookie(w, sessionVal)
			} else {
				sessionVal = sessionC.Value
			}
			agentID, _ := deriveID(m.idDerivationSecret, agentVal)
			sessionID, _ := deriveID(m.idDerivationSecret, sessionVal)
			log.Printf("ISSUE agent=%s session=%s %s %s%s", agentID, sessionID, r.Method, r.Host, r.URL.Path)
			m.writeDelegationError(w, r, agentID, sessionID, scopes)
			return
		}

		agentID, err := deriveID(m.idDerivationSecret, agentC.Value)
		if err != nil {
			log.Printf("ERROR deriveID(agent): %v", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		sessionID, err := deriveID(m.idDerivationSecret, sessionC.Value)
		if err != nil {
			log.Printf("ERROR deriveID(session): %v", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		delegation, ok, err := m.store.FindMatching(agentID, sessionID, r.Host, r.URL.Path, r.Method, scopes)
		if err != nil {
			log.Printf("ERROR FindMatching: %v", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if !ok {
			log.Printf("DENY  agent=%s session=%s %s %s%s", agentID, sessionID, r.Method, r.Host, r.URL.Path)
			setSessionCookie(w, sessionC.Value) // rolling session
			m.writeDelegationError(w, r, agentID, sessionID, scopes)
			return
		}

		log.Printf("ALLOW agent=%s session=%s delegation=%s %s %s%s",
			agentID, sessionID, delegation.DelegationID, r.Method, r.Host, r.URL.Path)

		if delegation.Duration == "once" {
			if err := m.store.RevokeDelegation(delegation.DelegationID); err != nil {
				log.Printf("ERROR revoking once delegation %s: %v", delegation.DelegationID, err)
			}
		}

		token, err := delegation.SignedJWT(m.delegationHeaderKey)
		if err != nil {
			log.Printf("ERROR SignedJWT: %v", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		r.Header.Set("X-Delegation", token)
		handler(w, r)
	})
}

func (m *authMiddlewareMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mux.ServeHTTP(w, r)
}

// writeHelpPage returns a human-readable HTML page describing the endpoint's
// requirements: host, path, and required scopes.
func (m *authMiddlewareMux) writeHelpPage(w http.ResponseWriter, r *http.Request, path string, scopes []string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := helpTemplate.Execute(w, helpPageData{
		Host:   r.Host,
		Path:   path,
		Scopes: scopes,
	}); err != nil {
		log.Printf("ERROR rendering help page: %v", err)
	}
}


func setSessionCookie(w http.ResponseWriter, val string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    val,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		// No MaxAge: session cookie, cleared when browser closes.
	})
}

// writeDelegationError writes an RFC 7807 delegation-required 401 response.
// scopes is the set required by this endpoint and is embedded in the JWT so
// the grant UI can display them.
func (m *authMiddlewareMux) writeDelegationError(w http.ResponseWriter, r *http.Request, agentID, sessionID string, scopes []string) {
	token, err := (Delegation{
		AgentID:     agentID,
		SessionID:   sessionID,
		HostPattern: r.Host,
		PathPattern: r.URL.Path,
		Methods:     []string{r.Method},
		Scopes:      scopes,
		ExpiresAt:   time.Now().Add(m.tokenTTL).UTC().Format(time.RFC3339),
		IssuedAt:    time.Now().Unix(),
	}).JWT(m.delegationURLSecret)
	if err != nil {
		log.Printf("ERROR JWT: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	delegationURL := fmt.Sprintf("http://%s%s?token=%s", r.Host, delegationPath, token)
	docsURL := fmt.Sprintf("http://%s%s?h=true", r.Host, r.URL.Path)
	body := problemDetail{
		Type:             "https://github.com/aarongoldman/delegated-access-token#delegation-required",
		Title:            "Delegation Required",
		Status:           http.StatusUnauthorized,
		Detail:           fmt.Sprintf("Delegation required. Scopes needed: %s", strings.Join(scopes, ", ")),
		DelegationURL:    delegationURL,
		DocumentationURL: docsURL,
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(body) // response write errors are unrecoverable here
}
