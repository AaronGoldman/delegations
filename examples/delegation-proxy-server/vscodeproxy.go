package main

import (
	"crypto/ed25519"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"

	"github.com/aarongoldman/delegations/examples/delegation-proxy-server/delegation"
)

// VscodeProxyHandler returns a handler that proxies authorized requests to a VS Code web socket.
// The socket is expected to be running at /tmp/vscode.sock via: code serve-web --socket-path /tmp/vscode.sock
func VscodeProxyHandler(pubKey ed25519.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check authorization
		d := delegation.GetAuthInfo(r, pubKey)
		if d == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		log.Printf("VS Code proxy: agent=%s session=%s", d.AgentID, d.SessionID)

		// Create a custom HTTP transport that dials the Unix socket
		transport := &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				return net.Dial("unix", "/tmp/vscode.sock")
			},
		}

		// Handle WebSocket upgrades separately
		if r.Header.Get("Upgrade") == "websocket" {
			proxyWebSocket(w, r)
			return
		}

		// For regular HTTP requests, use a reverse proxy
		proxy := &httputil.ReverseProxy{
			Transport: transport,
			Director: func(req *http.Request) {
				// Rewrite the request to target the Unix socket
				req.URL.Scheme = "http"
				req.URL.Host = "localhost"
				req.RequestURI = ""

				// Log the forwarded request for debugging
				log.Printf("Forwarding to VS Code: %s %s", req.Method, req.URL.String())
			},
		}

		proxy.ServeHTTP(w, r)
	}
}

// proxyWebSocket upgrades the connection to WebSocket and pipes it to the Unix socket.
func proxyWebSocket(w http.ResponseWriter, r *http.Request) {
	// Connect to the Unix socket
	conn, err := net.Dial("unix", "/tmp/vscode.sock")
	if err != nil {
		log.Printf("ERROR: failed to connect to VS Code socket: %v", err)
		http.Error(w, fmt.Sprintf("failed to connect to VS Code: %v", err), http.StatusBadGateway)
		return
	}
	defer conn.Close()

	// Hijack the HTTP connection to do a raw WebSocket upgrade
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "webSocket hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, fmt.Sprintf("hijack error: %v", err), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Modify the request for forwarding to VS Code on Unix socket
	r.Host = "localhost"
	r.RequestURI = ""

	log.Printf("WebSocket upgrade: %s %s", r.Method, r.URL.String())

	// Write the modified HTTP request to the Unix socket
	if err := r.Write(conn); err != nil {
		log.Printf("ERROR: failed to write request to VS Code socket: %v", err)
		return
	}

	// Bidirectionally pipe data between client and VS Code socket
	go func() {
		_, err := copyData(clientConn, conn)
		if err != nil {
			log.Printf("ERROR copying data from Unix socket to client: %v", err)
		}
	}()

	_, err = copyData(conn, clientConn)
	if err != nil {
		log.Printf("ERROR copying data from client to Unix socket: %v", err)
	}
}

// copyData performs a bidirectional copy of data between two connections.
func copyData(dst net.Conn, src net.Conn) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64

	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, err := dst.Write(buf[:n]); err != nil {
				return total + int64(n), err
			}
			total += int64(n)
		}
		if err != nil {
			return total, err
		}
	}
}
