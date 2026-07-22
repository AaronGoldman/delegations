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
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				log.Printf("ERROR: VS Code proxy failed: %v", err)
				writeVscodeUnavailableError(w)
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
		writeVscodeUnavailableError(w)
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

// writeVscodeUnavailableError returns a helpful 502 error when VS Code server is unavailable.
func writeVscodeUnavailableError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadGateway)
	fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>VS Code Server Unavailable</title>
	<style>
		body { font-family: system-ui, sans-serif; max-width: 600px; margin: 60px auto; padding: 20px; color: #1a1a1a; }
		h1 { color: #d32f2f; margin-bottom: 4px; }
		.subtitle { color: #666; margin-top: 0; margin-bottom: 24px; }
		.code { background: #f5f5f5; padding: 12px 16px; border-radius: 6px; font-family: monospace; font-size: 0.9rem; margin: 16px 0; overflow-x: auto; }
		.steps { margin: 24px 0; }
		.steps ol { line-height: 1.8; }
		.steps li { margin-bottom: 12px; }
	</style>
</head>
<body>
	<h1>502 Bad Gateway</h1>
	<p class="subtitle">VS Code server is not running or unavailable.</p>

	<h2>What's happening?</h2>
	<p>The VS Code proxy server is running, but the VS Code development server on the Unix socket is not available.</p>

	<h2>How to fix it</h2>
	<div class="steps">
		<ol>
			<li>Start the VS Code server in a separate terminal:
				<div class="code">make vscode</div>
			</li>
			<li>Or manually:
				<div class="code">code serve-web --socket-path /tmp/vscode.sock --without-connection-token --server-base-path /code/</div>
			</li>
			<li>Once the server is running, retry your request.</li>
		</ol>
	</div>

	<h2>Troubleshooting</h2>
	<ul>
		<li>Check if <code>/tmp/vscode.sock</code> exists: <code>ls -la /tmp/vscode.sock</code></li>
		<li>Make sure you have the VS Code CLI installed: <code>code --version</code></li>
		<li>Check server logs for errors if the socket exists but the server isn't responding.</li>
	</ul>
</body>
</html>
`)
}
