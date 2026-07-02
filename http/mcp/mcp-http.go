// Package main implements an MCP stdio server that wraps the delegations
// HTTP proxy binary as the "http_send" tool.
//
// The server:
//  1. Reads JSON-RPC 2.0 messages from stdin (line by line via bufio.Scanner).
//  2. Spawns /tmp/http with --agent and --session flags derived from the
//     caller's arguments (or defaults to all-zeros if omitted).
//  3. Pipes the `request` on stdin to the binary and captures the full
//     HTTP/1.1 wire-format response from stdout.
//  4. Returns the raw response text as an MCP tool result in jsonrpc format.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"
)

const (
	defaultAgent   = "00000000-0000-0000-0000-000000000000"
	defaultSession = "00000000-0000-0000-0000-000000000000"
	httpBinaryPath = "/tmp/http"
)

func logf(format string, args ...any) {
	fmt.Fprintln(os.Stderr, "[mcp-http] "+fmt.Sprintf(format, args...))
}

// ---- JSON-RPC wire format helpers ----

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *jsonRPCErr     `json:"error,omitempty"`
}

type jsonRPCErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func newRespSuccess(id any, result any) []byte {
	b, _ := json.Marshal(jsonRPCResponse{JSONRPC: "2.0", ID: id, Result: result})
	return b
}

func newRespError(id any, code int, msg string) []byte {
	b, _ := json.Marshal(jsonRPCResponse{JSONRPC: "2.0", ID: id, Error: &jsonRPCErr{Code: code, Message: msg}})
	return b
}

// ---- MCP tool registration ----

var toolsList = []map[string]any{{
	"name":        "http",
	"description": "Send an HTTP request through the delegations cookie proxy. Injects scoped cookies and strips HttpOnly Set-Cookie headers from the response.",
	"inputSchema": map[string]any{
		"type":       "object",
		"properties": toolInputSchema(),
		"required":   []string{"request"},
	},
}}

func toolInputSchema() map[string]any {
	return map[string]any{
		"request": map[string]any{
			"type":        "string",
			"description": "Raw HTTP/1.1 request string with headers (Host, User-Agent required).",
		},
		"agent": map[string]any{
			"type":        "string",
			"description": "Agent UUID for cookie scoping (default: all-zeros).",
		},
		"session": map[string]any{
			"type":        "string",
			"description": "Session UUID for cookie scoping (default: all-zeros).",
		},
	}
}

// ---- MCP main loop ----

func main() {
	logf("MCP server starting (binary: %s)", httpBinaryPath)

	// Send initialized notification.
	b, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	})
	os.Stdout.Write(b)
	os.Stdout.WriteString("\n")

	// Send tool definitions via tools/list notification.
	b, _ = json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      nil,
		"result":  toolsList,
	})
	os.Stdout.Write(b)
	os.Stdout.WriteString("\n")

	logf("Ready — listening on stdin")

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var req map[string]any
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			logf("WARN: malformed JSON: %v", err)
			continue
		}

		method, _ := req["method"].(string)
		rawID := req["id"]

		switch method {
		case "tools/list":
			id, _ := rawID.(float64)
			os.Stdout.Write(newRespSuccess(id, toolsList))
			os.Stdout.WriteString("\n")

		case "tools/call":
			handleToolsCall(os.Stdout, req, rawID)
			os.Stdout.WriteString("\n")

		default:
			// Notifications (no id field) should be silently ignored
			if rawID == nil {
				continue
			}
			if _, ok := req["params"]; !ok {
				os.Stdout.Write(newRespError(rawID, -32601, "unsupported method: "+method))
				os.Stdout.WriteString("\n")
				continue
			}
			paramsMap, ok := req["params"].(map[string]any)
			if !ok {
				os.Stdout.Write(newRespError(rawID, -32601, "invalid params structure"))
				os.Stdout.WriteString("\n")
				continue
			}
			// Only tools/call has the arguments wrapper; reject others gracefully
			argsRaw, ok := paramsMap["arguments"]
			if !ok {
				os.Stdout.Write(newRespError(rawID, -32601, fmt.Sprintf("unsupported method: %s", method)))
				os.Stdout.WriteString("\n")
				continue
			}
			callName, ok := argsRaw.(map[string]any)["name"]
			if !ok {
				os.Stdout.Write(newRespError(rawID, -32601, "invalid arguments structure"))
				os.Stdout.WriteString("\n")
				continue
			}
			os.Stdout.Write(newRespError(rawID, -32601, fmt.Sprintf("unknown tool: %v", callName)))
			os.Stdout.WriteString("\n")
		}
	}

	if err := scanner.Err(); err != nil {
		logf("WARN: stdin error: %v", err)
	}
}

func handleToolsCall(out *os.File, req map[string]any, rawID any) {
	// Extract args from params.arguments structure per JSON-RPC spec
	paramsMap, ok := req["params"].(map[string]any)
	if !ok || paramsMap == nil {
		out.Write(newRespError(rawID, -32602, "missing 'params' in request"))
		return
	}

	argMap, ok := paramsMap["arguments"].(map[string]any)
	if !ok || argMap == nil {
		argMap = make(map[string]any)
	}

	reqStr, _ := argMap["request"].(string)
	if reqStr == "" {
		out.Write(newRespError(rawID, -32602, "missing 'request' argument"))
		return
	}

	agentUUID, _ := argMap["agent"].(string)
	if agentUUID == "" {
		agentUUID = defaultAgent
	}

	sessionUUID, _ := argMap["session"].(string)
	if sessionUUID == "" {
		sessionUUID = defaultSession
	}

	// Spawn the HTTP proxy binary.
	cmdCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, httpBinaryPath, "--agent", agentUUID, "--session", sessionUUID)

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		out.Write(newRespError(rawID, -32601, "stdin pipe: "+err.Error()))
		return
	}

	go func() {
		stdinPipe.Write([]byte(reqStr))
		stdinPipe.Close()
	}()

	if err := cmd.Run(); err != nil {
		exitCode := 99
		if pe, ok := err.(*exec.ExitError); ok {
			exitCode = pe.ProcessState.ExitCode()
		}
		out.Write(newRespError(rawID, -32601, fmt.Sprintf("exit [%d]: %s", exitCode, stderrBuf.String())))
		return
	}

	result := map[string]any{
		"content": []map[string]any{{
			"type": "text",
			"text": stdoutBuf.String(),
		}},
	}
	out.Write(newRespSuccess(rawID, result))
	logf("Response length: %d bytes", len(stdoutBuf.Bytes()))
}
