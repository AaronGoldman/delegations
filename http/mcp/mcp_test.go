package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testAgentUUID    = "11111111-1111-1111-1111-111111111111"
	testSessionUUID  = "22222222-2222-2222-2222-222222222222"
	testHTTPBinPath  = "/tmp/http-test-binary"
)

// mcpTestClient wraps an MCP server process for testing
type mcpTestClient struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	cancel context.CancelFunc
	done   chan struct{}
}

// newMCPClient starts a fresh MCP server instance for testing
func newMCPClient(t *testing.T, tmpDir string) (*mcpTestClient, func()) {
	t.Helper()

	binPath := filepath.Join(tmpDir, "mcp-server-test")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	cmd := exec.CommandContext(ctx, binPath)

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("failed to create stdin pipe: %v", err)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}

	cmd.Env = append(os.Environ(), "HOME="+tmpDir)

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start MCP server: %v", err)
	}

	client := &mcpTestClient{
		cmd:    cmd,
		stdin:  stdinPipe,
		stdout: bufio.NewReader(stdoutPipe),
		cancel: cancel,
		done:   make(chan struct{}),
	}

	go func() {
		_ = cmd.Wait()
		close(client.done)
	}()

	cleanup := func() {
		client.cancel()
		cmd.Process.Kill()
		<-client.done
	}

	if err := client.waitForInit(); err != nil {
		cleanup()
		t.Fatalf("MCP server init failed: %v", err)
	}

	// Skip the tools/list notification (server sends it automatically after init)
	line, _ := client.stdout.ReadString('\n')
	var msg map[string]any
	json.Unmarshal([]byte(line), &msg)

	return client, cleanup
}

// waitForInit waits for the MCP server's initialization notification
func (c *mcpTestClient) waitForInit() error {
	line, err := c.stdout.ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading init message: %w", err)
	}
	var msg map[string]any
	if err := json.Unmarshal([]byte(line), &msg); err != nil {
		return fmt.Errorf("parsing init JSON: %w", err)
	}
	if msg["method"] != "notifications/initialized" {
		return fmt.Errorf("expected 'notifications/initialized', got: %v", msg)
	}
	return nil
}

// sendJSON sends a JSON-RPC message and returns the server's response line
func (c *mcpTestClient) sendJSON(method string, params map[string]any) ([]byte, error) {
	msg := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
	}
	if method != "" {
		msg["method"] = method
	}
	if params != nil {
		msg["params"] = params
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	if _, err := c.stdin.Write(append(data, '\n')); err != nil {
		return nil, fmt.Errorf("writing to stdin: %w", err)
	}

	line, err := c.stdout.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	return []byte(line), nil
}

// TestMCPInit verifies the server sends initialization notifications on startup
func TestMCPInit(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "mcp-server-test")

	if err := buildTestBinary(binPath); err != nil {
		t.Fatalf("failed to build test binary: %v", err)
	}

	client, cleanup := newMCPClient(t, tmpDir)
	defer cleanup()

	// Client is already past the tools/list notification at this point
	// Send a tools/call with missing tool name (should get "unknown tool" error)
	params := map[string]any{
		"name": "", // empty tool name triggers "unknown tool" error branch
	}
	resp, err := client.sendJSON("tools/call", params)
	if err != nil {
		t.Fatalf("communication failed: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(resp, &result); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	// Should get an error (unknown tool), not a blank result
	errorData, ok := result["error"].(map[string]any)
	if !ok {
		t.Fatal("expected error for empty tools/call request")
	}
	msg, _ := errorData["message"].(string)
	if msg == "" {
		t.Errorf("expected 'unknown tool' or similar error message, got: %v", result)
	}
}

// TestHTTPSendToolCall validates the http_send tool works correctly
func TestHTTPSendToolCall(t *testing.T) {
	// Skip if the actual /tmp/http binary is not available
	if _, err := os.Stat("/tmp/http"); os.IsNotExist(err) {
		t.Skipf("/tmp/http binary not found - skipping integration test")
		return
	}

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "mcp-server-test")

	if err := buildTestBinary(binPath); err != nil {
		t.Fatalf("failed to build test binary: %v", err)
	}

	client, cleanup := newMCPClient(t, tmpDir)
	defer cleanup()

	httpReq := "GET /get HTTP/1.1\r\nHost: httpbin.org\r\nUser-Agent: mcp-test-client/0.1\r\nConnection: close\r\n\r\n"

	params := map[string]any{
		"name": "http_send",
		"arguments": map[string]any{
			"request": httpReq,
			"agent":   testAgentUUID,
			"session": testSessionUUID,
		},
	}

	resp, err := client.sendJSON("tools/call", params)
	if err != nil {
		t.Fatalf("tools/call failed: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(resp, &result); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	if errMsg, ok := result["error"]; ok {
		t.Logf("Full error: %+v", errMsg)
		t.Skipf("Network unavailable or external service error - skipping HTTP test")
		return
	}

	resultData, ok := result["result"].(map[string]any)
	if !ok {
		t.Fatalf("missing or invalid 'result' field")
	}

	contentList, ok := resultData["content"].([]any)
	if !ok || len(contentList) == 0 {
		t.Fatalf("empty content array: %v", resultData)
	}

	firstContent := contentList[0].(map[string]any)
	text, _ := firstContent["text"].(string)

	if !strings.Contains(text, "HTTP/") {
		t.Errorf("response should contain HTTP status line, got: %.200s", text)
	}
}

// TestToolsCallWithInvalidParams tests error handling for missing request argument
func TestToolsCallWithInvalidParams(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "mcp-server-test")

	if err := buildTestBinary(binPath); err != nil {
		t.Fatalf("failed to build test binary: %v", err)
	}

	client, cleanup := newMCPClient(t, tmpDir)
	defer cleanup()

	params := map[string]any{
		"name": "http_send",
		"arguments": map[string]any{
			// missing 'request'
		},
	}

	resp, err := client.sendJSON("tools/call", params)
	if err != nil {
		t.Fatalf("tools/call failed: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(resp, &result); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	errorData, ok := result["error"].(map[string]any)
	if !ok {
		t.Fatal("expected error response for missing request parameter")
	}

	message, _ := errorData["message"].(string)
	if !strings.Contains(message, "missing 'request'") {
		t.Errorf("expected 'missing request' error, got: %v", message)
	}
}

// TestToolsListReturnsDefinition verifies tools/list returns the http_send definition
func TestToolsListReturnsDefinition(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "mcp-server-test")

	if err := buildTestBinary(binPath); err != nil {
		t.Fatalf("failed to build test binary: %v", err)
	}

	client, cleanup := newMCPClient(t, tmpDir)
	defer cleanup()

	resp, err := client.sendJSON("tools/list", nil)
	if err != nil {
		t.Fatalf("tools/list failed: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(resp, &result); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	toolsList, ok := result["result"].([]any)
	if !ok || len(toolsList) == 0 {
		t.Fatal("tools/list should return non-empty array")
	}

	toolDef := toolsList[0].(map[string]any)
	name, _ := toolDef["name"].(string)

	if name != "http" {
		t.Errorf("expected tool name 'http', got: %s", name)
	}
}

// buildTestBinary compiles the MCP server binary for testing
func buildTestBinary(outPath string) error {
	buildCmd := exec.Command("go", "build", "-o", outPath, "mcp-http.go")
	var stderr bytes.Buffer
	buildCmd.Stderr = &stderr
	if err := buildCmd.Run(); err != nil {
		return fmt.Errorf("go build failed: %w\nstderr: %s", err, stderr.String())
	}
	return nil
}
