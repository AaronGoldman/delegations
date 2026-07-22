// Package main implements an MCP stdio server that wraps the delegations
// HTTP proxy binary as the "mcp-http" tool.
//
// The server:
//  1. Reads JSON-RPC 2.0 messages from stdin via mcp.StdioTransport.
//  2. Registers the "mcp-http" tool using mcp.AddTool.
//  3. On tool call, spawns the companion http binary (next to this process) with --agent and --session flags
//     derived from the caller's arguments (or defaults to all-zeros).
//  4. Pipes `request` on stdin to the binary and returns the HTTP
//     response from stdout as a MCP text content result.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/aarongoldman/delegations/http/proxy"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "http"}, nil)

	type args struct {
		Request string `json:"request"`
		Agent   string `json:"agent,omitempty"`
		Session string `json:"session,omitempty"`
	}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "http",
		Description: "say hi",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args args) (*mcp.CallToolResult, any, error) {
		// Read HTTP request from stdin
		request, err := proxy.ReadRequest(strings.NewReader(args.Request))
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: failed to parse HTTP request: %v\n", err)
			os.Exit(2)
		}

		// Send the HTTP request
		resp, err := proxy.Send(request)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: failed to send HTTP request: %v\n", err)
			os.Exit(3)
		}
		defer resp.Body.Close()

		// Strip HttpOnly Set-Cookie headers from the response
		resp = proxy.StripHttpOnlySetCookies(resp)

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: resp.Status},
			},
		}, nil, nil
	})

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
