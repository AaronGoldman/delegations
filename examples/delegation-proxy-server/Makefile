.PHONY: help dev dev-server clean

VSCODE_SOCKET := /tmp/vscode.sock
VSCODE_CMD := code serve-web --socket-path $(VSCODE_SOCKET) --without-connection-token --server-base-path /code/

help:
	@echo "Available targets:"
	@echo "  make dev          - Start VS Code server and proxy server (run in separate terminals)"
	@echo "  make dev-server   - Start only the proxy server"
	@echo "  make vscode       - Start VS Code server only"
	@echo "  make clean        - Kill VS Code server and clean up socket"

# Start both services (user should run in separate terminals)
dev:
	@echo "Starting VS Code server on Unix socket..."
	@$(VSCODE_CMD) &
	@sleep 2
	@echo "Starting delegation-proxy-server..."
	@go run .

# Start proxy server only (assumes VS Code is already running)
dev-server:
	go run .

# Start VS Code server only
vscode:
	@echo "Starting VS Code server on $(VSCODE_SOCKET)..."
	@echo "Run 'make dev-server' in another terminal to start the proxy"
	$(VSCODE_CMD)

# Clean up
clean:
	@echo "Cleaning up..."
	@pkill -f "code serve-web" || true
	@rm -f $(VSCODE_SOCKET)
	@echo "Cleaned up"
