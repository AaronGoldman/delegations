---
name: http
description: Make authenticated HTTP requests through the delegated-access-token cookie proxy. Manages HttpOnly cookies securely — they are stored locally and injected on outbound requests but never returned to the caller.
allowed-tools:
  - Bash
  - AskUserQuestion
---

# HTTP skill

Use the binary at `.claude/skills/http` (relative to the project root) to make HTTP requests on behalf of this agent.

## Identity

**Agent UUID** — read from `.claude/http-agent.uuid` at the start of every call:
```bash
AGENT_ID=$(cat .claude/http-agent.uuid)
```
This UUID is stable for the lifetime of this workspace.

**Session UUID** — generated once per conversation and held in your context for the rest of the chat. If you do not yet have a session UUID for this conversation, generate one now and remember it:
```bash
SESSION_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
```
Do not regenerate it on subsequent calls — reuse the value already in your context. A new chat session naturally starts with a new UUID.

## Before every request — mandatory confirmation

Before running the binary you MUST:

1. Show the user the exact request you are about to send:
   - Method and URL
   - All request headers
   - Request body (if any)
2. Ask: **"Send this request? (yes/no)"**
3. Only proceed if the user confirms. If they say no, stop.

## Making the request

Format the HTTP request as a raw HTTP/1.1 message and pipe it to the binary:

```bash
AGENT_ID=$(cat .claude/http-agent.uuid)
# SESSION_ID is already in your context from earlier this conversation

printf 'GET /path HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n' \
  | .claude/skills/http --agent "$AGENT_ID" --session "$SESSION_ID"
```

For requests with a body (POST, PUT, etc.) include `Content-Type` and `Content-Length` headers.

## Cookie handling

- The binary reads cookies for this origin+agent+session from `cookies.sqlite3` (next to the binary) and injects them into the outbound request automatically.
- `Set-Cookie` headers from the response are saved back to the store.
- **HttpOnly cookies are stripped from the response before it reaches you.** You will never see their values. This is intentional — they stay inside the proxy to prevent leakage into logs or model context.
- Non-HttpOnly cookies appear in the response normally.

## Resetting the session

To start with a fresh cookie jar, ask the user to start a new chat. The new conversation will generate a new session UUID and the previous session's cookies will remain in the store but will no longer be used.
