#!/bin/bash
# Reads session_id from the SessionStart hook payload and injects it into the
# Claude Code environment so http-send can use it without the model ever seeing it.
set -euo pipefail

PAYLOAD=$(cat)
SESSION_ID=$(echo "$PAYLOAD" | jq -r '.session_id // empty')

if [[ -z "$SESSION_ID" ]]; then
  echo "inject-session: no session_id in payload" >&2
  exit 0
fi

if [[ -n "${CLAUDE_ENV_FILE:-}" ]]; then
  echo "HTTP_SESSION_ID=$SESSION_ID" >> "$CLAUDE_ENV_FILE"
fi
