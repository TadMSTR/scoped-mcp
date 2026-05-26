#!/bin/bash
# Template: stdio subprocess launcher with explicit env file sourcing.
#
# Copy and adjust for each MCP server you proxy via an mcp_proxy stdio entry.
#
# Why this pattern: the MCP protocol sanitizes the subprocess environment when
# launching stdio servers. Variables set in the parent shell (or inherited from
# a settings.json env block) are NOT visible inside the subprocess. Credentials
# must be explicitly exported here; they cannot be passed via the parent env.
#
# Usage: set `command` in your mcp_proxy manifest entry to point to this script
# instead of directly to the MCP server binary.
set -euo pipefail

# Source credentials from a secrets file. Use `set -a` / `set +a` to export
# all variables defined in the file without modifying the file itself.
set -a
source /path/to/secrets/my-service.env
set +a

# Any additional env vars not in the secrets file:
# export MY_SERVICE_BASE_URL="http://localhost:3000"

exec /path/to/venv/bin/python3 -m my_service.server
