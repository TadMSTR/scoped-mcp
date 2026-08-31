// PM2 ecosystem — one long-lived HTTP-transport scoped-mcp broker per agent.
//
// WHY THIS FILE EXISTS. These processes previously had no start definition in
// version control: they existed only in PM2's own dump file, which is not
// tracked, is rewritten wholesale by every `pm2 save`, and is regenerated from
// running state rather than from reviewed configuration. Declaring them here
// makes `pm2 start ecosystem.config.js` the recovery path instead of
// `pm2 resurrect`. It also unblocks ordinary maintenance: removing an env var
// from a PM2 app requires `pm2 delete` + `pm2 start`, because
// `restart --update-env` can add or overwrite a value but never delete one.
//
// NO SECRETS BELONG IN THIS FILE, and none are needed. The launcher is
// world-readable and sources its own per-agent env file (see LAUNCHER below)
// with `set -a` before exec'ing the broker. Confirmed on this deployment that
// every ${VAR} referenced by any deployed agent manifest is present in that
// agent's own env file, so nothing resolves out of the ambient environment.
// The two variables below per agent are the complete set this file must carry.
//
// EXPECT A LARGE, MISLEADING ENV DIFF. A process started by hand from an
// interactive shell inherits that shell's whole environment, and PM2 freezes it
// into the dump. Comparing the dump's env for these apps against this file will
// therefore report ~100 "missing" variables. They are inherited shell state
// (SSH_*, XDG_*, and whatever the login profile sources), not configuration.
// Do not reconcile that diff by copying the dump's env back into this file —
// doing so would commit inherited credential material into version control.
//
// Corollary: systemd's `pm2 resurrect` runs in a NON-LOGIN context and does not
// re-source the login profile, which is why those inherited values get frozen
// into the dump to survive a boot at all. A file that declares what it needs
// explicitly is therefore strictly better than resurrect, not merely equivalent.
//
// The agent list and ports below were taken from live process state, not from
// the fleet documentation, which was stale and listed only six of these eight.
// Building the map from the doc would have left two brokers undeclared — the
// same gap this file exists to close.
"use strict";

const LAUNCHER = "/usr/local/sbin/forge/run-scoped-mcp-http.sh";

// AGENT_TYPE -> SCOPED_MCP_HTTP_PORT. Both are required by the launcher, which
// fails loudly by name if either is unset. Every port here is bound to
// 127.0.0.1 by the launcher. Add a row to onboard a new broker.
//
// The steward broker is deliberately ABSENT: it runs under systemd as its own
// dedicated user rather than under PM2, and adding it here would create a
// second supervisor racing the first for the same port. Do not "complete the set".
const AGENTS = {
  research: 8471,
  developer: 8472,
  sysadmin: 8473,
  security: 8474,
  writer: 8475,
  jobsearch: 8476,
  "doc-health": 8477,
  "memory-sync": 8478,
};

function buildApp(agentType, httpPort) {
  return {
    name: `scoped-mcp-${agentType}`,
    script: LAUNCHER,
    interpreter: "bash",
    // The launcher execs an absolute path and reads only absolute paths, so cwd
    // is not load-bearing — but pinning it explicitly stops `pm2 save` from
    // stamping in whatever directory the caller happened to be run from, which
    // is how several apps on this host acquired a meaningless recorded cwd.
    cwd: "/home/ted",
    exec_mode: "fork",
    autorestart: true,
    // Matches current running state. Log paths are left to PM2's default
    // (~/.pm2/logs/<name>-{out,error}.log), which is already where these write.
    merge_logs: true,
    env: {
      AGENT_TYPE: agentType,
      SCOPED_MCP_HTTP_PORT: String(httpPort),
    },
  };
}

module.exports = {
  apps: Object.entries(AGENTS).map(([agentType, port]) => buildApp(agentType, port)),
};
