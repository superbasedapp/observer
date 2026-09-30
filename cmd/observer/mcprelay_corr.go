package main

import (
	"os"

	"github.com/marmutapp/superbased-observer/internal/mcprelay"
	"github.com/marmutapp/superbased-observer/internal/processobs"
)

// mcpRelayWrapperCorr is the stdio wrapper's stream correlation (Agent Access
// P11(a), R11.8): the AI client spawns `observer mcp-relay wrap` as its MCP
// server child, so the client's tree-inherited session env is in THIS
// process's environment. processobs.SessionTokenEnvKeys is the one allow-list
// of such keys (CLAUDE_CODE_SESSION_ID == sessions.id); only those keys'
// values are read, never the rest of the environment. The per-call tool-use
// id rides in each request's params._meta (mcprelay/corr.go).
func mcpRelayWrapperCorr() mcprelay.Correlation {
	return mcprelay.CorrelationFromEnv(os.Getenv, processobs.SessionTokenEnvKeys)
}
