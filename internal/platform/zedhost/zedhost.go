package zedhost

import "github.com/marmutapp/superbased-observer/internal/models"

// Host is the surface-host token a Zed-hosted session carries beside
// models.SurfaceIDE. The zed capture adapter stamps it on Zed's own agent
// threads; a future enricher stamps it on registry agents Zed hosts. It
// ships on the org wire verbatim (internal/store/orgpush.go
// knownSurfaceHosts, pinned by this package's tests).
const Host = "zed"

// extensionAgent is a (Zed extension id, agent server key) pair.
type extensionAgent struct {
	Extension string
	ServerKey string
}

// extensionAgents maps a Zed extension's agent server to the Observer tool
// whose product it runs. Grounded rows only.
var extensionAgents = map[extensionAgent]string{
	// Kilo's Zed extension "kilo" (7.8.17) names its agent server
	// "opencode" and downloads Kilo's own opencode-<os> archives: it is Kilo,
	// not OpenCode (inventory X13).
	{Extension: "kilo", ServerKey: "opencode"}: models.ToolKiloCodeCLI,
}

// ToolForExtensionAgent returns the Observer tool a Zed extension's agent
// server runs, keyed by the extension id AND the server key. ok is false for
// any pair not in the grounded table, including a known server key under a
// different extension.
func ToolForExtensionAgent(extension, serverKey string) (string, bool) {
	tool, ok := extensionAgents[extensionAgent{Extension: extension, ServerKey: serverKey}]
	return tool, ok
}
