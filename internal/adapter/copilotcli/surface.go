package copilotcli

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/jetbrainshost"
)

// This file owns Copilot CLI's SESSION-LANE capture-surface attribution:
// which client drove the session. The grounded discriminator is one line
// of the session's own `workspace.yaml`:
//
//	client_name: JetBrains.IntelliJ IDEA   (the IDE's ACP agent registry)
//	client_name: github/cli                (the interactive `copilot` CLI)
//
// Both values were captured live on 2026-09-03 from the operator's own
// ~/.copilot/session-state: the JetBrains value from an IntelliJ IDEA
// 2026.2 AI Assistant run through the GitHub Copilot ACP agent (Copilot
// CLI 1.0.79), the `github/cli` value from an ordinary terminal
// `copilot` run (1.0.60). Nothing else in the session's own record
// distinguishes them — `session.start.data.producer` is "copilot-agent"
// and `copilotVersion` is just the CLI build on BOTH — so `client_name`
// is the single seam, resolved here into the normalized
// models.Surface* vocabulary at the adapter boundary (CLAUDE.md #3/#5).
//
// # What is deliberately NOT in the table
//
//   - A VS Code row. `client_name` for a VS Code-hosted Copilot CLI
//     session is UNGROUNDED — no such session exists on the grounding
//     box. The one session-state directory carrying a
//     `vscode.metadata.json` sidecar (946bfb36…) is exactly the
//     `github/cli` terminal run above, so that sidecar is NOT a
//     VS-Code-hosted marker and must not be read as one. When a real
//     VS Code-hosted session is captured, its value becomes one more
//     row here — see docs/copilot-cli-smoke-test.md.
//   - A rule for an ABSENT `client_name`. Copilot CLI wrote no
//     `client_name` at all on older builds, so "absent" means "old
//     build", not "terminal": it is the honest unknown and gets no
//     stamp (the models.SessionSurface contract).
//   - A rule for an unrecognised non-JetBrains value. Same honesty
//     rule — a future `client_name` this table has not seen resolves to
//     nothing rather than to a guessed kind.
//
// Every stamp emitted here is an ORDINARY self-report
// (models.SessionSurface.Hosted stays false): it is what the agent's own
// store says about itself. The JetBrains AI Assistant's separate
// aia-task-history record produces the HOSTED stamp for the same session
// through internal/surfaceenrich; the two agree on `ide` /
// `jetbrains-idea` by construction, because both resolve the same
// product vocabulary through internal/platform/jetbrainshost.

// hostCopilotCLI is the surface-host token for the interactive Copilot
// CLI itself — the tool id, matching how the codex adapter tokenizes its
// own CLI lane ("codex-cli").
const hostCopilotCLI = "copilot-cli"

// clientNameJetBrainsPrefix is re-exported from jetbrainshost so the
// table row below reads as data rather than as a call.
const clientNameJetBrainsPrefix = jetbrainshost.ClientNamePrefix

// clientSurfaceRule is one row of [clientSurfaceRules]: how to recognise
// a `workspace.yaml` client_name, and what surface it resolves to.
type clientSurfaceRule struct {
	// Exact is the verbatim client_name this row claims, matched
	// case-insensitively. Empty when the row matches by Prefix instead.
	Exact string
	// Prefix, when non-empty, claims every client_name starting with it
	// (case-SENSITIVE, because the vendor writes a fixed literal).
	Prefix string
	// Kind is the models.Surface* constant this row resolves to.
	Kind string
	// Host is the fixed surface-host token. Left empty on the JetBrains
	// row, where HostFn refines the host per product instead.
	Host string
	// HostFn refines the host from the full client_name. When it
	// reports !ok the row does not match after all and the walk
	// continues.
	HostFn func(clientName string) (string, bool)
}

// clientSurfaceRules is THE ordered table of grounded `client_name`
// values. Walked top-down; the first matching row wins. A client_name
// matching no row yields NO stamp — see the file doc's honesty note.
var clientSurfaceRules = []clientSurfaceRule{
	// JetBrains AI Assistant drives Copilot CLI through its ACP agent
	// registry and stamps "JetBrains.<Product>". The product half is
	// resolved by the ONE owner of JetBrains host vocabulary so this
	// adapter never carries a second product table.
	{Prefix: clientNameJetBrainsPrefix, Kind: models.SurfaceIDE, HostFn: jetbrainshost.HostForClientName},
	// The interactive `copilot` CLI's own default client identity
	// (npm package @github/copilot). Grounded on the 1.0.60 terminal
	// run described in the file doc.
	{Exact: "github/cli", Kind: models.SurfaceCLI, Host: hostCopilotCLI},
}

// surfaceForClientName resolves a session's `workspace.yaml`
// `client_name` into a capture-surface stamp for sessionID. ok is false
// when sessionID or clientName is empty, or when clientName matches no
// row of [clientSurfaceRules] — in which case the caller emits nothing.
func surfaceForClientName(sessionID, clientName string) (models.SessionSurface, bool) {
	name := strings.TrimSpace(clientName)
	if sessionID == "" || name == "" {
		return models.SessionSurface{}, false
	}
	for _, r := range clientSurfaceRules {
		host, ok := matchClientRule(r, name)
		if !ok {
			continue
		}
		return models.SessionSurface{
			SessionID:   sessionID,
			Surface:     r.Kind,
			SurfaceHost: host,
		}, true
	}
	return models.SessionSurface{}, false
}

// matchClientRule reports whether name matches rule r and, if so, the
// host token the row resolves to.
func matchClientRule(r clientSurfaceRule, name string) (string, bool) {
	switch {
	case r.Prefix != "":
		if !strings.HasPrefix(name, r.Prefix) {
			return "", false
		}
	case r.Exact != "":
		if !strings.EqualFold(name, r.Exact) {
			return "", false
		}
	default:
		return "", false
	}
	if r.HostFn != nil {
		return r.HostFn(name)
	}
	return r.Host, true
}
