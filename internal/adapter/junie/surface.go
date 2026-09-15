package junie

import "github.com/marmutapp/superbased-observer/internal/models"

// This file owns Junie's self-reported capture-surface attribution. Until
// 2026-09-07 the package doc's "Capture surface: no self-report, by
// design" section was accurate: no live CLI session existed to compare
// against the two IDE-hosted fixtures (2026-08-16 plain plugin,
// 2026-09-03 AI-Assistant/MCP), so every session shipped with no
// models.SessionSurface stamp at all.
//
// On 2026-09-07 the operator ran BOTH lanes back to back against the
// same prompt and project: the standalone CLI
// (`junie --session-id session-260907-002452-gk1t`, anonymised into
// testdata/junie/cli/session-260907-002452-cli1/) and an IntelliJ IDEA
// 2026.2 AI-Assistant run (`session-260907-002018-1eui`, which
// internal/surfaceenrich independently stamped `ide`/`jetbrains-idea`
// from its `aia-task-history/*.agentsession` pointer). Diffing the two
// `events.jsonl` files — still no explicit client/host/transport field
// on any record — surfaced two POSITIVE (not absence-based) structural
// markers, each cross-checked against the two pre-existing IDE fixtures
// too:
//
//  1. IDE marker — the session's first UserPromptEvent carries an
//     `extraAttachments` entry of kind
//     "TaskRequestMcpServersAttachment" whose `mcpServers[].env[]`
//     names an `IJ_MCP_AUTH_TOKEN` key (plus `name:"idea"`,
//     `args:["stdioMcpServer"]` — never decoded past the key names, see
//     extraAttachmentRaw), naming the MCP server the IDE itself spawns
//     for Junie to call over MCP (`idea64.exe stdioMcpServer`).
//     PRESENT on both real IDE-hosted captures (the 2026-09-03
//     jetbrains-mcp fixture and the new 2026-09-07 IDE run); ABSENT on
//     the CLI run AND on the older 2026-08-16 plain-plugin fixture
//     (predating the AI-Assistant merge, so it never gets IDE-served
//     MCP tools either — a plugin session with no positive marker
//     still gets no self-stamp, exactly today's behavior, not a
//     regression). The attachment KIND alone ("TaskRequestMcpServersAttachment")
//     is deliberately NOT the discriminator: the CLI lane also runs MCP
//     clients (33 "Initializing MCP clients" status lines observed in
//     the 2026-09-07 CLI capture) whenever the operator configures one,
//     so a CLI run with a user-configured MCP server could carry the
//     same attachment kind with no `IJ_MCP_AUTH_TOKEN` key — the
//     IDE-specific fact hasIDEMCPAttachment requires.
//  2. CLI marker — a top-level `SessionCostTrajectorySnapshotEvent`
//     record (kindCostTrajectorySnapshot), the CLI's own end-of-task
//     cost-breakdown table, emitted once right before the task's
//     TaskState. PRESENT on the 2026-09-07 CLI run; ABSENT from BOTH
//     completed IDE fixtures (2026-09-03 jetbrains-mcp AND the
//     2026-08-16 plain-plugin capture both reach TaskState:"COMPLETED"
//     without ever emitting it) — so its absence on those two is not
//     an artifact of an incomplete session, it is a genuine CLI-only
//     terminal rendering feature (the IDE already shows a cost panel
//     of its own and has no reason to write this record). Caveat: this
//     marker is grounded on a SINGLE CLI build against two older IDE
//     fixtures, so it could in principle be a version-specific property
//     of that one CLI release rather than a durable CLI-vs-IDE fact;
//     the hosted enricher stamp (see below) mitigates the risk wherever
//     an `.agentsession` pointer resolves, since it always wins over
//     this self-report regardless of which marker fired it.
//
// Both markers are grounded across 3 independent completed sessions
// (1 CLI, 2 IDE, spanning two different IDE-hosting vintages), and
// neither one is "absence of the other" — a session with NEITHER
// marker (e.g. a plain-plugin session, or one truncated before its
// first UserPromptEvent's attachments were captured) still gets no
// stamp, honestly.
//
// # Why the IDE self-stamp cannot fight the enricher
//
// A self-reported IDE stamp from this file always has Hosted=false.
// internal/surfaceenrich's `aia-task-history` stamp always has
// Hosted=true and, per store.setHostedSessionSurface, REPLACES a
// differing self-report rather than being blocked by first-wins. So
// when both fire for the same session, the enricher's more specific
// product token (`jetbrains-idea`, `jetbrains-pycharm`, ...) always
// wins — this file's generic "jetbrains" is a same-fact placeholder,
// useful only for the window before the enricher's pointer resolves,
// or for an install where the pointer file has since been pruned
// (JetBrains task-history retention) and the enricher never runs. It
// never overrides a hosted stamp because the store's hosted branch has
// no first-wins guard to defeat.
//
// # Considered and rejected: inferring CLI from a missing enricher pointer
//
// A tempting THIRD signal: since internal/surfaceenrich retries a
// hosted stamp only while its `.agentsession` pointer file is younger
// than Options.Window, one might infer "no pointer ever showed up
// within the window" as evidence the session was CLI-driven. Rejected:
// JetBrains merging the Junie plugin into AI Assistant
// (com.intellij.ml.llm, see the package doc's "three surfaces, one
// store" section) does not mean EVERY IDE-hosted Junie run goes through
// AI Assistant's ACP registry today. An install still running the
// pre-merge standalone plugin lane (the 2026-08-16 Phase-0 shape) is
// IDE-hosted but writes no `.agentsession` pointer at all — the exact
// case TestPlainPluginFixtureNoSurfaceStamp pins. "No pointer" is
// therefore ambiguous between "this was CLI" and "this was the
// pre-merge plugin lane", i.e. an absence-based inference, which the
// models.SessionSurface honesty rule forbids (CLAUDE.md #3/#5: resolve
// from a grounded positive discriminator, never from what's missing).
// It would also structurally FIGHT a hosted stamp that simply arrives
// late (a slow ingest, a daemon restart mid-retry-window) — a false
// self-report landing before the true hosted one would block it
// outright, since a plain self-report is first-wins-unless-empty.
// Revisit only if a live pre-merge-plugin-vs-AI-Assistant install
// distribution is grounded well enough to bound the false-positive
// rate; the two positive markers above need no such bound.
//
// # Why this file does not try to name a specific JetBrains product
//
// The only IDE-side evidence in events.jsonl is the MCP server's
// command path (e.g. `...\IntelliJ IDEA 2026.2.2\bin\idea64.exe`), not
// a `JetBrains.<Product>` client-name string the way codex/copilot-cli
// self-stamp through jetbrainshost.HostForClientName. Parsing a product
// name out of an arbitrary local install path would be a guess, not a
// grounded discriminator, so this file uses jetbrainshost's own
// documented fallback instead: the bare "jetbrains" token for "an IDE,
// product unknown" (internal/platform/jetbrainshost's doc, "Host
// tokens"). The enricher supplies the real product once its pointer
// resolves.
const (
	// hostJunieCLI is the surface-host token for the standalone `junie`
	// CLI, matching the tool-id+"-cli" convention codex/copilot-cli use
	// ("codex-cli", "copilot-cli").
	hostJunieCLI = "junie-cli"
	// hostJunieIDEUnknown is the generic "an IDE hosted this, product
	// unknown" token — see the file doc's "why not a specific product"
	// section.
	hostJunieIDEUnknown = "jetbrains"
	// ideAttachmentKind is the extraAttachments entry kind an IDE
	// injects to hand Junie its own MCP server (see the file doc). On
	// its own this is too weak a signal: it is a generic
	// attachment-kind label, and the CLI lane demonstrably runs MCP
	// clients too (33 "Initializing MCP clients" status lines observed
	// in the 2026-09-07 CLI capture) whenever the operator has
	// configured one, so a CLI run with a user-configured MCP server
	// could otherwise carry this same kind. hasIDEMCPAttachment below
	// additionally requires mcpAuthTokenKey.
	ideAttachmentKind = "TaskRequestMcpServersAttachment"
	// mcpAuthTokenKey is the env key name IntelliJ's own MCP server
	// wiring carries (alongside IJ_MCP_SERVER_PROJECT_PATH/_PORT, not
	// decoded — see extraAttachmentRaw) — grounded on both real IDE
	// captures (2026-09-03 jetbrains-mcp, 2026-09-07 IDE run) — that a
	// user-configured CLI-side MCP server has no reason to ever set,
	// since it is IntelliJ's own internal auth handshake, not part of
	// the MCP protocol. This is the IDE-SPECIFIC fact hasIDEMCPAttachment
	// requires; the generic ideAttachmentKind alone is not sufficient.
	mcpAuthTokenKey = "IJ_MCP_AUTH_TOKEN" //nolint:gosec // G101: this is an env KEY NAME used for matching, never a credential value
)

// hasIDEMCPAttachment reports whether atts carries the IDE-injected
// MCP-server wiring attachment: an entry of kind ideAttachmentKind
// whose mcpServers[] declares an env key named mcpAuthTokenKey. Kind
// alone is not enough — see ideAttachmentKind's doc — so this also
// requires the IDE-specific auth-token key name (never its value).
func hasIDEMCPAttachment(atts []extraAttachmentRaw) bool {
	for _, a := range atts {
		if a.Kind != ideAttachmentKind {
			continue
		}
		for _, srv := range a.MCPServers {
			for _, env := range srv.Env {
				if env.Key == mcpAuthTokenKey {
					return true
				}
			}
		}
	}
	return false
}

// junieCLISurface and junieIDESurface build the two ordinary
// self-reports (Hosted stays false in both — see the file doc) for
// sessionID. Callers guard against emitting more than one per parse
// call and against an empty sessionID.
func junieCLISurface(sessionID string) models.SessionSurface {
	return models.SessionSurface{SessionID: sessionID, Surface: models.SurfaceCLI, SurfaceHost: hostJunieCLI}
}

func junieIDESurface(sessionID string) models.SessionSurface {
	return models.SessionSurface{SessionID: sessionID, Surface: models.SurfaceIDE, SurfaceHost: hostJunieIDEUnknown}
}
