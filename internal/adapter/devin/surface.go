package devin

import (
	"encoding/json"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// This file owns Devin's SESSION-LANE attribution: which client produced
// a session (the capture surface) and whether Devin spawned the session
// for itself (the sidecar lineage). Both are resolved from grounded
// columns of the `sessions` row at the adapter boundary and handed
// downstream as normalized values, so nothing outside this file ever
// interprets a Cognition-specific token (CLAUDE.md #3/#5).
//
// # Why the surface is NOT keyed on the watch root
//
// Devin Desktop 2.3.15 (the renamed Windsurf VS Code fork) does not
// carry its own session store: the desktop-bundled CLI writes the SAME
// store the standalone CLI does. Grounded on Windows 2026-09-03 —
// %APPDATA%\Devin\cli\sessions.db is byte-for-byte the path this
// adapter's Windows watch root already covers (`AppData\Roaming\devin\
// cli`), because NTFS is case-insensitive and Devin Desktop's Electron
// user-data directory is named "Devin". The live WSL daemon captured
// that desktop run through the existing root with no change at all.
//
// So on Windows there is no root-shaped discriminator to key a table
// on — one directory serves both lanes. And whether the two lanes
// diverge on macOS/Linux (the desktop's Electron user-data dir would be
// ~/Library/Application Support/Devin resp. ~/.config/Devin, next to
// the CLI's XDG ~/.local/share/devin/cli) is NOT grounded: no Devin
// Desktop install on those OSes has been inspected, and docs.devin.ai
// documents only the legacy Cascade config dir (~/.codeium/windsurf,
// empty on the live box). Keying a surface on the root would therefore
// be a guess on every platform — see docs/devin-adapter.md.
//
// The one grounded per-session discriminator is `sessions.metadata`:
// Devin Desktop stamps `client_meta["cognition.ai/requestingTabId"]`
// (the editor tab that requested the session) on the sessions it opens.
// The same tab id appears in the desktop's own globalStorage
// (`windsurf.acp.sessioninfo.session.acp/devin-cli/<name>`), which is
// what makes it a client marker rather than a coincidence.

// sessionMetadata is the decoded `sessions.metadata` JSON — a column
// added by the store's own migration 16 (`add_session_json_metadata`),
// so it is absent on older stores and the zero value must stay
// meaningful. Only the keys this package interprets are typed; the
// cost/telemetry keys (`total_credit_cost`, `total_acu_cost`,
// `response_dimensions`) are deliberately ignored — they were 0 / display
// strings in the live capture.
type sessionMetadata struct {
	// ClientMeta is the vendor-namespaced bag the requesting client
	// stamps on the session (`cognition.ai/...` keys).
	ClientMeta map[string]json.RawMessage `json:"client_meta"`
}

// surfaceRule is one row of [surfaceRules]: a `client_meta` key whose
// mere PRESENCE identifies the client that opened the session, plus the
// normalized surface that client is.
type surfaceRule struct {
	// MetaKey is the sessions.metadata.client_meta key to look for.
	MetaKey string
	// Surface is the stamp emitted when MetaKey is present.
	Surface models.SessionSurface
}

// surfaceRules is THE table mapping Devin's own client markers onto the
// normalized capture-surface vocabulary. Ordered: first present key
// wins. A session matching no row gets NO stamp — the honest zero
// (models.SessionSurface's contract), never a guess. In particular a
// session with no client_meta at all is NOT assumed to be a terminal
// session: on Windows the desktop and the standalone CLI share one
// store, so "no desktop marker" does not prove "CLI".
var surfaceRules = []surfaceRule{
	// Grounded live 2026-09-03 on Devin Desktop 2.3.15 (Windows): the
	// desktop stamps the requesting editor tab id
	// ("new-1788427379552-qrbhyvaz2") on every session it opens. The
	// standalone CLI has no editor tab, so the key cannot appear there.
	{
		MetaKey: "cognition.ai/requestingTabId",
		Surface: models.SessionSurface{Surface: models.SurfaceIDE, SurfaceHost: "devin-desktop"},
	},
}

// surfaceForSession resolves one session's capture surface through
// [surfaceRules]. ok is false when no rule matches (or the session has
// no id), in which case the caller emits nothing.
func surfaceForSession(s sessionRow) (models.SessionSurface, bool) {
	if s.ID == "" || s.Metadata == "" {
		return models.SessionSurface{}, false
	}
	var md sessionMetadata
	if err := json.Unmarshal([]byte(s.Metadata), &md); err != nil {
		return models.SessionSurface{}, false
	}
	for _, r := range surfaceRules {
		if _, ok := md.ClientMeta[r.MetaKey]; !ok {
			continue
		}
		out := r.Surface
		out.SessionID = s.ID
		return out, true
	}
	return models.SessionSurface{}, false
}

// threadSourceSubagent is the models.SessionLineage.ThreadSource value
// for a session an agent runtime spawned for itself, matching what the
// opencode / openclaw adapters already write (the read model is
// tool-agnostic).
const threadSourceSubagent = "subagent"

// lineageForSession marks Devin's MACHINE-SPAWNED sidecar sessions.
//
// Devin persists its own internal agent runs as ordinary rows in the
// same store, flagged `hidden = 1` (the store's migration 15
// `add_hidden_column`, with a dedicated idx_sessions_hidden) so they
// never appear in the session picker. Grounded 2026-09-03: after a
// five-turn desktop run the store held the user's session (hidden = 0)
// plus a `hidden = 1` summary-agent session whose nodes were generated
// by the `summarizer` model, whose working_directory was the drive root
// `C:\`, and whose sole user message was the parent conversation pasted
// in for summarization. The desktop's own globalStorage names that lane
// explicitly — `acp/summary-agent/<name>` against the user lane's
// `acp/devin-cli/<name>`, linked by a
// `windsurf.acp.session/summaryState/...` key carrying
// {"prefixedSessionId":"acp/summary-agent/<name>"}.
//
// The rows are kept, not dropped: they are real spend and real activity,
// and the store row exists either way. They are MARKED instead, through
// the repo's existing "not a user session" mechanism
// (models.SessionLineage.ThreadSource = "subagent"), so the session
// detail flags them and any future user-session count has a column to
// filter on. ParentThreadID is deliberately left empty: the parent link
// is NOT in this store (it lives in the desktop's VS Code globalStorage,
// which this adapter does not read), and SetSessionLineage is
// COALESCE-preserving so an empty field is a no-op rather than a lie.
//
// Accepted limitation: if a future Devin build lets a USER hide a
// session, that session would be marked a sidecar too. `hidden` is
// Devin's own "not user-facing" flag and is the only in-store marker of
// the lane; the narrower alternatives (matching the `summarizer` model
// name, or the "Summarizer" display label in metadata.response_dimensions)
// are vendor display strings that would miss every other sidecar kind.
func lineageForSession(s sessionRow) (models.SessionLineage, bool) {
	if s.ID == "" || !s.Hidden {
		return models.SessionLineage{}, false
	}
	return models.SessionLineage{SessionID: s.ID, ThreadSource: threadSourceSubagent}, true
}
