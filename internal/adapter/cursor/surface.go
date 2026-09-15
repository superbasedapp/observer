package cursor

import (
	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// Cursor persists NO surface discriminator of its own — there is no
// `entrypoint` / `originator` / `source` field anywhere in a
// transcript, a store.db or state.vscdb. What it does have is a STORE
// SHAPE that is written by exactly one client:
//
//   - `.cursor/projects/<slug>/agent-transcripts/<conv>/<conv>.jsonl`
//     and `Cursor/User/globalStorage/state.vscdb` are written by the
//     Cursor IDE (the VS Code fork) — the editor is the only thing
//     that maintains a project-slug transcript tree or the shared
//     global state database.
//   - `.cursor/chats/<ws-hash>/<conv>/store.db` is written by the
//     `cursor-agent` CLI.
//
// That shape is already the adapter's dispatch key (IsSessionFile /
// ParseSessionFile), so the surface mapping rides the SAME enum rather
// than introducing a second classification of the same paths.
//
// The three shapes are NOT equally strong evidence, though: a store.db
// is written only by the CLI, while a transcript or a state.vscdb row
// can exist for a conversation the CLI ran. Because the store's
// SetSessionSurface is first-wins-unless-empty, that asymmetry has to be
// resolved at emission rather than left to parse order — see
// cliStoreOverridable / resolveSurface below.

// storeLayout is the on-disk shape of a Cursor session file. It is the
// one dispatch key for both parsing (ParseSessionFile) and surface
// attribution (surfaceByLayout).
type storeLayout int

const (
	// layoutUnknown is a path none of the shape matchers claim. It
	// parses on the transcript path (the historical default) and is
	// never surface-stamped — an unrecognized shape is not evidence of
	// a client.
	layoutUnknown storeLayout = iota
	// layoutTranscript is `.cursor/projects/<slug>/agent-transcripts/
	// <conv>/<conv>.jsonl`.
	layoutTranscript
	// layoutStoreDB is `.cursor/chats/<ws-hash>/<conv>/store.db`.
	layoutStoreDB
	// layoutStateDB is `<...>/Cursor/User/globalStorage/state.vscdb`.
	layoutStateDB
	layoutCLIUsage
)

// layoutFor classifies path into one of Cursor's session-file shapes.
// Order matters only in that the three matchers are mutually exclusive
// by construction (distinct suffixes + distinct path segments).
func layoutFor(path string) storeLayout {
	switch {
	case matchesCLIUsageLog(path):
		return layoutCLIUsage
	case matchesStoreDBShape(path):
		return layoutStoreDB
	case matchesStateDBShape(path):
		return layoutStateDB
	case matchesSessionShape(path):
		return layoutTranscript
	}
	return layoutUnknown
}

// surfaceByLayout is THE cursor surface table (CLAUDE.md #3/#5): store
// shape -> normalized capture surface. A layout absent from the table
// produces no stamp — the honest "unknown", never a guess.
var surfaceByLayout = map[storeLayout]models.SessionSurface{
	layoutTranscript: {Surface: models.SurfaceIDE, SurfaceHost: "cursor"},
	layoutStateDB:    {Surface: models.SurfaceIDE, SurfaceHost: "cursor"},
	layoutStoreDB:    {Surface: models.SurfaceCLI, SurfaceHost: "cursor-agent"},
	layoutCLIUsage:   {Surface: models.SurfaceCLI, SurfaceHost: "cursor-agent"},
}

// # Precedence: the CLI store wins
//
// The two IDE-side stamps above are WEAKER claims than the store.db one,
// and this is the asymmetry that makes them so:
//
//   - `.cursor/chats/<ws-hash>/<conv>/store.db` is written by ONE client,
//     the `cursor-agent` CLI. Its presence is positive evidence about
//     which client ran the conversation.
//   - An agent-transcript, and a `composerData:` row in the shared
//     `state.vscdb`, are what the Cursor DESKTOP maintains — but a
//     `cursor-agent` run can also leave a conversation id visible in
//     those places. Their evidence is "this conversation exists", not
//     "the IDE ran it".
//
// That matters because the store's SetSessionSurface is
// FIRST-WINS-UNLESS-EMPTY: the first grounded stamp for a session sticks,
// and later stamps only fill in fields the first one left blank. So
// whichever file the watcher happens to parse first would decide the
// surface — and for a `cursor-agent` run whose transcript is parsed
// before its store.db, the IDE stamp would win by pure parse ORDER and
// then be unfixable.
//
// So the resolution is made HERE, at emission, not left to arrival order:
// before stamping a layout listed in cliStoreOverridable, look for that
// conversation's own store.db. If one exists, the conversation is a CLI
// run and gets the CLI stamp, whichever file we happen to be parsing.
//
// cliStoreOverridable is the table of layouts whose stamp is that weaker
// claim. layoutStoreDB is deliberately absent: it IS the strong evidence,
// and asking it to re-derive itself would be circular.
var cliStoreOverridable = map[storeLayout]bool{
	layoutTranscript: true,
	layoutStateDB:    true,
}

// resolveSurface returns the surface to stamp for one conversation id
// under layout, applying the cliStoreOverridable precedence above. The
// bool is false when layout has no row in surfaceByLayout (an
// unrecognized shape is not evidence of a client).
//
// Cost note: the override costs one filepath.Glob per distinct session id
// per parse. For layoutStateDB it is nearly always redundant —
// parseStateDBFile has already dropped every conversation with a
// store.db sibling — but the check is kept there anyway rather than
// depending on another file's filtering to stay correct.
func resolveSurface(layout storeLayout, sessionID string) (models.SessionSurface, bool) {
	sf, ok := surfaceByLayout[layout]
	if !ok {
		return models.SessionSurface{}, false
	}
	if cliStoreOverridable[layout] && cursorAgentStoreExists(sessionID) {
		return surfaceByLayout[layoutStoreDB], true
	}
	return sf, true
}

// stampSurfaces appends one models.SessionSurface per distinct session
// id this parse touched, resolved through resolveSurface (layout's row
// from surfaceByLayout, upgraded to the CLI stamp when that
// conversation's own `cursor-agent` store.db exists).
//
// The id set is every non-empty ToolEvent.SessionID plus hintSessionID
// — the conversation id the per-conversation layouts derive from the
// path itself. The hint matters because both of those paths can
// legitimately produce zero events on a given tick (a transcript whose
// session the live hook already covers, a store.db already parsed to
// EOF) while the session row is very much real and still deserves its
// attribution.
//
// Writes are idempotent downstream (Store.SetSessionSurface is
// first-wins-unless-empty and a missing session id is a silent no-op), so
// a re-stamp costs one matched-zero-rows UPDATE.
func stampSurfaces(res *adapter.ParseResult, layout storeLayout, hintSessionID string) {
	if res == nil {
		return
	}
	if _, ok := surfaceByLayout[layout]; !ok {
		return
	}
	seen := make(map[string]bool, len(res.SessionSurfaces)+len(res.ToolEvents)+1)
	for _, existing := range res.SessionSurfaces {
		seen[existing.SessionID] = true
	}
	add := func(sessionID string) {
		if sessionID == "" || seen[sessionID] {
			return
		}
		seen[sessionID] = true
		stamp, ok := resolveSurface(layout, sessionID)
		if !ok {
			return
		}
		stamp.SessionID = sessionID
		res.SessionSurfaces = append(res.SessionSurfaces, stamp)
	}
	add(hintSessionID)
	for _, ev := range res.ToolEvents {
		add(ev.SessionID)
	}
	for _, ev := range res.TokenEvents {
		add(ev.SessionID)
	}
}

// sessionHintFor returns the conversation id encoded in the path for
// the per-conversation layouts, and "" for state.vscdb (one shared
// file holding many conversations, whose ids are only known from the
// rows the parse actually read).
func sessionHintFor(layout storeLayout, path string) string {
	switch layout {
	case layoutTranscript:
		return convIDFromPath(path)
	case layoutStoreDB:
		return convIDFromStoreDBPath(path)
	}
	return ""
}
