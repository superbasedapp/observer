package config

// This file holds the config types of [loc]: lines-of-code tracking.

// DefaultLocEditorTokenFile is where the daemon keeps the per-install
// editor-endpoint secret when [loc].editor_token_file is unset. It sits in
// the observer home beside observer.db and config.toml; Load() expands the
// leading "~/" the same way it does for observer.db_path.
const DefaultLocEditorTokenFile = "~/.observer/loc-editor-token" //nolint:gosec // G101: a PATH, not a credential

// LocConfig is the [loc] surface — lines-of-code tracking
// (docs/loc-tracking.md). LOCAL-ONLY, never distributed to an org server
// (same posture as [predict]/[routing]/[cachewarm]). Same partial-merge
// invariant as CacheTrackConfig: an install with no [loc] section gets
// the Default() seed, NOT the zero value, because Load() starts from
// Default() and unmarshals TOML on top.
//
// The block holds ONLY the editor-endpoint credential today. The
// classifier itself has no knobs: it runs over rows the store already
// holds and its behaviour is versioned by internal/loc.Version, not by
// config.
type LocConfig struct {
	// EditorTokenFile is where the daemon keeps the per-install shared
	// secret the VS Code extension sends as X-Observer-Token on
	// POST /api/loc/editor-change. The daemon GENERATES the file on
	// first start (32 random bytes, hex, mode 0600) and never logs its
	// contents; the extension reads the same path.
	//
	// Default "~/.observer/loc-editor-token" — beside observer.db and
	// config.toml, so an operator who relocates the observer home by
	// hand relocates this with it in one edit.
	//
	// A file the daemon cannot read is NOT fatal: the endpoint keeps its
	// loopback + Origin posture and a warning is logged. Blocking daemon
	// start on a credential that only hardens one reporting endpoint
	// would trade a whole install for a hardening measure.
	EditorTokenFile string `toml:"editor_token_file"`
	// EditorTokenRequired makes the token MANDATORY on
	// POST /api/loc/editor-change: a request with no token, or with the
	// wrong one, is refused 401.
	//
	// Default FALSE this release. An extension older than the token file
	// sends nothing, and flipping the default before installs have caught
	// up would silently stop human-line capture on every one of them.
	// A request that DOES carry a token is verified either way — a wrong
	// token is never silently accepted. The default flips to true in a
	// later release; set it now on an install whose extension is current.
	EditorTokenRequired bool `toml:"editor_token_required"`
}
