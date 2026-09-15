package kilocode

import (
	"context"
	"path/filepath"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/cline"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/vscodehost"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// LegacyAdapter watches the legacy Kilo Code IDE extension
// (`kilocode.kilo-code`) which is a Cline + Roo Code fork. The
// per-task storage layout — `<globalStorage>/kilocode.kilo-code/
// tasks/<taskId>/api_conversation_history.json` (+ `ui_messages.json`)
// — is BYTE-IDENTICAL to Cline, so we reuse the existing
// internal/adapter/cline parser by wrapping a cline.Adapter with our
// own watch roots and re-tagging every emitted event with
// Tool = models.ToolKiloCode.
//
// The choice of wrapping rather than factoring the cline parser into a
// shared helper avoids touching the cline package's public surface and
// keeps the cline adapter's regression suite untouched as the
// authoritative cookbook for the format.
//
// # DEMOTION: this adapter serves PRE-7.x installs only (audit IDE-06)
//
// Kilo Code's IDE extension >= 7.x no longer persists its own task
// bundles. It spawns the BUNDLED `kilo` CLI and the conversation lands
// in that CLI's store (`~/.local/share/kilo/kilo.db`), which
// CLIAdapter reads and tags models.ToolKiloCodeCLI. There is NO
// persisted discriminator distinguishing an extension-spawned run from
// a terminal one: the extension marks itself with the `KILO_CLIENT`
// PROCESS ENVIRONMENT variable, which never reaches disk. So on a
// current Kilo install an IDE session is indistinguishable from a CLI
// session at rest, and this LegacyAdapter finds nothing at all.
//
// Do not "fix" that by inferring the surface for kilo-code-cli rows —
// there is no grounded signal to infer from, and inventing one would
// violate the honesty rule (plan §3.1). The correct scope of this
// adapter is: installs still on the pre-7.x extension.
//
// # Surface attribution
//
// Surface stamps ride through the delegate untouched. The cline parser
// stamps models.SurfaceIDE unconditionally (its store only ever exists
// inside an editor extension) and resolves the host from the task path
// via internal/platform/vscodehost, so a Kilo task under
// `<Cursor>/User/globalStorage/kilocode.kilo-code/...` correctly stamps
// host "cursor" and one under upstream Code stamps "vscode". Nothing
// in the retag loop touches models.SessionSurface — it carries no Tool
// field, being session-scoped rather than event-scoped.
type LegacyAdapter struct {
	scrubber   *scrub.Scrubber
	watchRoots []string
	delegate   *cline.Adapter
}

// NewLegacy returns a LegacyAdapter with default scrubber and the
// canonical Kilo Code globalStorage paths under every cross-mount-
// resolved $HOME (covers WSL2 reading Windows-side VS Code installs
// and vice-versa).
func NewLegacy() *LegacyAdapter {
	a := &LegacyAdapter{scrubber: scrub.New()}
	a.watchRoots = a.defaultRoots()
	a.delegate = cline.NewWithOptions(a.scrubber, a.watchRoots)
	return a
}

// NewLegacyWithOptions customizes scrubber and/or watch roots (used by
// tests to point at a t.TempDir() rather than the developer's real
// globalStorage).
func NewLegacyWithOptions(s *scrub.Scrubber, watchRoots []string) *LegacyAdapter {
	if s == nil {
		s = scrub.New()
	}
	a := &LegacyAdapter{scrubber: s, watchRoots: watchRoots}
	if len(a.watchRoots) == 0 {
		a.watchRoots = a.defaultRoots()
	}
	a.delegate = cline.NewWithOptions(s, a.watchRoots)
	return a
}

// Name implements adapter.Adapter.
func (*LegacyAdapter) Name() string { return models.ToolKiloCode }

// WatchPaths implements adapter.Adapter.
func (a *LegacyAdapter) WatchPaths() []string { return a.watchRoots }

// IsSessionFile implements adapter.Adapter. Matches the same basename
// as Cline (`api_conversation_history.json`) but constrained to paths
// under THIS adapter's `kilocode.kilo-code/tasks/` roots — preserves
// the v1.4.51 dispatch contract so a foreign-rooted file with the
// same basename can't be silently claimed.
func (a *LegacyAdapter) IsSessionFile(path string) bool {
	if filepath.Base(path) != "api_conversation_history.json" {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

// ParseSessionFile implements adapter.Adapter by delegating to the
// wrapped cline adapter and re-tagging every emitted event with
// Tool = models.ToolKiloCode. The format is identical between the two
// products; only the dashboard-facing attribution differs.
func (a *LegacyAdapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	res, err := a.delegate.ParseSessionFile(ctx, path, fromOffset)
	if err != nil {
		return res, err
	}
	for i := range res.ToolEvents {
		res.ToolEvents[i].Tool = models.ToolKiloCode
	}
	for i := range res.TokenEvents {
		res.TokenEvents[i].Tool = models.ToolKiloCode
	}
	return res, nil
}

// legacyExtensionID is the marketplace id whose globalStorage the
// legacy Kilo IDE extension writes its per-task bundles into.
const legacyExtensionID = "kilocode.kilo-code"

// defaultRoots returns the canonical `kilocode.kilo-code/tasks/` paths
// under EVERY VS Code-family product (upstream Code, Code - Insiders,
// VSCodium, Cursor, Windsurf, Kiro, Qoder, Trae) and every remote
// server layout (.vscode-server, .cursor-server), for every
// cross-mount-resolved $HOME.
//
// Product enumeration is delegated wholesale to
// internal/platform/vscodehost (audit IDE-14). It previously hand-
// rolled the per-OS convention for upstream "Code" plus a single
// `.vscode-server` special case, so a Kilo task recorded inside any
// fork host — or inside a Cursor Server remote — was never watched.
//
// Non-existent roots are returned deliberately (Invariant #48); the
// watcher owns existence filtering and root-identity dedup.
func (a *LegacyAdapter) defaultRoots() []string {
	var roots []string
	for _, h := range crossmount.AllHomes() {
		for _, ref := range vscodehost.GlobalStorageDirs(h) {
			roots = append(roots, filepath.Join(ref.Path, legacyExtensionID, "tasks"))
		}
	}
	return roots
}
