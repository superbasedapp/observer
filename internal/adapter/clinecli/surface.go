package clinecli

import (
	"github.com/marmutapp/superbased-observer/internal/models"
)

// surfaceBySource is THE table that resolves Cline CLI's own
// `sessions.source` discriminator into the normalized capture-surface
// vocabulary (models.Surface* + a lowercase host token). Cline writes
// the column on every session row; the adapter already SELECTs it
// (statedb.go::sessionRow.Source, surfaced as the session_start
// Target), so the surface attribution costs no extra read.
//
// The enum vocabulary is Cline's, captured 2026-09-02 from the
// `next` build's session manifest + the @cline/shared session-source
// union: core, cli, subagent, desktop, kanban, api, web, vscode,
// enterprise, ide, jetbrains, neovim, unknown.
//
// This is the ONLY place cline-cli source strings are interpreted
// (CLAUDE.md Module Boundaries #3/#5): everything downstream reads the
// normalized kind + host, never the vendor token. A source value that
// is not a key here — including Cline's own literal "unknown" and the
// empty string — yields NO stamp at all: the honest zero on the
// session row, never a guessed surface.
//
// Note the tool id does NOT split with the surface. Cline `next`
// drives its VS Code / JetBrains / Neovim sessions through the SAME
// sessions.db this adapter reads, so those rows stay
// models.ToolClineCLI and the surface columns are the only split.
var surfaceBySource = map[string]models.SessionSurface{
	// --- terminal surfaces ---------------------------------------
	"cli":      {Surface: models.SurfaceCLI, SurfaceHost: "cline-cli"},
	"core":     {Surface: models.SurfaceCLI, SurfaceHost: "cline-core"},
	"subagent": {Surface: models.SurfaceCLI, SurfaceHost: "cline-subagent"},
	// --- editor surfaces -----------------------------------------
	"vscode":    {Surface: models.SurfaceIDE, SurfaceHost: "vscode"},
	"jetbrains": {Surface: models.SurfaceIDE, SurfaceHost: "jetbrains"},
	"neovim":    {Surface: models.SurfaceIDE, SurfaceHost: "neovim"},
	"ide":       {Surface: models.SurfaceIDE, SurfaceHost: "ide"},
	// --- desktop app ---------------------------------------------
	"desktop": {Surface: models.SurfaceDesktop, SurfaceHost: "cline-desktop"},
	// --- web surfaces --------------------------------------------
	"web":    {Surface: models.SurfaceWeb, SurfaceHost: "cline-web"},
	"kanban": {Surface: models.SurfaceWeb, SurfaceHost: "cline-kanban"},
	// --- programmatic embeddings ---------------------------------
	"api":        {Surface: models.SurfaceSDK, SurfaceHost: "cline-api"},
	"enterprise": {Surface: models.SurfaceSDK, SurfaceHost: "cline-enterprise"},
}

// surfaceForSource resolves one sessions.source value through
// surfaceBySource. ok is false for an unmapped / empty / literal
// "unknown" token, in which case the caller emits nothing.
func surfaceForSource(source string) (models.SessionSurface, bool) {
	s, ok := surfaceBySource[source]
	return s, ok
}

// buildSessionSurfaces emits one models.SessionSurface per session
// whose `source` column maps to a known surface. Sessions with an
// unmapped source contribute nothing (the honest zero — see
// surfaceBySource).
//
// The store write is first-wins-unless-empty and idempotent, so emitting
// the same stamp on every rescan is a no-op; the surface is emitted
// even for sessions the hook-coverage gate skips in buildEvents,
// because the session row itself is still the grounded evidence of
// which surface produced it.
func buildSessionSurfaces(sessions []sessionRow) []models.SessionSurface {
	var out []models.SessionSurface
	for i := range sessions {
		s := &sessions[i]
		if s.ID == "" {
			continue
		}
		surf, ok := surfaceForSource(s.Source)
		if !ok {
			continue
		}
		surf.SessionID = s.ID
		out = append(out, surf)
	}
	return out
}
