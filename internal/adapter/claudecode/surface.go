package claudecode

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// This file resolves Claude Code's `entrypoint` JSONL field (present
// on every line, 100% of a 60-file sample taken 2026-09-02) into the
// normalized models.Surface* capture-surface vocabulary (Part E of
// docs/plans/ide-surface-capture-remediation-plan-2026-09-02.md,
// IDE-15 provenance half). CLAUDE.md #5: a lookup table, not a
// growing if/else ladder.

// surfaceRow is one resolved (kind, host) pair.
type surfaceRow struct {
	kind string
	host string
}

// claudeEntrypointSurface maps the exact `entrypoint` values sampled
// live. "cli" is by far the majority; "claude-desktop" is Claude
// Desktop's own Claude Code tab (47/60 in the sample — Claude
// Desktop, not the cowork agent-mode audit log, which is a wholly
// separate adapter/format). "claude-jetbrains" is documented in the
// plan as unverified spelling — kept here so a future confirmed
// sighting needs no code change, only removing the caveat.
var claudeEntrypointSurface = map[string]surfaceRow{
	"cli":              {kind: models.SurfaceCLI, host: "claude"},
	"claude-vscode":    {kind: models.SurfaceIDE, host: "vscode"},
	"claude-jetbrains": {kind: models.SurfaceIDE, host: "jetbrains"},
	"claude-desktop":   {kind: models.SurfaceDesktop, host: "claude-desktop"},
}

// sdkEntrypointPrefix is the vendor vocabulary for programmatic Agent
// SDK embeddings: "sdk-ts", "sdk-py", etc. The host token is
// whatever follows the prefix, so a language SDK Observer hasn't
// seen yet still resolves without a table update.
const sdkEntrypointPrefix = "sdk-"

// resolveClaudeSurface resolves one `entrypoint` value into (kind,
// host). Unknown entrypoints (a vendor token this table hasn't
// caught up with) return ok=false — the caller emits no
// SessionSurface row rather than guess, per the SessionSurface
// contract's honesty rule.
func resolveClaudeSurface(entrypoint string) (kind, host string, ok bool) {
	if row, hit := claudeEntrypointSurface[entrypoint]; hit {
		return row.kind, row.host, true
	}
	if strings.HasPrefix(entrypoint, sdkEntrypointPrefix) {
		host := strings.TrimPrefix(entrypoint, sdkEntrypointPrefix)
		if host == "" {
			host = "sdk"
		}
		return models.SurfaceSDK, host, true
	}
	if entrypoint == "sdk" {
		return models.SurfaceSDK, "sdk", true
	}
	return "", "", false
}
