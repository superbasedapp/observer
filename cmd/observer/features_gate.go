package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodefeatures/lkgsidecar"
)

// features_gate.go is the READ + WRITE plumbing for the node.features
// tools.disallow LKG sidecar (P6 item 5, docs/plans/plane-b-gateway-
// implementation-tracker-2026-08-29.md Phase P7 residual (a)):
//
//   - the daemon WRITER (makeFeaturesSidecarWriter) materializes the resolved
//     disallow list beside the DB whenever the node.features handle changes
//     state, and
//   - the launcher READER (refuseIfToolDisallowed*) lets a SHORT-LIVED bare
//     CLI launcher (`observer claude|codex|gemini|…`) refuse to launch an
//     org-disallowed tool without any access to the daemon's in-memory handle.
//
// Both sides fail OPEN: an absent/malformed/expired sidecar, an unresolvable
// path, or an empty tool name never blocks a launch. Enforcement is only ever
// ADDED by a live, valid disallow list.

// disallowKeys extracts the true keys of a disallow map as a sorted slice, the
// shape the sidecar writer takes. A nil/empty map yields nil (nothing
// disallowed).
func disallowKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// makeFeaturesSidecarWriter builds the daemon-side node.features LKG sidecar
// writer closure bound to the node's DB-derived sidecar path. It is idempotent
// (json.Marshal sorts keys and NewFile normalizes the list, so an unchanged
// disallow list rewrites byte-identical content) and best-effort: a write
// failure is logged, never fatal. Returns nil when no sidecar path resolves
// (no DB configured) — the handle then no-ops.
func makeFeaturesSidecarWriter(cfg config.Config, version string, logger *slog.Logger) func(disallow []string) {
	path := config.ResolveFeaturesSidecarPath(cfg, "")
	if path == "" {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	return func(disallow []string) {
		f := lkgsidecar.NewFile(version, disallow, time.Time{}, time.Now())
		raw, err := lkgsidecar.Encode(f)
		if err != nil {
			logger.Warn("node.features: could not encode the tools.disallow sidecar", "err", err)
			return
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			logger.Warn("node.features: could not write the tools.disallow sidecar — bare launchers may not see the live disallow list", "path", path, "err", err)
			return
		}
	}
}

// featuresSidecarPathForDB resolves the node.features LKG sidecar path from a
// bare DB path (the shape a launcher spec carries). Empty when no DB path is
// known.
func featuresSidecarPathForDB(dbPath string) string {
	if dbPath == "" {
		return ""
	}
	var cfg config.Config
	cfg.Observer.DBPath = dbPath
	return config.ResolveFeaturesSidecarPath(cfg, "")
}

// refuseIfToolDisallowed reads the node.features LKG sidecar at sidecarPath and
// returns a non-nil error (after printing honest, actionable copy to stderr)
// when tool is on the org disallow list. Fail-open on every other outcome
// (absent/malformed/expired sidecar, empty tool, empty path). tool is an
// integration-registry Capability.Tool name (e.g. "codex", "claude-code").
func refuseIfToolDisallowed(sidecarPath, tool string, stderr io.Writer) error {
	if sidecarPath == "" || tool == "" {
		return nil
	}
	f, _ := lkgsidecar.Read(sidecarPath, time.Now())
	if !f.Disallowed(tool) {
		return nil
	}
	if stderr != nil {
		fmt.Fprintf(stderr,
			"observer: refusing to launch %q — your organization has disallowed this tool fleet-wide (node.features tools.disallow). Contact your administrator to lift the restriction.\n",
			tool)
	}
	return fmt.Errorf("observer: %q is disallowed by org policy (node.features tools.disallow)", tool)
}

// refuseIfToolDisallowedCfg is refuseIfToolDisallowed for a caller that already
// has a resolved config.Config (the claude/codex launchers).
func refuseIfToolDisallowedCfg(cfg config.Config, tool string, stderr io.Writer) error {
	return refuseIfToolDisallowed(config.ResolveFeaturesSidecarPath(cfg, ""), tool, stderr)
}

// refuseIfToolDisallowedDB is refuseIfToolDisallowed for a caller that only has
// a DB path (the shared env launcher).
func refuseIfToolDisallowedDB(dbPath, tool string, stderr io.Writer) error {
	return refuseIfToolDisallowed(featuresSidecarPathForDB(dbPath), tool, stderr)
}

// featuresDisallowSet loads the current disallow set from the sidecar resolved
// from cfg, for a display surface (`observer adapters`). Returns a lookup
// closure and the resolved File (nil when nothing is governed). Fail-open: an
// absent/invalid sidecar yields an always-false lookup.
func featuresDisallowSet(cfg config.Config) (func(tool string) bool, *lkgsidecar.File) {
	f, _ := lkgsidecar.Read(config.ResolveFeaturesSidecarPath(cfg, ""), time.Now())
	return func(tool string) bool { return f.Disallowed(tool) }, f
}
