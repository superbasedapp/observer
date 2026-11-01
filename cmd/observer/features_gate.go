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
func makeFeaturesSidecarWriter(cfg config.Config, version string, logger *slog.Logger) func(disallow []string, terminals *lkgsidecar.Terminals) {
	path := config.ResolveFeaturesSidecarPath(cfg, "")
	if path == "" {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	return func(disallow []string, terminals *lkgsidecar.Terminals) {
		f := lkgsidecar.NewFile(version, disallow, time.Time{}, time.Now())
		raw, err := lkgsidecar.Encode(f)
		if err != nil {
			logger.Warn("node.features: could not encode the tools.disallow sidecar", "err", err)
			return
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			logger.Warn("node.features: could not write the tools.disallow sidecar - bare launchers may not see the live disallow list", "path", path, "err", err)
		}
		// The terminals rule goes in its own sibling file (OSH-R-003, audit
		// F2), so the disallow sidecar keeps the exact shape an older binary
		// decodes. Written on every state change, nil when not governed.
		traw, err := lkgsidecar.EncodeTerminals(lkgsidecar.NewTerminalsFile(version, terminals, time.Now()))
		if err != nil {
			logger.Warn("node.features: could not encode the terminals sidecar", "err", err)
			return
		}
		if err := os.WriteFile(lkgsidecar.TerminalsPath(path), traw, 0o600); err != nil {
			logger.Warn("node.features: could not write the terminals sidecar - bare launchers may not see the live terminals rule", "path", lkgsidecar.TerminalsPath(path), "err", err)
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
//
// A disallowed tool still launches under a verified org tool access grant for
// exactly that tool (request-grants G8): the grant is read from the node's
// own re-verified grant cache in dbPath, one use is counted per launch, and
// the launch says so on stderr. Without one, the refusal names the request
// path. The grant is consulted only for a disallowed tool.
func refuseIfToolDisallowed(sidecarPath, dbPath, tool string, stderr io.Writer) error {
	return refuseIfToolDisallowedMode(sidecarPath, dbPath, tool, stderr, true)
}

// refuseIfToolDisallowedMode is the gate with the use-counting choice made
// explicit (review M3-10): claim=true counts one use and is called ONLY by the
// process that starts the tool binary itself (the bare path of `observer
// <tool>`, or the inner launcher a dashboard / attach PTY runs), so a launch
// counts exactly once; claim=false is the same verified answer without a
// count, for a gate in front of a process that will claim (the pre-attach
// check, the dashboard's CreateFresh).
func refuseIfToolDisallowedMode(sidecarPath, dbPath, tool string, stderr io.Writer, claim bool) error {
	if sidecarPath == "" || tool == "" {
		return nil
	}
	f, _ := lkgsidecar.Read(sidecarPath, time.Now())
	if !f.Disallowed(tool) {
		return nil
	}
	if dbPath != "" {
		read := peekToolGrant
		if claim {
			read = claimToolGrant
		}
		if c := read(hookOrgGrantOpener(dbPath), 3*time.Second, tool); c.OK {
			if stderr != nil && claim {
				fmt.Fprintf(stderr, "observer: your organization disallows %q; launching it under org grant #%d%s.\n",
					tool, c.Hit.GrantID, grantWindowWords(c.Hit.ExpiresAtNs, c.Hit.UsesLeft))
			}
			return nil
		}
	}
	if stderr != nil {
		fmt.Fprintf(stderr,
			"observer: refusing to launch %q: your organization has disallowed this tool (node.features tools.disallow). "+
				"Request access: `observer request tool %s \"<reason>\"`, or the Requests page on the Observer dashboard.\n",
			tool, tool)
	}
	return fmt.Errorf("observer: %q is disallowed by org policy (node.features tools.disallow)", tool)
}

// refuseIfToolDisallowedCfg is refuseIfToolDisallowed for a caller that already
// has a resolved config.Config (the claude/codex launchers).
func refuseIfToolDisallowedCfg(cfg config.Config, tool string, stderr io.Writer) error {
	return refuseIfToolDisallowed(config.ResolveFeaturesSidecarPath(cfg, ""), cfg.Observer.DBPath, tool, stderr)
}

// refuseIfToolDisallowedPeekCfg is the no-count gate for a launcher that may
// hand the launch to the daemon (attach): it refuses a disallowed tool with no
// covering grant, and otherwise counts nothing, because the process that
// finally starts the tool claims the use (refuseIfToolDisallowedCfg on the
// bare path, or the daemon-spawned inner launcher).
func refuseIfToolDisallowedPeekCfg(cfg config.Config, tool string, stderr io.Writer) error {
	return refuseIfToolDisallowedMode(config.ResolveFeaturesSidecarPath(cfg, ""), cfg.Observer.DBPath, tool, stderr, false)
}

// refuseIfToolDisallowedDB is refuseIfToolDisallowed for a caller that only has
// a DB path (the shared env launcher).
func refuseIfToolDisallowedDB(dbPath, tool string, stderr io.Writer) error {
	return refuseIfToolDisallowed(featuresSidecarPathForDB(dbPath), dbPath, tool, stderr)
}

// featuresDisallowSet loads the current disallow set from the sidecar resolved
// from cfg, for a display surface (`observer adapters`). Returns a lookup
// closure and the resolved File (nil when nothing is governed). Fail-open: an
// absent/invalid sidecar yields an always-false lookup.
func featuresDisallowSet(cfg config.Config) (func(tool string) bool, *lkgsidecar.File) {
	f, _ := lkgsidecar.Read(config.ResolveFeaturesSidecarPath(cfg, ""), time.Now())
	return func(tool string) bool { return f.Disallowed(tool) }, f
}
