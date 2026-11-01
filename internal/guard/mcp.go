package guard

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/mcp/locate"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// MCP security integration (guard spec §9, G10). The guard layer owns
// three seams here, all injected at cmd composition because guard
// never imports store (the ApprovalLookup precedent):
//
//   - MCPPinLookup refines TaintSourceMCPUnpinned (§4.5): a server the
//     operator has pinned AND approved stops marking taint, on both
//     the watcher mark site (ingest.go markTaint) and the proxy
//     injection mark site (proxyguard.go scanInjection). The G3 note
//     "every server is unpinned until G10" resolves here.
//   - SetMCPRescan wires the watcher-triggered config re-scan (§9.2):
//     when an evaluated action writes one of the locate-table MCP
//     registry files, the injected callback fires (the cmd layer
//     debounces and runs the scan). Relative-path targets that don't
//     resolve to a registry path don't trigger — the daemon-start
//     baseline scan still covers the change eventually (documented
//     approximation).
//   - EvaluateMCPFindings evaluates mcpsec diff results through the
//     REAL engine so [guard.rules] disable, overrides and mode apply
//     to R-301/302/303/305 exactly like every other rule.

// MCPPinLookup reports whether an MCP server is pinned AND approved
// (guard_pins kind=mcp_server, status=approved, no drifted rows).
// Lookup failures must report false — fail toward "unpinned", never
// toward silently trusting a server.
type MCPPinLookup func(server string) bool

// SetMCPPinLookup wires the pin-status lookup. Nil keeps the G3
// behavior: every MCP server marks mcp_unpinned taint. Set once at
// composition.
func (g *Guard) SetMCPPinLookup(fn MCPPinLookup) {
	g.mcpPins = fn
}

// configWatch is one watched-config-paths trigger consumer: when a
// write-class action targets one of the (normalized) paths, fire
// runs. One mechanism, two consumers (§9.2 MCP re-scan, §13.2 dialect
// drift re-check) — a third consumer registers a new tag here rather
// than minting a parallel trigger.
type configWatch struct {
	paths []string
	fire  func()
}

// setWatch registers (or, with a nil fn, removes) one tagged
// config-path watch. Composition-time only — the watches map is read
// without locking on the ingest path.
func (g *Guard) setWatch(tag string, paths []string, fn func()) {
	if fn == nil || len(paths) == 0 {
		delete(g.watches, tag)
		return
	}
	g.watches[tag] = configWatch{paths: paths, fire: fn}
}

// SetMCPRescan wires the §9.2 config-change re-scan trigger over the
// locate-table MCP registry paths. Nil disables the trigger (hook
// processes, tests). Set once at composition; the callback must be
// cheap or self-debouncing — it runs on the ingest path.
func (g *Guard) SetMCPRescan(fn func()) {
	g.setWatch("mcp", mcpRegistryPaths(g.home), fn)
}

// SetDialectRescan wires the §13.2 native-dialect drift re-check
// trigger over the compiled targets' config paths (the cmd layer
// passes them — the path knowledge lives in guard/compile's target
// table). Nil disables. Same contract as SetMCPRescan: set once at
// composition, callback cheap or self-debouncing.
func (g *Guard) SetDialectRescan(paths []string, fn func()) {
	norm := make([]string, 0, len(paths))
	for _, p := range paths {
		if p != "" {
			norm = append(norm, normalizeMCPPath(p))
		}
	}
	g.setWatch("dialect", norm, fn)
}

// mcpApproved is the nil-safe lookup: a server only stops marking
// taint when a lookup is wired AND it reports approved. Called on the
// rare MCP-result paths only (one indexed read at the cmd wiring),
// mirroring the ApprovalLookup cost posture: the lookup runs when an
// MCP result appears, not per action.
func (g *Guard) mcpApproved(server string) bool {
	return server != "" && g.mcpPins != nil && g.mcpPins(server)
}

// mcpRegistryPaths returns the normalized locate-table paths for the
// rescan trigger, computed once at construction. A location with no file (a
// relocation variable holding a relative value, locate.Location.Unresolved,
// FU-130) has nothing to watch and is left out by that reason, never as the
// "." an empty path would normalize to; the guard's MCP inventory
// (mcpsec.Inventory) reports the variable.
func mcpRegistryPaths(home string) []string {
	if home == "" {
		return nil
	}
	locs := locate.Locations(home)
	out := make([]string, 0, len(locs))
	for _, loc := range locs {
		if loc.Unresolved != "" || loc.Path == "" {
			continue
		}
		out = append(out, normalizeMCPPath(loc.Path))
	}
	return out
}

// normalizeMCPPath canonicalizes a path for registry comparison:
// cleaned, forward slashes, lowercased (correct on the
// case-insensitive filesystems where these configs live; negligible
// false-trigger surface elsewhere — a trigger only causes a re-scan).
func normalizeMCPPath(p string) string {
	return strings.ToLower(filepath.ToSlash(filepath.Clean(p)))
}

// maybeConfigRescan fires each registered config-watch consumer whose
// path set contains the target of a write-class action. MCP consumer:
// project-scoped registries (.mcp.json) still fire R-304 but not the
// re-scan — they are outside the locate inventory's scope. Dialect
// consumer: an agent (or operator tool) editing a compiled native
// config re-checks drift. Each consumer fires at most once per
// action; relative targets that don't resolve to a watched path don't
// trigger (the daemon-start baseline pass still covers the change
// eventually — documented approximation, the §9.2 contract).
func (g *Guard) maybeConfigRescan(in *ActionInput) {
	if len(g.watches) == 0 {
		return
	}
	switch in.ActionType {
	case models.ActionWriteFile, models.ActionEditFile, models.ActionConfigChange:
	default:
		return
	}
	target := in.Target
	if strings.HasPrefix(target, "~/") || strings.HasPrefix(target, `~\`) {
		target = filepath.Join(g.home, target[2:])
	}
	norm := normalizeMCPPath(target)
	for _, w := range g.watches {
		for _, p := range w.paths {
			if p == norm {
				w.fire()
				break
			}
		}
	}
}

// EvaluateMCPFindings evaluates config-layer findings (mcpsec diff +
// poisoning results) through the engine: one KindConfigChange event
// per finding, so each audit row names exactly one subject. The
// events carry watcher capabilities — the scan observes config state
// post-hoc and can never block (the §5.5 rows are flag-in-both-modes
// regardless). Approvals are not consulted: they only downgrade
// ask/deny-class verdicts, which these rows never produce.
//
// Returned verdicts are ready for store.PersistGuardVerdicts; rows
// land session-less and unanchored (no action/api_turn produced
// them — the config file itself is the subject).
func (g *Guard) EvaluateMCPFindings(findings []policy.MCPFinding, now time.Time) []ActionVerdict {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	// One snapshot for the whole finding set (NIT contract).
	es := g.set.Load()
	var out []ActionVerdict
	for i := range findings {
		f := findings[i]
		ev := policy.Event{
			Kind:        policy.KindConfigChange,
			Tool:        f.Client,
			Target:      f.Server,
			Caps:        watcherCaps,
			MCPFindings: []policy.MCPFinding{f},
			Now:         now,
		}
		verdict, guardErr := g.evaluateWith(es, ev)
		if verdict.Decision < policy.DecisionFlag && guardErr == nil {
			continue
		}
		out = append(out, ActionVerdict{
			Input: ActionInput{
				Tool:      f.Client,
				Target:    f.Server,
				Timestamp: now,
			},
			Kind:       policy.KindConfigChange,
			Category:   g.categoryWith(es, verdict.RuleID),
			Verdict:    verdict,
			GuardError: guardErr != nil,
		})
	}
	return out
}
