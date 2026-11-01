package integration

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// hooksurface.go is the per-surface hook scope side table (surface-gap arc
// Wave 3, findings CX-1 and W-5; the routeSurfaces precedent). A tool's
// HookSpec says which events Observer registers, but a product ships several
// capture surfaces and they do not all run the hooks Observer writes: Codex
// Desktop and the IDE-embedded Codex cores never run hooks.json, and Junie
// and Poolside in a JetBrains IDE (ACP) run none of the CLI's hooks. A row
// here says, for one surface, whether Observer's registered hooks run there.
// It is data; consumers ask HookSpec.SurfaceFor / SurfaceCaveat and never
// branch on a tool name.

// HookSurfaceRun says whether the hooks Observer registers for a tool run on
// one capture surface. Closed; the zero value is unknown.
type HookSurfaceRun string

const (
	// HookSurfaceUnknown: not grounded. The surface's gate is reported as
	// unknown, never as gated.
	HookSurfaceUnknown HookSurfaceRun = ""
	// HookSurfaceRuns: grounded, the surface runs the hooks Observer
	// registers, so a wired gate acts there.
	HookSurfaceRuns HookSurfaceRun = "runs"
	// HookSurfaceSkipped: grounded negative, the surface runs none of the
	// hooks Observer registers, so its calls are not gated by them.
	HookSurfaceSkipped HookSurfaceRun = "skipped"
)

// hookSurfaceRuns is the closed HookSurfaceRun set.
var hookSurfaceRuns = map[HookSurfaceRun]bool{
	HookSurfaceUnknown: true,
	HookSurfaceRuns:    true,
	HookSurfaceSkipped: true,
}

// Known reports whether r is one of the declared HookSurfaceRun values.
func (r HookSurfaceRun) Known() bool { return hookSurfaceRuns[r] }

// HookSurface is one capture surface's hook scope for one tool.
type HookSurface struct {
	// Kind is a models.Surface* kind (models.KnownSurface).
	Kind string
	// Host refines Kind with a host token; "" = every host of Kind.
	Host string
	// Runs says whether Observer's registered hooks run on the surface.
	Runs HookSurfaceRun
	// Note explains the row for people. On a row whose Runs is not
	// HookSurfaceRuns it is the admin-facing caveat, one sentence, that the
	// rule coverage shows beside every wired gate of the tool
	// (HookSpec.SurfaceCaveat); it replaces a per-binding AdminCaveat saying
	// the same thing.
	Note string
	// Grounding names the evidence. Required on every row.
	Grounding string
	// LiveCheck names the pending live check(s) of the gap review (section
	// 6) that would ground or confirm the row.
	LiveCheck string
}

// SurfaceFor returns the hook scope that applies to one capture surface, and
// how it was found (the same exact, then kind, match table as
// Capability.RouteSurfaceFor). With no matching row it returns an unknown
// row and SurfaceMatchTool: the tool-level HookSpec answers.
func (h HookSpec) SurfaceFor(kind, host string) (HookSurface, SurfaceMatch) {
	if kind != "" {
		for _, rule := range surfaceMatchRules {
			for _, row := range h.Surfaces {
				if rule.hit(SurfaceRoute{Kind: row.Kind, Host: row.Host}, kind, host) {
					return row, rule.match
				}
			}
		}
	}
	return HookSurface{Kind: kind, Host: host}, SurfaceMatchTool
}

// SurfaceCaveat is the one admin-facing sentence about the surfaces where
// the tool's registered hooks do not run (or are not known to): the Notes of
// every row whose Runs is not HookSurfaceRuns, in table order, each distinct
// Note once (one fact declared for several hosts reads as one sentence). ""
// when every declared surface runs them, or none is declared.
func (h HookSpec) SurfaceCaveat() string {
	var parts []string
	seen := map[string]bool{}
	for _, row := range h.Surfaces {
		if row.Runs != HookSurfaceRuns && row.Note != "" && !seen[row.Note] {
			seen[row.Note] = true
			parts = append(parts, row.Note)
		}
	}
	return strings.Join(parts, " ")
}

// hookSurfaces is the ONE owner of the HookSpec.Surfaces column, keyed by
// registry tool. Declared where a surface's hook behaviour differs from the
// CLI's, or is the reason a caveat exists.
var hookSurfaces = map[string][]HookSurface{
	"claude-code": {
		{
			Kind: models.SurfaceCLI, Runs: HookSurfaceRuns,
			Note:      "The CLI runs ~/.claude/settings.json hooks.",
			Grounding: "live: hook-parity Lane A tool gate (demo node 1) and the 2026-09-07 prompt-guard sweep",
		},
		{
			Kind: models.SurfaceIDE, Runs: HookSurfaceRuns,
			Note:      "The IDE extensions run Claude Code itself, which runs the same hooks.",
			Grounding: "live: 2026-09-07 prompt-guard sweep, Claude Code in the Windows IDE blocked with a visible reason (docs/plans/adapter-coverage-parity-plan-2026-06-26.md)",
		},
		{
			Kind: models.SurfaceDesktop, Runs: HookSurfaceRuns,
			Note:      "Claude Desktop's Code tab runs the same hooks, so the hook gates and the hook budget stop act there even though the proxy route does not.",
			Grounding: "doc: https://code.claude.com/docs/en/desktop (gap review CC-1, grounded locally 2026-10-24)",
			LiveCheck: "LC1",
		},
		{
			Kind:      models.SurfaceSDK,
			Note:      "An Agent SDK or claude -p embedding can drop user settings (settingSources) or skip hooks entirely (--bare), so Observer's user-level hooks may not run there.",
			Grounding: "doc: https://code.claude.com/docs/en/agent-sdk/typescript and cli-reference (gap review CC-3)",
			LiveCheck: "LC4, LC5",
		},
	},
	"codex": {
		{
			Kind: models.SurfaceCLI, Runs: HookSurfaceRuns,
			Note:      "The CLI runs ~/.codex/hooks.json once the hooks are trusted.",
			Grounding: "live: 2026-09-07 codex CLI UserPromptSubmit block, hook-parity Lane A PreToolUse deny",
		},
		{
			Kind: models.SurfaceIDE, Runs: HookSurfaceSkipped,
			Note:      "The Codex IDE extensions (VS Code, JetBrains) run no hooks.json, so their calls are not gated; only the proxy lane covers them, while routed.",
			Grounding: "live: 2026-09-07, Codex VS Code / JetBrains-embedded cores 0.151-0.153 do not execute hooks.json (docs/plans/adapter-coverage-parity-plan-2026-06-26.md codex prompt row; gap review CX-1)",
			LiveCheck: "LC8",
		},
		{
			Kind: models.SurfaceDesktop, Runs: HookSurfaceSkipped,
			Note:      "Codex Desktop runs no hooks.json, so its calls are not gated; only the proxy lane covers it, while routed.",
			Grounding: "live: 2026-09-07, Codex Desktop 0.151-0.153 does not execute hooks.json (docs/plans/adapter-coverage-parity-plan-2026-06-26.md codex prompt row; gap review CX-1)",
			LiveCheck: "LC7, LC8",
		},
	},
	"junie": {
		{
			Kind: models.SurfaceCLI, Runs: HookSurfaceRuns,
			Note:      "The Junie CLI runs the hooks in $JUNIE_HOME/config.json.",
			Grounding: "doc: https://junie.jetbrains.com/docs/junie-cli-hooks.html",
		},
		{
			Kind: models.SurfaceIDE, Runs: HookSurfaceSkipped,
			Note:      "The Junie CLI only: Junie in the JetBrains IDE (ACP), its main surface, runs no hooks, so its calls there are not gated.",
			Grounding: "doc: https://junie.jetbrains.com/docs/junie-cli-hooks.html (hooks do not run in ACP or server hosts; gap review W-5); live: 2026-10-27 MAC-5 batch 2, the Junie plugin in IntelliJ IDEA CE logged no call to Observer's stand-in Junie hooks (JetBrains Air, which runs the Junie CLI, did)",
			LiveCheck: "LC20",
		},
	},
	"poolside": {
		{
			Kind: models.SurfaceCLI, Runs: HookSurfaceRuns,
			Note:      "The pool CLI runs the hooks in ~/.config/poolside/settings.yaml.",
			Grounding: "doc: https://docs.poolside.ai/hooks (live-fetched 2026-09-07)",
		},
		{
			Kind:      models.SurfaceIDE,
			Note:      "The pool CLI only: Poolside as a JetBrains ACP agent, its main surface, has no grounded hook, so its calls there are not gated.",
			Grounding: "repo: docs/poolside-adapter.md (What's NOT built: no hook on the JetBrains ACP surface); gap review W-5",
			LiveCheck: "LC20",
		},
	},
}

// init folds the Surfaces column into the registry rows' HookSpec. A key
// with no registry row is a table error caught by
// TestHookSurfacesAreRegistryRows.
// claudeAgentInJetBrains is the hook row of Claude Agent run by JetBrains AI
// Assistant over ACP (registry claude-acp), one per JetBrains product host.
// The negative was OBSERVED on IntelliJ IDEA Community Edition only (MAC-5
// batch 2); the other eleven product hosts are inferred, because they run
// the same AI Assistant ACP host. A run on another product would confirm it.
// The rows are per host because the surface enricher stamps those sessions
// ide/jetbrains-<product> (internal/surfaceenrich). The Claude Code
// JetBrains plugin, which runs the claude CLI in the IDE terminal,
// self-reports the generic "jetbrains" host and keeps the IDE kind row.
func claudeAgentInJetBrains() []HookSurface {
	out := make([]HookSurface, 0, len(jetbrainsProductHosts))
	for _, host := range jetbrainsProductHosts {
		out = append(out, HookSurface{
			Kind: models.SurfaceIDE, Host: host, Runs: HookSurfaceSkipped,
			Note:      "Claude Agent in JetBrains AI Assistant (ACP) does not load ~/.claude/settings.json, so Observer's Claude Code hooks do not gate it there.",
			Grounding: "live: 2026-10-27 MAC-5 batch 2, observed on IntelliJ IDEA CE only: its AI Chat Claude Agent logged no call to the stand-in hooks (docs/handovers/surface-gap-mac-ide-round-2026-10-27.md; tracker FU-124); inferred for the other JetBrains products, which run the same AI Assistant ACP host",
			LiveCheck: "MAC-5",
		})
	}
	return out
}

// xcodeHost is the surface-host token of an agent run inside Xcode 26.3+
// Intelligence (gap review S-2). No adapter stamps it yet; it ships on the
// org wire verbatim (internal/store/orgpush.go knownSurfaceHosts).
const xcodeHost = "xcode"

// jetbrainsProductHosts is the product-host vocabulary of
// internal/platform/jetbrainshost (Products()[i].Host), declared here so the
// registry stays free of that package; TestJetBrainsProductHostsMatch pins
// the two equal.
var jetbrainsProductHosts = []string{
	"jetbrains-idea", "jetbrains-pycharm", "jetbrains-webstorm", "jetbrains-goland",
	"jetbrains-clion", "jetbrains-rider", "jetbrains-phpstorm", "jetbrains-rubymine",
	"jetbrains-rustrover", "jetbrains-datagrip", "jetbrains-dataspell", "jetbrains-android-studio",
}

// JetBrainsProductHosts returns the product host tokens the hook surface
// rows are declared for, for the pin test.
func JetBrainsProductHosts() []string { return append([]string(nil), jetbrainsProductHosts...) }

// wave8HookSurfaces are the hook rows surface-gap lane w8-registry added:
// the surfaces the 2026-10-27 macOS IDE round (MAC-5) and the Windows rounds
// (LC15) grounded as running none of Observer's hooks, or whose hook load
// Observer itself breaks, and an unknown row for every IDE surface the lane
// gave a route row (routeSurfaces), so the posture never reads a gate as
// acting on a surface where nobody checked that the hooks run.
var wave8HookSurfaces = map[string][]HookSurface{
	"kiro-cli": {
		{
			// FU-153: unknown, not skipped. Kiro IDE 1.4.51 runs
			// ~/.kiro/hooks/*.json only in a trusted workspace, decided at
			// window load; the earlier negative was an untrusted one.
			Kind: models.SurfaceIDE, Runs: HookSurfaceUnknown,
			Note:      "The Kiro IDE ignores the Kiro CLI's agent hooks and runs ~/.kiro/hooks only in a trusted workspace after a window reload, and whether it runs Observer's own file there is not live-run, so its gate is not counted.",
			Grounding: "live: 2026-10-26 LC15 (Windows) and 2026-10-27 MAC-5 batch 1 (macOS, untrusted workspace, no call); MAC-5 round 4 and the Windows rerun 2026-10-29 (trusted workspace after a reload, a ~/.kiro/hooks probe hook blocked)",
			LiveCheck: "LC15, MAC-5",
		},
		{
			Kind: models.SurfaceDesktop, Host: "kiro-crew", Runs: HookSurfaceSkipped,
			Note:      "Kiro Crew drives kiro-cli without the CLI's agent hooks, so its runs are not gated.",
			Grounding: "live: 2026-10-26 LC15, Kiro Crew ran none of Observer's ~/.kiro hooks",
			LiveCheck: "LC15",
		},
	},
	"gemini-cli": {
		{
			Kind:      models.SurfaceIDE,
			Note:      "Whether an IDE-hosted Gemini (Gemini Code Assist agent mode, or Gemini run by an ACP host) runs Observer's ~/.gemini/settings.json hooks is not checked.",
			Grounding: "audit: docs/audits/vendor-surface-inventory-2026-10-25.md sections 2.3 and 5 (lane w8-registry)",
			LiveCheck: "LCR-63, LCR-64",
		},
	},
	"goose": {
		{
			Kind:      models.SurfaceIDE,
			Note:      "Whether the goose that Goose for VS Code or an ACP host spawns loads Observer's ~/.agents/plugins hooks is not checked.",
			Grounding: "audit: docs/audits/vendor-surface-inventory-2026-10-25.md section 2.2 (lane w8-registry)",
			LiveCheck: "LCR-62, LCR-63",
		},
	},
	"kilo-code-cli": {
		{
			Kind:      models.SurfaceIDE,
			Note:      "Whether Kilo Code 7.x for VS Code and Kilo Code for JetBrains v7 load Observer's global plugin shim is not checked.",
			Grounding: "audit: docs/audits/surface-settings-precedence-gap-review-2026-10-25.md IDE-9 (lane w8-registry)",
			LiveCheck: "LC16",
		},
	},
	"claude-code": {
		{
			Kind: models.SurfaceIDE, Host: xcodeHost, Runs: HookSurfaceSkipped,
			Note: "Claude Agent in Xcode runs Xcode's own bundled Claude with its config in ~/Library/Developer/Xcode/CodingAssistant/ClaudeAgentConfig and never reads ~/.claude, so Observer's Claude Code hooks gate it only through the separate claude-code-xcode hook target, which no caller (observer start, observer init, the dashboard) registers yet.",
			Grounding: "live: 2026-10-28 MAC-1 read (Xcode 26.6 17F113, macOS 26.2): a Bash call carrying the deny marker ran with Observer-written ~/.claude/settings.json hooks in place and no hook call reached them; ClaudeAgentConfig holds no settings.json. " +
				"live: 2026-10-28 Mac round 5b (LCR-89 passed): the claude-code-xcode writer's ClaudeAgentConfig/settings.json hooks ran there and blocked a deny-marker Bash call",
		},
	},
	"opencode": {
		{
			Kind:      models.SurfaceDesktop,
			Note:      "OpenCode Desktop 2.2 rejected Observer's v1-only plugin (it wants the v2 setup or effect export); the shim now carries the v2 setup form beside v1 (FU-121), but whether 2.2 loads it and honours a deny is not live-checked yet; an older desktop server loaded the v1 form.",
			Grounding: "live: 2026-10-27 MAC-5 batch 1 (OpenCode Desktop 2.2.0, log: \"Plugin must export a default definition with an id and an effect or setup function\"; tracker FU-121) and 2026-10-26 LC42 (Windows, an older desktop server loaded the shim); code: the v2 loader schema and hooks read from @opencode-ai/cli 0.0.0-beta-19271 (lane w8-writers)",
			LiveCheck: "MAC-5",
		},
	},
}

func init() {
	for tool, rows := range wave8HookSurfaces {
		hookSurfaces[tool] = append(hookSurfaces[tool], rows...)
	}
	hookSurfaces["claude-code"] = append(hookSurfaces["claude-code"], claudeAgentInJetBrains()...)
	for tool, rows := range hookSurfaces {
		if c, ok := registry[tool]; ok {
			c.Hook.Surfaces = append([]HookSurface(nil), rows...)
			registry[tool] = c
		}
	}
}
