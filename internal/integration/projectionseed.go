package integration

// projectionseed.go is the per-tool projection seed side table (sandbox
// plan v2 section 5.4, gap G27, lane SBX-P3C). A box whose tool state is a
// per-run projected directory instead of the real one (a row that crosses a
// kernel, or an image's own copy of the tool) starts from an empty tool
// state; a row here says, for one tool:
//
//   - Files: the NON-SECRET files copied from the real tool state into the
//     projection at launch (HOME-relative, inside a SandboxSpec.StateRW
//     entry). Credential files are never seed files: a sign-in reaches a
//     projected box only through consented sign-in seeding (lane
//     BOXSIGNIN: the row's SandboxSpec.SignIn, internal/sandboxsignin), so
//     without consent a projected run signs in again or uses the proxy's
//     credentials. A file that can carry a credential (an env block, a
//     provider key) is not seeded either;
//   - Transcripts: the subtrees under which the tool writes its session
//     transcripts (HOME-relative, inside a StateRW entry). The host watcher
//     registers each as a watch root for the run's life, read by the tool's
//     own adapter; SQLite stores are never registered (db-copy covers them).
//
// It is data, one row per grounded tool; the projection reads nothing else
// about a tool. Grounded first: claude-code, whose recorded fixtures
// (testdata/claudecode) cover the transcript shape; lane LEFT-SBX added a
// row for every other sandbox-launchable tool whose transcripts are files
// (leftSBXProjectionSeeds). A tool with no row starts empty on a projected
// run and leaves its transcripts uncaptured (the run's capture says so).

// ProjectionSeed is one tool's projection seed row.
type ProjectionSeed struct {
	// Tool is the registry tool id.
	Tool string
	// Files are the non-secret files seeded into the projection.
	Files []string
	// Transcripts are the transcript subtrees watched in the projection.
	Transcripts []string
	// Grounding says where the paths come from.
	Grounding string
	// DocURL is the tool's own document that names the seeded Files (lane
	// LEFT-SBX: a file is seeded only when the vendor's docs name it, and
	// it must hold no secret). Required when Files is not empty.
	DocURL string
}

var projectionSeeds = []ProjectionSeed{
	{
		Tool:        "claude-code",
		Files:       []string{".claude/CLAUDE.md"},
		Transcripts: []string{".claude/projects"},
		Grounding: "the claude-code adapter's own watch root is ~/.claude/projects (internal/adapter/claudecode WatchPaths, fixtures testdata/claudecode); " +
			"~/.claude/CLAUDE.md is the user memory file (code.claude.com/docs/en/memory, read 2026-10-23), plain instructions with no credential slot. " +
			"Not seeded: ~/.claude/settings.json (its env block can carry API keys, internal/integration credentialfile.go) and ~/.claude/.credentials.json (the Linux sign-in store)",
		DocURL: "https://code.claude.com/docs/en/memory",
	},
}

// leftSBXProjectionSeeds are the G27 rows added by lane LEFT-SBX
// (2026-10-24) for every other sandbox-launchable tool whose transcripts are
// files: each transcript subtree is the tool's own adapter watch root
// (internal/adapter/<tool> WatchPaths, judged by that adapter at its box
// path), and a file is seeded only where the tool's own docs name it as a
// plain instruction file (DocURL). Not given a row, recorded: tools whose
// sessions live in a SQLite store (opencode, kilo-code-cli, crush, zcode,
// goose, hermes; db-copy covers them on the oci-runsc row), cline-cli (its
// session index is SQLite and its watch root is the whole ~/.cline),
// aider (its history lives in the repository, already the workspace) and
// every tool with no sandbox state row.
var leftSBXProjectionSeeds = []ProjectionSeed{
	{
		Tool: "codex", Transcripts: []string{".codex/sessions"},
		Grounding: "the codex adapter's watch root is ~/.codex/sessions (internal/adapter/codex WatchPaths, fixtures testdata/codex). " +
			"Not seeded: ~/.codex/config.toml (provider keys and a protected executed config) and ~/.codex/auth.json (the sign-in)",
	},
	{
		Tool: "gemini-cli", Files: []string{".gemini/GEMINI.md"}, Transcripts: []string{".gemini/tmp"},
		Grounding: "the gemini adapter's watch root is ~/.gemini/tmp (internal/adapter/gemini WatchPaths); the CLI's docs name ~/.gemini/GEMINI.md as the global context file " +
			"(plain instructions, read 2026-10-24). Not seeded: ~/.gemini/settings.json (a protected executed config) and the OAuth files",
		DocURL: "https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/gemini-md.md",
	},
	{
		Tool: "qwen-code", Files: []string{".qwen/QWEN.md"}, Transcripts: []string{".qwen/projects"},
		Grounding: "the qwen-code adapter's watch root is ~/.qwen/projects (internal/adapter/qwencode WatchPaths); the settings docs name ~/.qwen/QWEN.md as the global context file " +
			"(plain instructions, read 2026-10-24). Not seeded: ~/.qwen/settings.json (a protected executed config) and the OAuth files",
		DocURL: "https://github.com/QwenLM/qwen-code/blob/main/docs/users/configuration/settings.md",
	},
	{
		Tool: "copilot-cli", Transcripts: []string{".copilot/session-state", ".copilot/logs"},
		Grounding: "the copilot-cli adapter's watch roots are ~/.copilot/session-state and ~/.copilot/logs (internal/adapter/copilotcli WatchPaths). Not seeded: ~/.copilot/config.json (its sign-in)",
	},
	{
		Tool: "openclaw", Transcripts: []string{".openclaw/agents", ".openclaw/tasks"},
		Grounding: "the openclaw adapter's watch roots are ~/.openclaw/agents and ~/.openclaw/tasks (internal/adapter/openclaw WatchPaths, fixtures testdata/openclaw). Not seeded: the gateway config and its tokens",
	},
	{
		Tool: "pi", Transcripts: []string{".pi/agent/sessions"},
		Grounding: "the pi adapter's watch root is ~/.pi/agent/sessions (internal/adapter/pi WatchPaths). Not seeded: ~/.pi/agent/auth.json (the sign-in)",
	},
	{
		Tool: "grok", Transcripts: []string{".grok/sessions", ".grok/logs"},
		Grounding: "the grok adapter's watch roots are ~/.grok/sessions and ~/.grok/logs, the token splits living in logs/unified.jsonl (internal/adapter/grok WatchPaths). Not seeded: the sign-in",
	},
	{
		Tool: "kimi-code", Transcripts: []string{".kimi-code/sessions"},
		Grounding: "the kimi-code adapter's watch root is ~/.kimi-code/sessions (internal/adapter/kimicode WatchPaths). Not seeded: the sign-in and config",
	},
	{
		Tool: "droid", Transcripts: []string{".factory/sessions"},
		Grounding: "the droid adapter's watch root is ~/.factory/sessions, settings sidecars included (internal/adapter/droid WatchPaths). Not seeded: ~/.factory/hooks.json and ~/.factory/mcp.json (protected executed configs) and the sign-in",
	},
	{
		Tool: "command-code", Transcripts: []string{".commandcode/projects"},
		Grounding: "the command-code adapter's watch root is ~/.commandcode/projects (internal/adapter/commandcode WatchPaths). Not seeded: ~/.commandcode/mcp.json and mods (protected executed state)",
	},
	{
		Tool: "prime-agent", Transcripts: []string{".prime/agent/sessions"},
		Grounding: "the prime-agent adapter's watch root is ~/.prime/agent/sessions (internal/adapter/primeagent WatchPaths). Not seeded: ~/.prime/agent/auth.json, daemon-workers and the kernel state pickle, never read",
	},
	{
		Tool: "junie", Transcripts: []string{".junie/sessions"},
		Grounding: "the junie adapter's watch root is ~/.junie/sessions (internal/adapter/junie WatchPaths). Not seeded: the sign-in",
	},
	{
		Tool: "mistral-code", Transcripts: []string{".vibe/logs/session"},
		Grounding: "the mistral-code adapter's vibe watch root is ~/.vibe/logs/session, both the legacy and the unified layouts (internal/adapter/mistralcode WatchPaths). Not seeded: ~/.vibe/config.toml and its .env (provider keys)",
	},
	{
		Tool: "qoder", Transcripts: []string{".qoder/projects"},
		Grounding: "the qoder adapter's CLI watch root is ~/.qoder/projects (internal/adapter/qoder WatchPaths). Not seeded: ~/.qoder/settings.json (a protected executed config)",
	},
	{
		Tool: "open-interpreter", Transcripts: []string{".openinterpreter/sessions"},
		Grounding: "the open-interpreter (codex retag) watch root is ~/.openinterpreter/sessions (internal/adapter/codex NewOpenInterpreter WatchPaths). Not seeded: config*.toml (plaintext provider keys, never read)",
	},
	{
		Tool: "muse", Transcripts: []string{".local/share/muse/sessions"},
		Grounding: "the muse adapter's watch root is ~/.local/share/muse/sessions (internal/adapter/muse WatchPaths). Not seeded: auth.json, trust.json and tui-history.jsonl, never read",
	},
	{
		Tool: "kiro-cli", Transcripts: []string{".kiro/sessions"},
		Grounding: "the kiro-cli adapter's flat-bundle watch root is ~/.kiro/sessions (internal/adapter/kirocli WatchPaths); its conversations_v2 SQLite store is db-copy's",
	},
}

// ProjectionSeedFor returns tool's seed row; ok is false when none is
// grounded yet (G27 owed).
func ProjectionSeedFor(tool string) (ProjectionSeed, bool) {
	for _, s := range append(append([]ProjectionSeed(nil), projectionSeeds...), leftSBXProjectionSeeds...) {
		if s.Tool == tool {
			s.Files = append([]string(nil), s.Files...)
			s.Transcripts = append([]string(nil), s.Transcripts...)
			return s, true
		}
	}
	return ProjectionSeed{}, false
}

// ProjectionSeeds returns every row.
func ProjectionSeeds() []ProjectionSeed {
	all := append(append([]ProjectionSeed(nil), projectionSeeds...), leftSBXProjectionSeeds...)
	out := make([]ProjectionSeed, 0, len(all))
	for _, s := range all {
		if r, ok := ProjectionSeedFor(s.Tool); ok {
			out = append(out, r)
		}
	}
	return out
}
