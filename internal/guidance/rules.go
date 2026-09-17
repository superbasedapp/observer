package guidance

// Kind classifies what a guidance file IS to the tool that reads it.
// The vocabulary is closed; a consumer switches on it for presentation
// only, never to decide capability (CLAUDE.md rule #3).
type Kind string

// The closed Kind vocabulary.
const (
	// KindInstructions is always-on context: CLAUDE.md, AGENTS.md,
	// GEMINI.md, .goosehints, CONVENTIONS.md.
	KindInstructions Kind = "instructions"
	// KindSkill is a packaged, on-demand capability (Claude Code skills).
	KindSkill Kind = "skill"
	// KindAgent is a sub-agent / persona definition.
	KindAgent Kind = "agent"
	// KindCommand is an operator-invoked prompt (slash commands, prompt
	// files, chat modes).
	KindCommand Kind = "command"
	// KindRule is conditionally-applied guidance selected by a glob or an
	// alwaysApply flag (.mdc rules, .github/instructions/*).
	KindRule Kind = "rule"
	// KindConfig is a machine-readable file that configures the harness
	// and may POINT AT further instructions (settings.json, opencode.json).
	KindConfig Kind = "config"
)

// Scope says which root a rule's glob is anchored to.
type Scope string

// The closed Scope vocabulary.
const (
	// ScopeProject anchors a glob at the project root.
	ScopeProject Scope = "project"
	// ScopeUser anchors a glob at the operator's home directory. Such a
	// glob is written with a leading "~/" and rendered back into RelPath
	// the same way, so a user-scope row is never mistaken for a file
	// inside the repository.
	ScopeUser Scope = "user"
)

// Front-matter dialects a rule's files may carry. These name a PARSING
// SHAPE, not a tool — the scanner dispatches on the shape (rule #3).
const (
	// FrontmatterNone means the whole file is prose.
	FrontmatterNone = "none"
	// FrontmatterYAML is a leading "---" fenced YAML block.
	FrontmatterYAML = "yaml"
	// FrontmatterMDC is Cursor's .mdc dialect — structurally the same
	// leading "---" fenced YAML block, named separately because its key
	// vocabulary (globs / alwaysApply) is its own.
	FrontmatterMDC = "mdc"
	// FrontmatterJSON means the whole file is JSON.
	FrontmatterJSON = "json"
)

// Rule is one row of the discovery table: "tool T reads files matching
// Glob, and they are of this Kind, anchored at this Scope, carrying this
// front-matter dialect".
//
// Tool MUST be an id that exists in internal/integration's registry
// (pinned by TestRuleToolsExistInRegistry). Glob is anchored at the
// project root for ScopeProject and written "~/..."-prefixed for
// ScopeUser. "**" in a glob means "zero or more directory levels" and is
// depth-capped by [Options.MaxDepth].
type Rule struct {
	Tool        string
	Glob        string
	Kind        Kind
	Scope       Scope
	Frontmatter string
	Note        string
}

// agentsMDReaders lists the tools whose only project-root convention is
// the cross-vendor AGENTS.md file. Keeping them in one slice keeps the
// table below readable without turning it into a conditional.
var agentsMDReaders = []string{
	"hermes",
	"pi",
	"prime-agent",
	"kimi-code",
	"command-code",
	"mistral-code",
	"muse",
	"openclaw",
	"freebuff",
	"grok",
	"qoder",
}

// geminiMDReaders lists the tools that read Google's GEMINI.md memory
// convention: the Gemini CLI and both Antigravity surfaces, which share
// the same ~/.gemini tree (see docs/antigravity_gemini_cli_pipes.md).
var geminiMDReaders = []string{"gemini-cli", "antigravity", "antigravity-cli"}

// rules is the discovery table. It is built once at package init so
// Rules() can hand out a defensive copy without rebuilding it per call.
var rules = buildRules()

// Rules returns the discovery table. The returned slice is a copy; the
// caller may sort or filter it freely.
func Rules() []Rule {
	out := make([]Rule, len(rules))
	copy(out, rules)
	return out
}

func buildRules() []Rule {
	out := []Rule{
		// ---- claude-code -------------------------------------------------
		{Tool: "claude-code", Glob: "CLAUDE.md", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone},
		{Tool: "claude-code", Glob: "CLAUDE.local.md", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone, Note: "gitignored personal overlay"},
		{Tool: "claude-code", Glob: ".claude/CLAUDE.md", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone},
		{Tool: "claude-code", Glob: "**/CLAUDE.md", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone, Note: "sub-directory memory, depth-capped"},
		{Tool: "claude-code", Glob: ".claude/skills/*/SKILL.md", Kind: KindSkill, Scope: ScopeProject, Frontmatter: FrontmatterYAML},
		{Tool: "claude-code", Glob: ".claude/agents/*.md", Kind: KindAgent, Scope: ScopeProject, Frontmatter: FrontmatterYAML},
		{Tool: "claude-code", Glob: ".claude/commands/**/*.md", Kind: KindCommand, Scope: ScopeProject, Frontmatter: FrontmatterYAML},
		{Tool: "claude-code", Glob: ".claude/settings.json", Kind: KindConfig, Scope: ScopeProject, Frontmatter: FrontmatterJSON},
		{Tool: "claude-code", Glob: ".claude/settings.local.json", Kind: KindConfig, Scope: ScopeProject, Frontmatter: FrontmatterJSON},
		{Tool: "claude-code", Glob: "~/.claude/CLAUDE.md", Kind: KindInstructions, Scope: ScopeUser, Frontmatter: FrontmatterNone},
		{Tool: "claude-code", Glob: "~/.claude/skills/*/SKILL.md", Kind: KindSkill, Scope: ScopeUser, Frontmatter: FrontmatterYAML},
		{Tool: "claude-code", Glob: "~/.claude/agents/*.md", Kind: KindAgent, Scope: ScopeUser, Frontmatter: FrontmatterYAML},
		{Tool: "claude-code", Glob: "~/.claude/commands/**/*.md", Kind: KindCommand, Scope: ScopeUser, Frontmatter: FrontmatterYAML},

		// ---- codex -------------------------------------------------------
		{Tool: "codex", Glob: "AGENTS.md", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone},
		{Tool: "codex", Glob: "**/AGENTS.md", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone, Note: "sub-directory memory, depth-capped"},
		{Tool: "codex", Glob: "~/.codex/AGENTS.md", Kind: KindInstructions, Scope: ScopeUser, Frontmatter: FrontmatterNone},

		// ---- cursor ------------------------------------------------------
		{Tool: "cursor", Glob: ".cursor/rules/**/*.mdc", Kind: KindRule, Scope: ScopeProject, Frontmatter: FrontmatterMDC},
		{Tool: "cursor", Glob: ".cursorrules", Kind: KindRule, Scope: ScopeProject, Frontmatter: FrontmatterNone, Note: "legacy single-file form"},

		// ---- copilot -----------------------------------------------------
		// .github/instructions/*.instructions.md carries an applyTo glob;
		// prompts and chat modes are operator-invoked, so both land as
		// commands.
		{Tool: "copilot", Glob: ".github/copilot-instructions.md", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone},
		{Tool: "copilot", Glob: ".github/instructions/*.instructions.md", Kind: KindRule, Scope: ScopeProject, Frontmatter: FrontmatterYAML},
		{Tool: "copilot", Glob: ".github/prompts/*.prompt.md", Kind: KindCommand, Scope: ScopeProject, Frontmatter: FrontmatterYAML},
		{Tool: "copilot", Glob: ".github/chatmodes/*.chatmode.md", Kind: KindCommand, Scope: ScopeProject, Frontmatter: FrontmatterYAML},

		// ---- qwen-code ---------------------------------------------------
		{Tool: "qwen-code", Glob: "QWEN.md", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone},
		{Tool: "qwen-code", Glob: "**/QWEN.md", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone, Note: "sub-directory memory, depth-capped"},

		// ---- devin (the windsurf alias, docs/harness-lifecycle-policy.md) --
		{Tool: "devin", Glob: ".windsurfrules", Kind: KindRule, Scope: ScopeProject, Frontmatter: FrontmatterNone},
		{Tool: "devin", Glob: ".windsurf/rules/*.md", Kind: KindRule, Scope: ScopeProject, Frontmatter: FrontmatterYAML},

		// ---- aider / goose / crush ---------------------------------------
		{Tool: "aider", Glob: "CONVENTIONS.md", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone},
		{Tool: "goose", Glob: ".goosehints", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone},
		{Tool: "goose", Glob: "~/.config/goose/.goosehints", Kind: KindInstructions, Scope: ScopeUser, Frontmatter: FrontmatterNone},
		{Tool: "crush", Glob: "CRUSH.md", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone},

		// ---- droid (Factory AI) ------------------------------------------
		{Tool: "droid", Glob: "AGENTS.md", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone},
		{Tool: "droid", Glob: ".factory/droids/*.md", Kind: KindAgent, Scope: ScopeProject, Frontmatter: FrontmatterYAML},
		{Tool: "droid", Glob: ".factory/commands/*.md", Kind: KindCommand, Scope: ScopeProject, Frontmatter: FrontmatterYAML},

		// ---- kiro-cli ----------------------------------------------------
		{Tool: "kiro-cli", Glob: ".kiro/steering/*.md", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterYAML},
	}

	// cline and its CLI sibling share one convention; so do kilo-code's
	// two surfaces, copilot's CLI, and opencode's zcode fork. Expanding a
	// shared convention over a list of tool ids keeps the table a table.
	for _, tool := range []string{"cline", "cline-cli"} {
		out = append(out,
			Rule{Tool: tool, Glob: ".clinerules", Kind: KindRule, Scope: ScopeProject, Frontmatter: FrontmatterNone, Note: "single-file form"},
			Rule{Tool: tool, Glob: ".clinerules/**/*.md", Kind: KindRule, Scope: ScopeProject, Frontmatter: FrontmatterNone, Note: "directory form"},
		)
	}
	for _, tool := range []string{"kilo-code", "kilo-code-cli"} {
		out = append(out,
			Rule{Tool: tool, Glob: ".kilocode/rules/**/*.md", Kind: KindRule, Scope: ScopeProject, Frontmatter: FrontmatterNone},
			Rule{Tool: tool, Glob: ".kilocoderules", Kind: KindRule, Scope: ScopeProject, Frontmatter: FrontmatterNone, Note: "legacy single-file form"},
		)
	}
	// copilot-cli reads the same .github tree the extension does.
	var copilotCLI []Rule
	for _, r := range out {
		if r.Tool == "copilot" {
			r.Tool = "copilot-cli"
			copilotCLI = append(copilotCLI, r)
		}
	}
	out = append(out, copilotCLI...)
	for _, tool := range []string{"opencode", "zcode"} {
		out = append(out,
			Rule{Tool: tool, Glob: "AGENTS.md", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone},
			Rule{Tool: tool, Glob: "opencode.json", Kind: KindConfig, Scope: ScopeProject, Frontmatter: FrontmatterJSON, Note: "instructions[] points at further files"},
			Rule{Tool: tool, Glob: ".opencode/command/*.md", Kind: KindCommand, Scope: ScopeProject, Frontmatter: FrontmatterYAML},
			Rule{Tool: tool, Glob: ".opencode/agent/*.md", Kind: KindAgent, Scope: ScopeProject, Frontmatter: FrontmatterYAML},
		)
	}
	for _, tool := range geminiMDReaders {
		out = append(out,
			Rule{Tool: tool, Glob: "GEMINI.md", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone},
			Rule{Tool: tool, Glob: "**/GEMINI.md", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone, Note: "sub-directory memory, depth-capped"},
		)
	}
	out = append(out, Rule{
		Tool: "gemini-cli", Glob: ".gemini/styleguide.md",
		Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone,
		Note: "Gemini Code Assist review style guide",
	})
	for _, tool := range agentsMDReaders {
		out = append(out, Rule{
			Tool: tool, Glob: "AGENTS.md",
			Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone,
		})
	}
	return out
}
