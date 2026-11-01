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
	// Personal marks a project-scope file the tool's own convention keeps
	// OUT of version control: a per-developer overlay such as
	// CLAUDE.local.md, which the vendor tells you to gitignore. It lives
	// in the project tree but is not shared with the team, so a consumer
	// must never describe editing it as "commits with the repo". Every
	// project-scope glob whose file name carries a ".local." segment is
	// personal (TestLocalOverlaysArePersonal).
	Personal bool
	// Borrowed marks a directory the rule's tool READS but does not own:
	// another tool's tree (IBM Bob loading ~/.claude/skills) or a
	// tool-agnostic one (~/.agents/skills). A file there is guidance the
	// tool loads, but the directory existing says nothing about whether the
	// tool is installed, so a consumer must not treat it as install
	// evidence (agentconfigsvc.Service.Installed). Every rule whose glob
	// sits under a root in borrowedRoots owned by a different tool is
	// borrowed (TestBorrowedRootsAreMarked).
	Borrowed bool
}

// borrowedRoots maps a directory root that more than one tool reads to the
// tool that owns it ("" = tool-agnostic, owned by none). Keys are the first
// path segment of a rule glob, with "~/" stripped.
var borrowedRoots = map[string]string{
	".claude": "claude-code",
	".agents": "",
	".pi":     "pi",
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
		{Tool: "claude-code", Glob: "CLAUDE.local.md", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone, Note: "gitignored personal overlay", Personal: true},
		{Tool: "claude-code", Glob: ".claude/CLAUDE.md", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone},
		{Tool: "claude-code", Glob: "**/CLAUDE.md", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone, Note: "sub-directory memory, depth-capped"},
		{Tool: "claude-code", Glob: ".claude/skills/*/SKILL.md", Kind: KindSkill, Scope: ScopeProject, Frontmatter: FrontmatterYAML},
		{Tool: "claude-code", Glob: ".claude/agents/*.md", Kind: KindAgent, Scope: ScopeProject, Frontmatter: FrontmatterYAML},
		{Tool: "claude-code", Glob: ".claude/commands/**/*.md", Kind: KindCommand, Scope: ScopeProject, Frontmatter: FrontmatterYAML},
		{Tool: "claude-code", Glob: ".claude/settings.json", Kind: KindConfig, Scope: ScopeProject, Frontmatter: FrontmatterJSON},
		{Tool: "claude-code", Glob: ".claude/settings.local.json", Kind: KindConfig, Scope: ScopeProject, Frontmatter: FrontmatterJSON, Personal: true},
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
	// Project skill and command directories the JSP-7 spike found in real
	// repositories that the table did not list (security pillar plan
	// section 5.1, revision 2.4 change (c)). Gemini CLI command files are
	// TOML; a "!{...}" in one runs shell when the user invokes the command.
	out = append(out,
		Rule{Tool: "codex", Glob: ".agents/skills/*/SKILL.md", Kind: KindSkill, Scope: ScopeProject, Frontmatter: FrontmatterYAML, Borrowed: true, Note: "cross-tool skills directory"},
		Rule{Tool: "codex", Glob: ".codex/skills/*/SKILL.md", Kind: KindSkill, Scope: ScopeProject, Frontmatter: FrontmatterYAML},
		Rule{Tool: "qwen-code", Glob: ".qwen/skills/*/SKILL.md", Kind: KindSkill, Scope: ScopeProject, Frontmatter: FrontmatterYAML},
		Rule{Tool: "gemini-cli", Glob: ".gemini/skills/*/SKILL.md", Kind: KindSkill, Scope: ScopeProject, Frontmatter: FrontmatterYAML},
		Rule{Tool: "gemini-cli", Glob: ".gemini/commands/**/*.toml", Kind: KindCommand, Scope: ScopeProject, Frontmatter: FrontmatterNone, Note: "TOML custom commands; !{...} runs shell when invoked"},
	)
	for _, tool := range agentsMDReaders {
		out = append(out, Rule{
			Tool: tool, Glob: "AGENTS.md",
			Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone,
		})
	}
	out = append(out, wave1021Rules()...)
	return out
}

// skillRow is the one shape every KindSkill row in wave1021Rules takes:
// "<dir>/*/SKILL.md" with YAML front matter.
func skillRow(tool, dir string, scope Scope, note string) Rule {
	return Rule{Tool: tool, Glob: dir + "/*/SKILL.md", Kind: KindSkill, Scope: scope, Frontmatter: FrontmatterYAML, Note: note}
}

// borrowedSkillRow is skillRow for a skills directory the tool reads but
// does not own (Rule.Borrowed).
func borrowedSkillRow(tool, dir string, scope Scope, note string) Rule {
	r := skillRow(tool, dir, scope, note)
	r.Borrowed = true
	return r
}

// wave1021Rules are the guidance conventions of the ten adapters added on
// 2026-10-21. Every directory is grounded on the vendor's own bundle /
// binary strings or source (named per tool) or on a live directory on this
// box; vendor-shipped builtin skills (autohand ~/.autohand/builtin/<hash>,
// cortex bundled_skills) are deliberately absent — they are the tool's own
// content, not the operator's guidance.
func wave1021Rules() []Rule {
	out := []Rule{
		// autohand-cli dist: "~/.autohand/skills/", ".autohand/skills/",
		// AGENTS.md (and $AUTOHAND_HOME/AGENTS.md).
		{Tool: "autohand", Glob: "AGENTS.md", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone},
		{Tool: "autohand", Glob: "~/.autohand/AGENTS.md", Kind: KindInstructions, Scope: ScopeUser, Frontmatter: FrontmatterNone},
		skillRow("autohand", ".autohand/skills", ScopeProject, ""),
		skillRow("autohand", "~/.autohand/skills", ScopeUser, ""),

		// bobshell 2.0.6 dist/bob.js: workspace skills .bob/skills,
		// .bob/plugins/*/skills, .agents/skills, .claude/skills; user
		// ~/.bob, ~/.agents, ~/.claude skills; mode rules
		// .bob/rules-<mode>/AGENTS.md.
		{Tool: "ibm-bob", Glob: "AGENTS.md", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone},
		{Tool: "ibm-bob", Glob: ".bob/rules-*/AGENTS.md", Kind: KindRule, Scope: ScopeProject, Frontmatter: FrontmatterNone, Note: "mode-specific rules (rules-agent / rules-ask / rules-plan)"},
		skillRow("ibm-bob", ".bob/skills", ScopeProject, ""),
		{Tool: "ibm-bob", Glob: ".bob/plugins/*/skills/*/SKILL.md", Kind: KindSkill, Scope: ScopeProject, Frontmatter: FrontmatterYAML, Note: "plugin-bundled skills"},
		borrowedSkillRow("ibm-bob", ".agents/skills", ScopeProject, "tool-agnostic skills dir"),
		borrowedSkillRow("ibm-bob", ".claude/skills", ScopeProject, "reads Claude Code's skills dir"),
		skillRow("ibm-bob", "~/.bob/skills", ScopeUser, ""),
		borrowedSkillRow("ibm-bob", "~/.agents/skills", ScopeUser, "tool-agnostic skills dir"),
		borrowedSkillRow("ibm-bob", "~/.claude/skills", ScopeUser, "reads Claude Code's skills dir"),

		// cortex.exe 1.2.18: "Project Skill ... (.cortex/skills/)", global
		// skills under the data home (~/.snowflake/cortex, relocatable by
		// $CORTEX_HOME / $SNOWFLAKE_HOME), instruction files AGENTS.md and
		// CORTEX.md.
		{Tool: "cortex-code", Glob: "AGENTS.md", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone},
		{Tool: "cortex-code", Glob: "CORTEX.md", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone},
		skillRow("cortex-code", ".cortex/skills", ScopeProject, ""),
		skillRow("cortex-code", "~/.snowflake/cortex/skills", ScopeUser, "default data home; $CORTEX_HOME relocates it"),

		// @tencent-ai/codebuddy-code dist: CODEBUDDY.md, .codebuddy/{rules,
		// agents,commands,skills}/, ~/.codebuddy/{skills,agents}/.
		{Tool: "codebuddy", Glob: "CODEBUDDY.md", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone},
		{Tool: "codebuddy", Glob: "CODEBUDDY.local.md", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone, Note: "gitignored personal overlay", Personal: true},
		{Tool: "codebuddy", Glob: ".codebuddy/rules/**/*.md", Kind: KindRule, Scope: ScopeProject, Frontmatter: FrontmatterYAML},
		{Tool: "codebuddy", Glob: ".codebuddy/agents/*.md", Kind: KindAgent, Scope: ScopeProject, Frontmatter: FrontmatterYAML},
		{Tool: "codebuddy", Glob: ".codebuddy/commands/**/*.md", Kind: KindCommand, Scope: ScopeProject, Frontmatter: FrontmatterYAML},
		skillRow("codebuddy", ".codebuddy/skills", ScopeProject, ""),
		{Tool: "codebuddy", Glob: "~/.codebuddy/agents/*.md", Kind: KindAgent, Scope: ScopeUser, Frontmatter: FrontmatterYAML},
		skillRow("codebuddy", "~/.codebuddy/skills", ScopeUser, ""),

		// deepagents-code (uv tool env) project_utils.py / _paths.py:
		// project .agents/skills + .deepagents/skills (alias), user
		// ~/.agents/skills + ~/.deepagents/<agent>/skills (default agent
		// "agent"; live ~/.deepagents/agent/{AGENTS.md,skills}).
		{Tool: "deepagents-code", Glob: "~/.deepagents/agent/AGENTS.md", Kind: KindInstructions, Scope: ScopeUser, Frontmatter: FrontmatterNone, Note: "default agent; a named agent uses ~/.deepagents/<name>/"},
		borrowedSkillRow("deepagents-code", ".agents/skills", ScopeProject, "tool-agnostic skills dir"),
		skillRow("deepagents-code", ".deepagents/skills", ScopeProject, "alias of .agents/skills"),
		borrowedSkillRow("deepagents-code", "~/.agents/skills", ScopeUser, "tool-agnostic skills dir"),
		skillRow("deepagents-code", "~/.deepagents/agent/skills", ScopeUser, "default agent"),

		// dimcode 0.5.21 binary: resolveDimcodeHome()/skills (live
		// ~/.dimcode/v2/skills, 13 skills on WSL), ~/.agents/skills,
		// CWD .agents/skills and .claude/skills.
		skillRow("dimcode", "~/.dimcode/v2/skills", ScopeUser, ""),
		borrowedSkillRow("dimcode", "~/.agents/skills", ScopeUser, "tool-agnostic skills dir"),
		borrowedSkillRow("dimcode", ".agents/skills", ScopeProject, "tool-agnostic skills dir"),
		borrowedSkillRow("dimcode", ".claude/skills", ScopeProject, "reads Claude Code's skills dir"),

		// dirac-cli source (Cline fork): .diracrules (file or dir),
		// .diracrules/workflows, AGENTS.md; skills under .diracrules/skills,
		// .dirac/skills, .claude/skills, .agents/skills, .ai/skills.
		{Tool: "dirac", Glob: "AGENTS.md", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone},
		{Tool: "dirac", Glob: ".diracrules", Kind: KindRule, Scope: ScopeProject, Frontmatter: FrontmatterNone, Note: "single-file form"},
		{Tool: "dirac", Glob: ".diracrules/*.md", Kind: KindRule, Scope: ScopeProject, Frontmatter: FrontmatterNone, Note: "directory form"},
		{Tool: "dirac", Glob: ".diracrules/workflows/*.md", Kind: KindCommand, Scope: ScopeProject, Frontmatter: FrontmatterNone, Note: "operator-invoked workflows"},
		skillRow("dirac", ".diracrules/skills", ScopeProject, ""),
		skillRow("dirac", ".dirac/skills", ScopeProject, ""),
		borrowedSkillRow("dirac", ".claude/skills", ScopeProject, "reads Claude Code's skills dir"),
		borrowedSkillRow("dirac", ".agents/skills", ScopeProject, "tool-agnostic skills dir"),
		skillRow("dirac", ".ai/skills", ScopeProject, ""),

		// kimchi.exe 1.17: KIMCHI_TRUST_REQUIRING_PROJECT_RESOURCES lists
		// .kimchi/skills, .pi/agent/skills, .claude/skills (all project
		// scope); instruction candidates AGENTS.md / CLAUDE.md.
		{Tool: "kimchi", Glob: "AGENTS.md", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone},
		skillRow("kimchi", ".kimchi/skills", ScopeProject, ""),
		borrowedSkillRow("kimchi", ".pi/agent/skills", ScopeProject, "pi-mono compatibility dir"),
		borrowedSkillRow("kimchi", ".claude/skills", ScopeProject, "reads Claude Code's skills dir"),

		// stakpak binary: ".stakpak/skills" joined to $HOME beside the
		// SKILL.md loader; a project-scope skills dir is NOT grounded.
		{Tool: "stakpak", Glob: "AGENTS.md", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone},
		skillRow("stakpak", "~/.stakpak/skills", ScopeUser, "home scope from the binary; project scope ungrounded"),

		// vtcode binary: .vtcode/skills, CWD/repo-root .agents/skills,
		// ~/.agents/skills; AGENTS.md.
		{Tool: "vtcode", Glob: "AGENTS.md", Kind: KindInstructions, Scope: ScopeProject, Frontmatter: FrontmatterNone},
		skillRow("vtcode", ".vtcode/skills", ScopeProject, ""),
		borrowedSkillRow("vtcode", ".agents/skills", ScopeProject, "tool-agnostic skills dir"),
		borrowedSkillRow("vtcode", "~/.agents/skills", ScopeUser, "tool-agnostic skills dir"),
	}
	return out
}
