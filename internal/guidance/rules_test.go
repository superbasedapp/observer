package guidance

import (
	"path"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestRuleToolsExistInRegistry is the load-bearing cross-check: every
// Tool in the discovery table must be an id internal/integration knows
// about. internal/integration is the ONE owner of Observer's closed tool
// vocabulary (CLAUDE.md rule #4) — a guidance row for "gemini" or
// "windsurf" would produce rows no other surface could ever join to.
func TestRuleToolsExistInRegistry(t *testing.T) {
	t.Parallel()
	known := map[string]bool{}
	for _, tool := range integration.Tools() {
		known[tool] = true
	}
	if len(known) == 0 {
		t.Fatal("integration.Tools() is empty — the cross-check would be vacuous")
	}
	for _, r := range Rules() {
		if !known[r.Tool] {
			t.Errorf("rule %q -> unknown tool %q (not in internal/integration's registry)", r.Glob, r.Tool)
		}
	}
}

// TestRulesAreWellFormed pins the table's own shape so a new row cannot
// land half-specified.
func TestRulesAreWellFormed(t *testing.T) {
	t.Parallel()
	kinds := map[Kind]bool{
		KindInstructions: true, KindSkill: true, KindAgent: true,
		KindCommand: true, KindRule: true, KindConfig: true,
	}
	dialects := map[string]bool{
		FrontmatterNone: true, FrontmatterYAML: true,
		FrontmatterMDC: true, FrontmatterJSON: true,
	}
	seen := map[string]bool{}
	for _, r := range Rules() {
		switch {
		case r.Tool == "":
			t.Errorf("rule %q has no tool", r.Glob)
		case r.Glob == "":
			t.Errorf("rule for %q has no glob", r.Tool)
		case !kinds[r.Kind]:
			t.Errorf("rule %s/%s has unknown kind %q", r.Tool, r.Glob, r.Kind)
		case r.Scope != ScopeProject && r.Scope != ScopeUser:
			t.Errorf("rule %s/%s has unknown scope %q", r.Tool, r.Glob, r.Scope)
		case !dialects[r.Frontmatter]:
			t.Errorf("rule %s/%s has unknown front-matter dialect %q", r.Tool, r.Glob, r.Frontmatter)
		}
		if r.Scope == ScopeUser && !strings.HasPrefix(r.Glob, "~/") {
			t.Errorf("user-scope rule %s/%s must be written ~/-prefixed", r.Tool, r.Glob)
		}
		if r.Scope == ScopeProject && strings.HasPrefix(r.Glob, "~/") {
			t.Errorf("project-scope rule %s/%s must not be ~/-prefixed", r.Tool, r.Glob)
		}
		key := r.Tool + "\x00" + r.Glob
		if seen[key] {
			t.Errorf("duplicate rule %s/%s", r.Tool, r.Glob)
		}
		seen[key] = true
	}
}

// TestRulesReturnsACopy pins the defensive copy — a consumer sorting the
// table must not reorder it for everyone else.
func TestRulesReturnsACopy(t *testing.T) {
	t.Parallel()
	a := Rules()
	if len(a) == 0 {
		t.Fatal("empty table")
	}
	a[0] = Rule{Tool: "tampered"}
	if Rules()[0].Tool == "tampered" {
		t.Error("Rules() handed out the backing array")
	}
}

// TestRulesCoverTheHeadlineConventions spot-checks the rows the rest of
// the feature is specified against.
func TestRulesCoverTheHeadlineConventions(t *testing.T) {
	t.Parallel()
	want := []struct {
		tool, glob string
		kind       Kind
		scope      Scope
	}{
		{"claude-code", "CLAUDE.md", KindInstructions, ScopeProject},
		{"claude-code", ".claude/skills/*/SKILL.md", KindSkill, ScopeProject},
		{"claude-code", "~/.claude/commands/**/*.md", KindCommand, ScopeUser},
		{"codex", "AGENTS.md", KindInstructions, ScopeProject},
		{"cursor", ".cursor/rules/**/*.mdc", KindRule, ScopeProject},
		{"copilot-cli", ".github/prompts/*.prompt.md", KindCommand, ScopeProject},
		{"cline-cli", ".clinerules/**/*.md", KindRule, ScopeProject},
		{"kilo-code", ".kilocode/rules/**/*.md", KindRule, ScopeProject},
		{"devin", ".windsurfrules", KindRule, ScopeProject},
		{"opencode", "opencode.json", KindConfig, ScopeProject},
		{"zcode", ".opencode/agent/*.md", KindAgent, ScopeProject},
		{"droid", ".factory/droids/*.md", KindAgent, ScopeProject},
		{"kiro-cli", ".kiro/steering/*.md", KindInstructions, ScopeProject},
		{"aider", "CONVENTIONS.md", KindInstructions, ScopeProject},
		{"goose", "~/.config/goose/.goosehints", KindInstructions, ScopeUser},
		{"gemini-cli", "GEMINI.md", KindInstructions, ScopeProject},
		{"antigravity", "**/GEMINI.md", KindInstructions, ScopeProject},
		{"qwen-code", "QWEN.md", KindInstructions, ScopeProject},
		{"qoder", "AGENTS.md", KindInstructions, ScopeProject},
	}
	index := map[string]Rule{}
	for _, r := range Rules() {
		index[r.Tool+"\x00"+r.Glob] = r
	}
	for _, w := range want {
		r, ok := index[w.tool+"\x00"+w.glob]
		if !ok {
			t.Errorf("missing rule %s/%s", w.tool, w.glob)
			continue
		}
		if r.Kind != w.kind {
			t.Errorf("%s/%s kind = %q want %q", w.tool, w.glob, r.Kind, w.kind)
		}
		if r.Scope != w.scope {
			t.Errorf("%s/%s scope = %q want %q", w.tool, w.glob, r.Scope, w.scope)
		}
	}
}

// TestSkillKey pins the wave-2 join primitive.
func TestSkillKey(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name            string
		tool            string
		kind            Kind
		input, wantKey  string
		wantSameAsAbove bool
	}{
		{name: "plain", tool: "claude-code", kind: KindSkill, input: "foo", wantKey: "claude-code/skill/foo"},
		{name: "case folded", tool: "Claude-Code", kind: KindSkill, input: "FOO", wantKey: "claude-code/skill/foo"},
		{name: "trimmed", tool: "claude-code", kind: KindSkill, input: "  foo  ", wantKey: "claude-code/skill/foo"},
		{name: "md suffix stripped", tool: "claude-code", kind: KindCommand, input: "deploy.md", wantKey: "claude-code/command/deploy"},
		{name: "mdc suffix stripped", tool: "cursor", kind: KindRule, input: "a.mdc", wantKey: "cursor/rule/a"},
		{name: "path collapses to its last element", tool: "claude-code", kind: KindCommand, input: "commands/sub/deploy.md", wantKey: "claude-code/command/deploy"},
		{name: "windows path", tool: "claude-code", kind: KindCommand, input: `commands\deploy.md`, wantKey: "claude-code/command/deploy"},
		{name: "empty name", tool: "codex", kind: KindInstructions, input: "", wantKey: "codex/instructions/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SkillKey(tc.tool, tc.kind, tc.input); got != tc.wantKey {
				t.Errorf("SkillKey(%q,%q,%q) = %q want %q", tc.tool, tc.kind, tc.input, got, tc.wantKey)
			}
		})
	}
}

// TestSkillKeyJoinsAScannedFile is the property the primitive exists for:
// a File produced by a scan and a bare name printed in a transcript
// resolve to the same key.
func TestSkillKeyJoinsAScannedFile(t *testing.T) {
	t.Parallel()
	res := scanFixture(t, testOptions())
	f := find(t, res, "claude-code", ".claude/skills/foo/SKILL.md")
	if a, b := SkillKey(f.Tool, f.Kind, f.Name), SkillKey("claude-code", KindSkill, "Foo-Skill"); a != b {
		t.Errorf("scan key %q != transcript key %q", a, b)
	}
}

// TestLocalOverlaysArePersonal: a project-scope file named "*.local.*" is a
// per-developer overlay the vendor keeps out of git, so the rule must say so
// (and only a project-scope rule may: a user-scope file is personal by
// where it lives, not by a flag).
func TestLocalOverlaysArePersonal(t *testing.T) {
	for _, r := range Rules() {
		base := path.Base(r.Glob)
		local := strings.Contains(base, ".local.")
		switch {
		case r.Scope == ScopeProject && local && !r.Personal:
			t.Errorf("%s %s: a .local. overlay must be Personal", r.Tool, r.Glob)
		case r.Personal && r.Scope != ScopeProject:
			t.Errorf("%s %s: Personal is only meaningful on a project-scope rule", r.Tool, r.Glob)
		case r.Personal && !local:
			t.Errorf("%s %s: Personal without a .local. name; extend this test with the vendor's grounding if that is intended", r.Tool, r.Glob)
		}
	}
	var sawClaudeLocal bool
	for _, r := range Rules() {
		if r.Tool == "claude-code" && r.Glob == "CLAUDE.local.md" {
			sawClaudeLocal = r.Personal
		}
	}
	if !sawClaudeLocal {
		t.Fatal("claude-code CLAUDE.local.md must be a Personal rule")
	}
}

// TestBorrowedRootsAreMarked pins Rule.Borrowed: a rule whose glob sits
// under a root another tool owns (or no tool owns, borrowedRoots) is
// borrowed, and a rule under the root its own tool owns is not. A borrowed
// directory must never count as install evidence (agentconfigsvc).
func TestBorrowedRootsAreMarked(t *testing.T) {
	var sawBorrowed bool
	for _, r := range Rules() {
		root := strings.SplitN(strings.TrimPrefix(r.Glob, "~/"), "/", 2)[0]
		owner, shared := borrowedRoots[root]
		want := shared && owner != r.Tool
		if r.Borrowed != want {
			t.Errorf("%s %s: Borrowed = %v, want %v (root %q owner %q)", r.Tool, r.Glob, r.Borrowed, want, root, owner)
		}
		sawBorrowed = sawBorrowed || r.Borrowed
	}
	if !sawBorrowed {
		t.Fatal("no borrowed rule: ibm-bob reads ~/.claude/skills")
	}
}
