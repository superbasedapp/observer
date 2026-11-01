package agentconfigsvc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// FU-142: Claude Code reads its user CLAUDE.md, skills, agents and commands
// from $CLAUDE_CONFIG_DIR, so with the variable set the instruction list, a
// new skill's path, a save, a glob target and the managed inventory name the
// files under that directory, and nothing under ~/.claude.

const (
	skillRow    = "claude-code/skill:~/.claude/skills/*/SKILL.md"
	agentRow    = "claude-code/agent:~/.claude/agents/*.md"
	commandRow  = "claude-code/command:~/.claude/commands/**/*.md"
	claudeMDRow = "claude-code/instructions:~/.claude/CLAUDE.md"
)

// writeUnder writes rel under dir.
func writeUnder(t *testing.T, dir, rel, body string) string {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// guidanceTree stages the same four kinds of file at the ~/.claude default
// (named "home-...") and under the relocated directory ("moved-...").
func guidanceTree(t *testing.T, h *harness, dir string) {
	t.Helper()
	h.write(".claude/CLAUDE.md", "# HOME-NOTES\n")
	h.write(".claude/skills/home-skill/SKILL.md", "---\nname: home-skill\ndescription: d\n---\nHOME-SKILL\n")
	h.write(".claude/agents/home-agent.md", "---\nname: home-agent\ndescription: d\n---\nHOME-AGENT\n")
	h.write(".claude/commands/home-cmd.md", "HOME-CMD\n")
	writeUnder(t, dir, "CLAUDE.md", "# MOVED-NOTES\n")
	writeUnder(t, dir, "skills/moved-skill/SKILL.md", "---\nname: moved-skill\ndescription: d\n---\nMOVED-SKILL\n")
	writeUnder(t, dir, "agents/moved-agent.md", "---\nname: moved-agent\ndescription: d\n---\nMOVED-AGENT\n")
	writeUnder(t, dir, "commands/sub/moved-cmd.md", "MOVED-CMD\n")
}

func userInstructionPaths(t *testing.T, h *harness) map[string]InstructionFile {
	t.Helper()
	files, err := h.svc.Instructions(context.Background(), "claude-code", "")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]InstructionFile{}
	for _, f := range files {
		if f.Scope == agentconfig.ScopeUser {
			out[f.Path] = f
		}
	}
	return out
}

func TestInstructionsFollowClaudeConfigDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claude-cfg")
	h := relocHarness(t, map[string]string{"CLAUDE_CONFIG_DIR": dir})
	guidanceTree(t, h, dir)
	got := userInstructionPaths(t, h)

	want := map[string]string{
		filepath.Join(dir, "CLAUDE.md"):                         claudeMDRow,
		filepath.Join(dir, "skills", "moved-skill", "SKILL.md"): skillRow,
		filepath.Join(dir, "agents", "moved-agent.md"):          agentRow,
		filepath.Join(dir, "commands", "sub", "moved-cmd.md"):   commandRow,
	}
	for p, row := range want {
		f, ok := got[p]
		if !ok || !f.Exists || f.FileID != row {
			t.Errorf("relocated %s: %+v (found %v), want an existing %s file", p, f, ok, row)
		}
	}
	for p, f := range got {
		if strings.HasPrefix(p, filepath.Join(h.home, ".claude")) {
			t.Errorf("the list names %s (%s), a ~/.claude file Claude Code does not read under CLAUDE_CONFIG_DIR", p, f.FileID)
		}
		if f.NewName && !strings.HasPrefix(p, dir) {
			t.Errorf("a new %s file would be made at %s, not under CLAUDE_CONFIG_DIR", f.FileID, p)
		}
	}

	// A new skill is named, previewed and saved under the variable's
	// directory; the home tree does not change.
	before := hashTree(t, h.home)
	path, err := h.svc.NewInstructionPath(Target{Tool: "claude-code", FileID: skillRow}, "deploy")
	if err != nil || path != filepath.Join(dir, "skills", "deploy", "SKILL.md") {
		t.Fatalf("NewInstructionPath = (%q, %v)", path, err)
	}
	body := "---\nname: deploy\ndescription: ships it\n---\nSteps.\n"
	ctx := context.Background()
	req := SaveRequest{Target: Target{Tool: "claude-code", FileID: skillRow, Path: path}, Raw: &body}
	pv, err := h.svc.Preview(ctx, req)
	if err != nil || !pv.OK {
		t.Fatalf("preview: %v %+v", err, pv.Findings)
	}
	req.PreviewEtag = pv.PreviewEtag
	out, err := h.svc.Save(ctx, req)
	if err != nil || out.Path != path {
		t.Fatalf("save: %+v %v", out, err)
	}
	if h.read(path) != body {
		t.Fatal("the skill was not written under CLAUDE_CONFIG_DIR")
	}
	if after := hashTree(t, h.home); !sameTree(before, after) {
		t.Fatal("the save changed the home tree")
	}

	// A glob target is judged under the variable's directory: the moved
	// agent is this row's file, the ~/.claude one is not.
	if raw, err := h.svc.Raw(ctx, Target{Tool: "claude-code", FileID: agentRow, Path: filepath.Join(dir, "agents", "moved-agent.md")}); err != nil || !strings.Contains(raw.Text, "MOVED-AGENT") {
		t.Fatalf("raw of the moved agent: %+v %v", raw, err)
	}
	if _, err := h.svc.Raw(ctx, Target{Tool: "claude-code", FileID: agentRow, Path: filepath.Join(h.home, ".claude", "agents", "home-agent.md")}); !errors.Is(err, ErrBadTarget) {
		t.Fatalf("raw of the ~/.claude agent: %v, want ErrBadTarget", err)
	}
	// The fixed-name CLAUDE.md row names the moved file.
	if raw, err := h.svc.Raw(ctx, Target{Tool: "claude-code", FileID: claudeMDRow}); err != nil || !strings.Contains(raw.Text, "MOVED-NOTES") {
		t.Fatalf("raw of CLAUDE.md: %+v %v", raw, err)
	}
}

// TestInventoryFollowsClaudeConfigDir: the managed inventory reports the
// moved instruction files under the catalogue's home spelling (the same
// logical file, no local path) and none of the ~/.claude ones.
func TestInventoryFollowsClaudeConfigDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claude-cfg")
	h := relocHarness(t, map[string]string{"CLAUDE_CONFIG_DIR": dir})
	h.write(".claude/settings.json", `{"model": "sonnet"}`+"\n")
	guidanceTree(t, h, dir)
	rep := h.svc.Inventory(context.Background(), nil)
	for _, c := range []struct{ setting, fileID, text string }{
		{"claude-code/@instructions", "claude-code/instructions:~/.claude/CLAUDE.md", "MOVED-NOTES"},
		{"claude-code/@skill", "claude-code/skill:~/.claude/skills/moved-skill/SKILL.md", "MOVED-SKILL"},
		{"claude-code/@agent", "claude-code/agent:~/.claude/agents/moved-agent.md", "MOVED-AGENT"},
		{"claude-code/@command", "claude-code/command:~/.claude/commands/sub/moved-cmd.md", "MOVED-CMD"},
	} {
		r, ok := invRow(rep.Rows, c.setting, c.fileID, "")
		if !ok || !strings.Contains(r.ObservedValue, c.text) {
			t.Errorf("inventory %s: %+v (found %v), want the moved file's text", c.fileID, r, ok)
		}
	}
	for _, r := range rep.Rows {
		if strings.Contains(r.ObservedValue, "HOME-") {
			t.Errorf("inventory row %s carries a ~/.claude file Claude Code does not read: %s", r.FileID, r.ObservedValue)
		}
		if strings.Contains(r.FileID, dir) || strings.Contains(r.FileID, h.home) {
			t.Errorf("inventory row id names a local path: %s", r.FileID)
		}
	}
}

// TestInstructionsRefuseARelativeClaudeConfigDir: a relative value is read
// by Claude Code against its own working directory, so the user rows have no
// file Observer can name: none is listed (the ~/.claude defaults included),
// and a save or a raw read of one is refused, naming the variable.
func TestInstructionsRefuseARelativeClaudeConfigDir(t *testing.T) {
	h := relocHarness(t, map[string]string{"CLAUDE_CONFIG_DIR": "relative/cfg"})
	guidanceTree(t, h, filepath.Join(t.TempDir(), "unused"))
	for p, f := range userInstructionPaths(t, h) {
		if f.FileID == claudeMDRow || f.FileID == skillRow || f.FileID == agentRow || f.FileID == commandRow {
			t.Errorf("a user file is listed under a relative CLAUDE_CONFIG_DIR: %s (%s)", p, f.FileID)
		}
	}
	ctx := context.Background()
	before := hashTree(t, h.home)
	body := "x\n"
	for _, tgt := range []Target{
		{Tool: "claude-code", FileID: claudeMDRow},
		{Tool: "claude-code", FileID: skillRow, Path: filepath.Join(h.home, ".claude", "skills", "home-skill", "SKILL.md")},
	} {
		if _, err := h.svc.Preview(ctx, SaveRequest{Target: tgt, Raw: &body}); !errors.Is(err, ErrNotEditable) || !strings.Contains(err.Error(), "CLAUDE_CONFIG_DIR") || strings.Contains(err.Error(), "relative/cfg") {
			t.Errorf("preview of %s: %v, want ErrNotEditable naming the variable, not its value", tgt.FileID, err)
		}
	}
	if _, err := h.svc.NewInstructionPath(Target{Tool: "claude-code", FileID: skillRow}, "x"); !errors.Is(err, ErrBadTarget) {
		t.Errorf("NewInstructionPath under a relative variable: %v, want ErrBadTarget", err)
	}
	if rep := h.svc.Inventory(ctx, nil); len(rep.Rows) > 0 {
		for _, r := range rep.Rows {
			if strings.Contains(r.ObservedValue, "HOME-") {
				t.Errorf("inventory reports a ~/.claude file under a relative variable: %s", r.FileID)
			}
		}
	}
	if after := hashTree(t, h.home); !sameTree(before, after) {
		t.Fatal("a refused save changed the home tree")
	}
}

// TestInstructionsPinnedHomeReadsNoClaudeConfigDir: with a nil Getenv and a
// pinned home, or an isolated process home, the service reads no variable,
// so the instruction list stays under the home.
func TestInstructionsPinnedHomeReadsNoClaudeConfigDir(t *testing.T) {
	for _, mode := range []string{"pinned", "isolated"} {
		t.Run(mode, func(t *testing.T) {
			outside := filepath.Join(t.TempDir(), "outside")
			writeUnder(t, outside, "skills/moved-skill/SKILL.md", "---\nname: moved-skill\ndescription: d\n---\nMOVED\n")
			t.Setenv("CLAUDE_CONFIG_DIR", outside)
			h := newHarness(t, func(o *Options) {
				o.Getenv = nil
				if mode == "isolated" {
					t.Setenv("HOME", o.Home)
					crossmount.StageForeignLayoutForTest(t, crossmount.ForeignLayoutForTest{Root: t.TempDir(), RealHome: t.TempDir()})
					if crossmount.IsolationReason() == "" {
						t.Fatal("the staged real home did not isolate HOME")
					}
					o.Home = ""
				}
			})
			h.write(".claude/skills/home-skill/SKILL.md", "---\nname: home-skill\ndescription: d\n---\nHOME\n")
			got := userInstructionPaths(t, h)
			if _, ok := got[filepath.Join(h.home, ".claude", "skills", "home-skill", "SKILL.md")]; !ok {
				t.Errorf("the home skill is not listed: %v", got)
			}
			for p := range got {
				if strings.HasPrefix(p, outside) {
					t.Errorf("a pinned or isolated home listed %s under the variable's directory", p)
				}
			}
		})
	}
}

// TestUnrelocatedInstructionsUnchanged: with no variable set the list is the
// ~/.claude one (the control).
func TestUnrelocatedInstructionsUnchanged(t *testing.T) {
	h := relocHarness(t, nil)
	guidanceTree(t, h, filepath.Join(t.TempDir(), "unused"))
	got := userInstructionPaths(t, h)
	for _, rel := range []string{"CLAUDE.md", "skills/home-skill/SKILL.md", "agents/home-agent.md", "commands/home-cmd.md"} {
		p := filepath.Join(h.home, ".claude", filepath.FromSlash(rel))
		if f, ok := got[p]; !ok || !f.Exists || f.relocatedID != "" {
			t.Errorf("%s: %+v (found %v), want the existing home file", p, f, ok)
		}
	}
}
