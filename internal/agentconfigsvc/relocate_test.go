package agentconfigsvc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// FU-140: every read and write of the settings editor resolves a file row
// through the one path environment (Service.env, Relocate on), so with a
// tool's relocation variable set the view, raw / preview / save, the
// effective layers, the integrated-capture refusal and the managed
// inventory all name the relocated file, and nothing is written at the
// default location.

// relocCase is one tool with a relocation rule: the variable, the user
// settings row, its default path under home, its name under the variable's
// directory, a body and one form edit.
type relocCase struct {
	tool, env, fileID string
	defaultRel, name  string
	body              string
	edit              agentconfig.Edit
	want              string
	// layers: the tool has an effective-layer family over this file.
	layers bool
}

var relocCases = []relocCase{
	{
		tool: "claude-code", env: "CLAUDE_CONFIG_DIR", fileID: "claude-code/user-settings",
		defaultRel: ".claude/settings.json", name: "settings.json",
		body: claudeSettings,
		edit: agentconfig.Edit{Path: agentconfig.KeyPath{"model"}, Op: agentconfig.OpSet, Value: "opus"}, want: `"model": "opus"`,
		layers: true,
	},
	{
		tool: "codex", env: "CODEX_HOME", fileID: "codex/user-config",
		defaultRel: ".codex/config.toml", name: "config.toml",
		body: "model = \"gpt-5\"\n",
		edit: agentconfig.Edit{Path: agentconfig.KeyPath{"model"}, Op: agentconfig.OpSet, Value: "gpt-5.5"}, want: `model = "gpt-5.5"`,
	},
}

// relocHarness is a harness whose Getenv answers the given variables.
func relocHarness(t *testing.T, vars map[string]string) *harness {
	t.Helper()
	return newHarness(t, func(o *Options) { o.Getenv = func(k string) string { return vars[k] } })
}

func (c relocCase) save(t *testing.T, h *harness) (SaveOutcome, error) {
	t.Helper()
	req := SaveRequest{Target: Target{Tool: c.tool, FileID: c.fileID}, Edits: []agentconfig.Edit{c.edit}}
	p, err := h.svc.Preview(context.Background(), req)
	if err != nil {
		return SaveOutcome{}, err
	}
	req.PreviewEtag = p.PreviewEtag
	return h.svc.Save(context.Background(), req)
}

func TestSaveWritesTheRelocatedFileOnly(t *testing.T) {
	for _, c := range relocCases {
		t.Run(c.tool, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "relocated")
			h := relocHarness(t, map[string]string{c.env: dir})
			def := h.write(c.defaultRel, c.body)
			moved := filepath.Join(dir, c.name)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(moved, []byte(c.body), 0o644); err != nil {
				t.Fatal(err)
			}
			before := hashTree(t, h.home)
			ctx := context.Background()

			// The view names the relocated file and says what moved it.
			v, err := h.svc.Inspect(ctx, c.tool, "")
			if err != nil {
				t.Fatal(err)
			}
			fv := fileView(t, v, c.fileID)
			if fv.Path != moved || fv.State != agentconfig.FilePresent || !strings.Contains(fv.Reason, c.env) {
				t.Fatalf("view: %+v, want path %s present with a reason naming %s", fv, moved, c.env)
			}
			raw, err := h.svc.Raw(ctx, Target{Tool: c.tool, FileID: c.fileID})
			if err != nil || raw.Path != moved {
				t.Fatalf("raw: %+v %v", raw, err)
			}
			// The default file's path is not this row's file any more.
			if _, err := h.svc.Raw(ctx, Target{Tool: c.tool, FileID: c.fileID, Path: def}); !errors.Is(err, ErrBadTarget) {
				t.Fatalf("raw of the default path: %v, want ErrBadTarget", err)
			}

			out, err := c.save(t, h)
			if err != nil {
				t.Fatal(err)
			}
			if !out.Saved || out.Path != moved {
				t.Fatalf("outcome %+v, want saved to %s", out, moved)
			}
			if got := h.read(moved); !strings.Contains(got, c.want) {
				t.Fatalf("relocated file after save:\n%s", got)
			}
			if after := hashTree(t, h.home); !sameTree(before, after) {
				t.Fatalf("the save changed the home tree:\nbefore %v\nafter  %v", before, after)
			}
			if len(h.locks) == 0 || h.locks[0] != moved {
				t.Fatalf("lock not taken on the relocated file: %v", h.locks)
			}
			if len(h.st.writes) != 1 || h.st.writes[0].FilePath != moved {
				t.Fatalf("history names %+v, want %s", h.st.writes, moved)
			}

			// The effective layers read the same file.
			if !c.layers {
				return
			}
			rep, err := h.svc.EffectiveLayers(ctx, LayerOptions{Tools: []string{c.tool}})
			if err != nil {
				t.Fatal(err)
			}
			if p := rep.paths[layerPathKey("", c.fileID)]; p != moved {
				t.Fatalf("effective layers read %q, want %s", p, moved)
			}
		})
	}
}

// TestRelocatedSaveRefusesARelativeValue: a relative value is what the tool
// reads against its own working directory, so the row has no file Observer
// can name; the save refuses and writes nothing, the default file included
// (the R-188 F6 rule).
func TestRelocatedSaveRefusesARelativeValue(t *testing.T) {
	for _, c := range relocCases {
		t.Run(c.tool, func(t *testing.T) {
			h := relocHarness(t, map[string]string{c.env: "relative/dir"})
			h.write(c.defaultRel, c.body)
			before := hashTree(t, h.home)
			_, err := c.save(t, h)
			if !errors.Is(err, ErrNotEditable) || !strings.Contains(err.Error(), c.env) || strings.Contains(err.Error(), "relative/dir") {
				t.Fatalf("save: %v, want ErrNotEditable naming %s and not its value", err, c.env)
			}
			if after := hashTree(t, h.home); !sameTree(before, after) {
				t.Fatalf("a refused save changed the home tree")
			}
			v, err := h.svc.Inspect(context.Background(), c.tool, "")
			if err != nil {
				t.Fatal(err)
			}
			fv := fileView(t, v, c.fileID)
			if fv.Path != "" || fv.State != agentconfig.FileUnresolved || fv.Editable || !strings.Contains(fv.Reason, c.env) ||
				!strings.Contains(fv.NotEditable, "relative path") {
				t.Fatalf("view of an unresolved relocation: %+v", fv)
			}
		})
	}
}

// TestPinnedOrIsolatedHomeReadsNoRelocationVariable: with a nil Getenv the
// service applies crossmount.HomeEnv, so a pinned home, or an unpinned one
// whose process home is isolated, reads no variable and the save lands at
// the default path under that home.
func TestPinnedOrIsolatedHomeReadsNoRelocationVariable(t *testing.T) {
	for _, c := range relocCases {
		for _, mode := range []string{"pinned", "isolated"} {
			t.Run(c.tool+"/"+mode, func(t *testing.T) {
				outside := filepath.Join(t.TempDir(), "outside")
				if err := os.MkdirAll(outside, 0o755); err != nil {
					t.Fatal(err)
				}
				t.Setenv(c.env, outside)
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
				def := h.write(c.defaultRel, c.body)
				before := hashTree(t, outside)
				out, err := c.save(t, h)
				if err != nil {
					t.Fatal(err)
				}
				if out.Path != def || !strings.Contains(h.read(def), c.want) {
					t.Fatalf("saved %s, want the default %s", out.Path, def)
				}
				if after := hashTree(t, outside); !sameTree(before, after) {
					t.Fatalf("the save wrote under the variable's directory")
				}
			})
		}
	}
}

// TestIntegratedRefusalReadsTheRelocatedFile: the integrated-capture check
// looks for Observer's live entries in the file the tool reads.
func TestIntegratedRefusalReadsTheRelocatedFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "relocated")
	h := relocHarness(t, map[string]string{"CLAUDE_CONFIG_DIR": dir})
	plain := `{"model": "sonnet"}` + "\n"
	h.write(".claude/settings.json", claudeSettings) // Observer's hook, at the default only
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(moved, []byte(plain), 0o644); err != nil {
		t.Fatal(err)
	}
	if h.svc.integrated("claude-code", h.svc.snapshots("claude-code", "")) {
		t.Fatal("integrated judged on the default file Claude Code does not read")
	}
	if err := os.WriteFile(moved, []byte(claudeSettings), 0o644); err != nil {
		t.Fatal(err)
	}
	if !h.svc.integrated("claude-code", h.svc.snapshots("claude-code", "")) {
		t.Fatal("Observer's hook in the relocated file is not seen")
	}
}

// TestInventoryReadsTheRelocatedFile: the managed inventory reports the
// value of the file the tool reads.
func TestInventoryReadsTheRelocatedFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "relocated")
	h := relocHarness(t, map[string]string{"CLAUDE_CONFIG_DIR": dir})
	h.write(".claude/settings.json", `{"model": "sonnet"}`+"\n")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(`{"model": "opus"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep := h.svc.Inventory(context.Background(), nil)
	if r, ok := invRow(rep.Rows, "claude-code/model", "claude-code/user-settings", ""); !ok || r.ObservedValue != `"opus"` {
		t.Fatalf("inventory model row %+v (found %v), want the relocated file's value", r, ok)
	}
}

// TestRelocationsStayOnConcreteSettingsRows guards the parts of the service
// that walk under a home directory. A glob or instruction-family row may
// carry a relocation rule only as a directory move of a user-scope row (an
// Anchor under "~/"): that is what the instruction scan, a glob target and
// the inventory's file id follow (instructions_relocate.go, FU-142). The
// .env key read (dotenvPath) follows no rule, so no file of a tool whose
// .env files Observer reads may carry one. Claude Code's four user
// instruction rows must carry CLAUDE_CONFIG_DIR (FU-142).
func TestRelocationsStayOnConcreteSettingsRows(t *testing.T) {
	dotenvTools := map[string]bool{}
	for _, tool := range integration.Tools() {
		if c, ok := integration.For(tool); ok && c.Proxy != nil && c.Proxy.DotenvOverride != nil {
			dotenvTools[tool] = true
		}
	}
	for _, f := range agentconfig.Files() {
		rules := agentconfig.RelocationsFor(f.ID)
		if len(rules) == 0 {
			continue
		}
		glob := false
		for _, p := range []string{f.Paths.Linux, f.Paths.Darwin, f.Paths.Windows} {
			if strings.ContainsAny(p, "*?[") {
				glob = true
			}
		}
		if glob || isInstructionKind(f.Kind) {
			if f.Scope != agentconfig.ScopeUser {
				t.Errorf("%s: a %s-scope glob or instruction row carries a relocation rule; only a user-scope anchor is followed", f.ID, f.Scope)
			}
			for _, r := range rules {
				if r.Semantics == agentconfig.RelocDoesNotMoveArtifact {
					continue
				}
				if !strings.HasPrefix(r.Anchor, "~/") || r.Semantics == agentconfig.RelocFileNotDir {
					t.Errorf("%s: rule %s (%s) is not a directory move under ~/; the instruction scan and glob targets follow only that", f.ID, r.Env, r.Semantics)
				}
			}
		}
		if dotenvTools[f.Tool] {
			t.Errorf("%s: a tool whose .env files Observer reads carries a relocation rule; dotenvPath anchors at home", f.ID)
		}
	}
	for _, id := range []string{claudeMDRow, skillRow, agentRow, commandRow} {
		rules := agentconfig.RelocationsFor(id)
		if len(rules) != 1 || rules[0].Env != "CLAUDE_CONFIG_DIR" || rules[0].Anchor != "~/.claude" {
			t.Errorf("%s: rules %+v, want the CLAUDE_CONFIG_DIR directory move (FU-142)", id, rules)
		}
	}
}

func isInstructionKind(k agentconfig.FileKind) bool {
	switch k {
	case agentconfig.KindInstructions, agentconfig.KindSkill, agentconfig.KindAgent, agentconfig.KindCommand, agentconfig.KindRule:
		return true
	}
	return false
}

func fileView(t *testing.T, v agentconfig.ToolView, id string) agentconfig.FileView {
	t.Helper()
	for _, f := range v.Files {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("no file %s in the view", id)
	return agentconfig.FileView{}
}

// hashTree maps every entry under root to its sha256; a directory maps to
// "dir", so a save that only creates a directory is seen too.
func hashTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			out[p] = "dir"
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		out[p] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func sameTree(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// TestRelocationNoteRows: one case per relocationNote rule. A variable the
// catalogue declares not to move the file (does_not_move) is not "refused".
func TestRelocationNoteRows(t *testing.T) {
	row := agentconfig.FileRow{ID: "x/user-settings", Tool: "x"}
	cases := []struct {
		name     string
		rp       agentconfig.ResolvedPath
		want     []string
		mustNot  []string
		wantNone bool
	}{
		{name: "no variable", rp: agentconfig.ResolvedPath{Status: agentconfig.PathResolved}, wantNone: true},
		{name: "moved", rp: agentconfig.ResolvedPath{Status: agentconfig.PathResolved, RelocatedBy: "X_HOME"}, want: []string{"Moved by X_HOME"}},
		{name: "relative", rp: agentconfig.ResolvedPath{Status: agentconfig.PathRelocationUnresolved, RelocatedBy: "X_HOME"}, want: []string{"X_HOME holds a relative path"}},
		{name: "refused", rp: agentconfig.ResolvedPath{Status: agentconfig.PathResolved, RelocationIgnored: []string{"KIRO_HOME:home_ancestor"}}, want: []string{"refused (KIRO_HOME:home_ancestor)"}},
		{
			name: "does_not_move only", wantNone: true,
			rp: agentconfig.ResolvedPath{Status: agentconfig.PathResolved, RelocationIgnored: []string{"DIRAC_DIR:does_not_move", "DIRAC_DATA_DIR:does_not_move"}},
		},
		{
			name: "does_not_move beside a refusal",
			rp:   agentconfig.ResolvedPath{Status: agentconfig.PathResolved, RelocationIgnored: []string{"DIRAC_DATA_DIR:does_not_move", "DIRAC_DIR:relative_value"}},
			want: []string{"refused (DIRAC_DIR:relative_value)"}, mustNot: []string{"does_not_move"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := relocationNote(row, c.rp)
			if c.wantNone {
				if got != "" {
					t.Fatalf("note %q, want none", got)
				}
				return
			}
			for _, w := range c.want {
				if !strings.Contains(got, w) {
					t.Errorf("note %q lacks %q", got, w)
				}
			}
			for _, m := range c.mustNot {
				if strings.Contains(got, m) {
					t.Errorf("note %q carries %q", got, m)
				}
			}
		})
	}
}

// TestRelocationNotesNamesOnlyRelocatedFiles: the CLI's notes come from this
// map, so a file no variable touched carries none.
func TestRelocationNotesNamesOnlyRelocatedFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "relocated")
	h := relocHarness(t, map[string]string{"CLAUDE_CONFIG_DIR": dir})
	notes := h.svc.RelocationNotes("claude-code", "")
	if !strings.Contains(notes["claude-code/user-settings"], "CLAUDE_CONFIG_DIR") || strings.Contains(notes["claude-code/user-settings"], dir) {
		t.Fatalf("user-settings note %q, want the variable named and its value not", notes["claude-code/user-settings"])
	}
	for id := range notes {
		if len(agentconfig.RelocationsFor(id)) == 0 {
			t.Errorf("%s has a note but no relocation rule", id)
		}
	}
}
