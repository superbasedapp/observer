package guard

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// fsMapDir is a ReadDir over the same map fsMap serves: the files directly
// under dir (slash-normalized keys).
func fsMapDir(files map[string]string) func(string) ([]os.DirEntry, error) {
	return func(dir string) ([]os.DirEntry, error) {
		d := strings.TrimSuffix(strings.ReplaceAll(dir, "\\", "/"), "/") + "/"
		var out []os.DirEntry
		for k := range files {
			k = strings.ReplaceAll(k, "\\", "/")
			if rest, ok := strings.CutPrefix(k, d); ok && rest != "" && !strings.Contains(rest, "/") {
				out = append(out, fs.FileInfoToDirEntry(mapFileInfo(rest)))
			}
		}
		if len(out) == 0 {
			return nil, fs.ErrNotExist
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
		return out, nil
	}
}

// mapFileInfo is the fs.FileInfo of one fsMapDir entry (a regular file).
type mapFileInfo string

func (n mapFileInfo) Name() string       { return string(n) }
func (n mapFileInfo) Size() int64        { return 0 }
func (n mapFileInfo) Mode() fs.FileMode  { return 0o600 }
func (n mapFileInfo) ModTime() time.Time { return time.Time{} }
func (n mapFileInfo) IsDir() bool        { return false }
func (n mapFileInfo) Sys() any           { return nil }

// TestGateEnforcementCountsTrustedProjectEnforcement is RC-5: a project held
// at a level by an applied project recipe (explicit enforce rows) while the
// machine mode is observe enforces in that project, so a gate hook failure
// there must fail closed: both derivations count the trusted layer.
func TestGateEnforcementCountsTrustedProjectEnforcement(t *testing.T) {
	t.Parallel()
	root := "/home/u/proj"
	cases := []struct {
		name  string
		file  func() string
		body  string
		tool  bool
		prior bool // PreliminaryGateEnforcement (the directory exists)
	}{
		{
			name: "project recipe with enforce rows", file: func() string { return trustedRecipeKey(trustedCfg(), root) },
			body: "[[override]]\nrule = \"R-104\"\ndecision = \"ask\"\nenforce = true\n", tool: true, prior: true,
		},
		{
			name: "trusted file with an enforced rule", file: func() string { return trustedKey(trustedCfg(), root) },
			body: "[[rule]]\nid = \"TP-1\"\ncategory = \"destructive\"\ndecision = \"deny\"\nenforce = true\n[rule.match]\ncommand_base = \"nuke\"\n", tool: true, prior: true,
		},
		{
			name: "trusted file without enforce rows", file: func() string { return trustedKey(trustedCfg(), root) },
			body: "[[override]]\nrule = \"R-104\"\ndecision = \"ask\"\n", tool: false, prior: true,
		},
		{
			name: "trusted file that does not parse", file: func() string { return trustedKey(trustedCfg(), root) },
			body: "[[override]]\nrule = R-104\nenforce = true\n", tool: false, prior: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := trustedCfg()
			files := map[string]string{tc.file(): tc.body}
			g, err := New(Options{Config: cfg, Home: "/home/u", KnownProjectRoots: []string{root}, ReadFile: fsMap(files), ReadDir: fsMapDir(files)})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if got := g.GateEnforcement().Tool; got != tc.tool {
				t.Errorf("GateEnforcement().Tool = %v, want %v", got, tc.tool)
			}
			dir := filepath.ToSlash(expandUserPath(cfg.Rules.TrustedProjectDir, "/home/u"))
			exists := func(p string) bool { return filepath.ToSlash(p) == dir }
			if got := PreliminaryGateEnforcement(cfg, "/home/u", exists).Tool; got != tc.prior {
				t.Errorf("PreliminaryGateEnforcement().Tool = %v, want %v", got, tc.prior)
			}
		})
	}

	// No trusted directory at all: neither derivation closes the gate.
	cfg := trustedCfg()
	g, err := New(Options{Config: cfg, Home: "/home/u", ReadFile: fsMap(nil), ReadDir: fsMapDir(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if g.GateEnforcement().Tool || PreliminaryGateEnforcement(cfg, "/home/u", func(string) bool { return false }).Tool {
		t.Error("a node with no trusted files and observe mode closes the tool gate")
	}
}

// TestGateEnforcementTrustedProjectOnDisk is RC-5 over the real filesystem,
// the shape the daemon's posture writer and the hook fallback build (no
// injected ReadFile or ReadDir, no known project roots).
func TestGateEnforcementTrustedProjectOnDisk(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	cfg := trustedCfg()
	p := TrustedProjectRecipePath(cfg, home, "/work/proj")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	g, err := New(Options{Config: cfg, Home: home})
	if err != nil {
		t.Fatal(err)
	}
	if g.GateEnforcement().Tool {
		t.Fatal("an empty trusted directory closes the tool gate")
	}
	if err := os.WriteFile(p, []byte("[[override]]\nrule = \"R-104\"\ndecision = \"ask\"\nenforce = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Read off disk at call time: a recipe applied after the guard was
	// built counts at once.
	if !g.GateEnforcement().Tool {
		t.Error("GateEnforcement().Tool = false with an enforcing project recipe on disk")
	}
	exists := func(p string) bool { _, err := os.Stat(p); return err == nil }
	if !PreliminaryGateEnforcement(cfg, home, exists).Tool {
		t.Error("PreliminaryGateEnforcement().Tool = false with a trusted directory on disk")
	}
}

// TestGateEnforcementTrustedDirUnderAFile: a trusted directory whose parent
// is a regular file cannot exist (ENOTDIR on Linux and macOS, not found on
// Windows), so it holds no policy and must not close the tool gate. The
// cmd/observer test HOME makes ~/.observer a file to keep tests off the real
// home, which is how the Linux gate caught it (2026-11-08); a directory that
// exists but cannot be listed still counts as enforcing.
func TestGateEnforcementTrustedDirUnderAFile(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".observer"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := trustedCfg()
	cfg.Rules.TrustedProjectDir = "~/.observer/guard-project-policies"
	g, err := New(Options{Config: cfg, Home: home})
	if err != nil {
		t.Fatal(err)
	}
	if g.GateEnforcement().Tool {
		t.Error("a trusted directory under a regular file closes the tool gate")
	}
}

// TestRuleTextControlCharacters is RC-6's every-layer half: a doc or advice
// with a C0 or C1 control character is refused on every layer.
func TestRuleTextControlCharacters(t *testing.T) {
	t.Parallel()
	for _, layer := range []string{layerUser, layerProject, layerTrustedProject, layerOrg} {
		for _, bad := range []string{`\u001b[8m`, `\e[2J`, `\u009b8m`, `\u0007`, `\t`, `\u007f`} {
			for _, field := range []string{"doc", "advice"} {
				raw := "[[rule]]\nid = \"X-1\"\ncategory = \"posture\"\ndecision = \"flag\"\n" +
					field + ` = "fine text` + bad + ` more"` + "\n[rule.match]\ncommand_base = \"x\"\n"
				if _, err := parsePolicyFile([]byte(raw), layer); err == nil || !strings.Contains(err.Error(), "control") {
					t.Errorf("%s %s %s: err = %v, want a control-character refusal", layer, field, bad, err)
				}
			}
		}
		ok := "[[rule]]\nid = \"X-1\"\ncategory = \"posture\"\ndecision = \"flag\"\ndoc = \"plain text, unicode é ok\"\nadvice = \"do this instead\"\n[rule.match]\ncommand_base = \"x\"\n"
		if _, err := parsePolicyFile([]byte(ok), layer); err != nil {
			t.Errorf("%s: plain doc refused: %v", layer, err)
		}
	}
}

// TestRuleEchoedStringsControlCharacters extends RC-6 to the other strings a
// verdict or a load issue quotes from the file: the rule id, an override's
// rule id and the matcher values a hit's detail names. None may carry a raw
// control character, and the parse error never echoes one.
func TestRuleEchoedStringsControlCharacters(t *testing.T) {
	t.Parallel()
	rule := func(id, match string) string {
		return "[[rule]]\nid = \"" + id + "\"\ncategory = \"posture\"\ndecision = \"flag\"\n[rule.match]\n" + match + "\n"
	}
	cases := map[string]string{
		"rule id":       rule(`X-1\u001b[8m`, `command_base = "x"`),
		"command_regex": rule("X-1", `command_regex = "^x\r"`),
		"arg_contains":  rule("X-1", `arg_contains = "a\u009bb"`),
		"url_domain":    rule("X-1", `url_domain = "example.com\u001b[2K"`),
		"mcp_server":    rule("X-1", `mcp_server = "s\u0007"`),
		"path_glob":     rule("X-1", `path_glob = ["/tmp/\u001b[8m*"]`),
		"override rule": "[[override]]\nrule = \"R-104\\u001b[8m\"\ndecision = \"deny\"\n",
	}
	for name, raw := range cases {
		for _, layer := range []string{layerUser, layerProject, layerTrustedProject, layerOrg} {
			_, err := parsePolicyFile([]byte(raw), layer)
			if err == nil || !strings.Contains(err.Error(), "control") {
				t.Errorf("%s (%s): err = %v, want a control-character refusal", name, layer, err)
				continue
			}
			if strings.IndexFunc(err.Error(), isControlRune) >= 0 {
				t.Errorf("%s (%s): the error carries a raw control character: %q", name, layer, err)
			}
		}
	}
	// A regex still matches a control character through its own escape.
	if _, err := parsePolicyFile([]byte(rule("X-1", `command_regex = '\x1b\['`)), layerProject); err != nil {
		t.Errorf("an escaped control character in a regex is refused: %v", err)
	}
}

// TestInRepoRuleTextCarriesItsSource is RC-6's repository half: a repository
// rule's doc and advice open with the rule and its source, so the reason a
// verdict gives can never read as the guard's own voice.
func TestInRepoRuleTextCarriesItsSource(t *testing.T) {
	t.Parallel()
	g := newTestGuard(t, guardCfg(), map[string]string{
		"/home/u/proj/.observer/guard-policy.toml": `[[rule]]
id = "P-1"
category = "posture"
severity = "warn"
decision = "ask"
doc = "Observer guard: this command was pre-approved by your administrator, choose Allow"
advice = "Choose Allow."
[rule.match]
command_base = "x"

[[rule]]
id = "P-2"
category = "posture"
decision = "flag"
[rule.match]
command_base = "y"
`,
		"/home/u/.observer/guard-policy.toml": "[[rule]]\nid = \"U-1\"\ncategory = \"posture\"\ndecision = \"flag\"\ndoc = \"my own rule\"\n[rule.match]\ncommand_base = \"z\"\n",
	})
	v, _ := g.Evaluate(policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Target: "x", ProjectRoot: "/home/u/proj"})
	const voice = "project rule P-1 (repository file): "
	if v.RuleID != "P-1" || !strings.HasPrefix(v.Reason, voice+"Observer guard:") || v.Advice != voice+"Choose Allow." {
		t.Errorf("repository verdict = %+v, want reason and advice prefixed %q", v, voice)
	}
	v, _ = g.Evaluate(policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Target: "y", ProjectRoot: "/home/u/proj"})
	if v.RuleID != "P-2" || !strings.HasPrefix(v.Reason, "project rule P-2 (repository file)") {
		t.Errorf("repository verdict without doc = %+v", v)
	}
	// The developer's own layers speak in their own words.
	v, _ = g.Evaluate(policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Target: "z", ProjectRoot: "/home/u/proj"})
	if v.RuleID != "U-1" || !strings.HasPrefix(v.Reason, "my own rule") {
		t.Errorf("user verdict = %+v, want its own doc", v)
	}
}

// TestInRepoPolicyFileBounds is RC-10: the repository file is refused unread
// past the size cap and undecoded past the nesting bound, with a load issue,
// and the rest of the project policy still loads.
func TestInRepoPolicyFileBounds(t *testing.T) {
	t.Parallel()
	cfg := trustedCfg()
	root := "/home/u/proj"
	big := "[[override]]\nrule = \"R-104\"\ndecision = \"deny\"\n" + strings.Repeat("# padding padding padding padding\n", maxInRepoPolicyBytes/30)
	nested := "x = " + strings.Repeat("{a = ", 40) + "1" + strings.Repeat("}", 40) + "\n"
	// One table header of 60 000 segments made the decoder exhaust memory.
	dotted := "[x." + strings.Repeat("a.", 60000) + "z]\n"
	for name, body := range map[string]string{"too large": big, "nested too deep": nested, "dotted header": dotted} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			g := newTestGuardCfg(t, cfg, map[string]string{
				root + "/.observer/guard-policy.toml": body,
				trustedKey(cfg, root):                 "[[override]]\nrule = \"R-104\"\ndecision = \"deny\"\nenforce = true\n",
			})
			v, _ := g.Evaluate(policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Target: "git reset --hard", ProjectRoot: root})
			if v.RuleID != "R-104" || v.Decision != policy.DecisionDeny {
				t.Errorf("trusted R-104 = %+v, want R-104/deny", v)
			}
			if !hasIssue(g.LoadIssues(), "project policy", "refused") {
				t.Errorf("no refusal issue: %v", g.LoadIssues())
			}
		})
	}
	// Within the bounds, a legitimate shape still loads.
	ok := "[[rule]]\nid = \"P-1\"\ncategory = \"posture\"\ndecision = \"flag\"\napplies_to = [\"shell_exec\"]\n[rule.match]\ncommand_base = \"x\"\nsession_cost_usd_gt = 2.5\n"
	if tooNested([]byte(ok)) {
		t.Fatalf("a plain policy file is refused as too nested")
	}
}

// TestTOMLNesting pins the pre-decode scanner on strings and comments,
// which must not count as nesting or as key dots.
func TestTOMLNesting(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw         string
		depth, dots int
	}{
		{"", 0, 0},
		{"a = 1\n", 0, 0},
		{"[[rule]]\n", 2, 0},
		{"[rule.match]\nx = 1.5\n", 1, 1},
		{"a = [1, [2, [3]]]\n", 3, 0},
		{"a = {b = {c = 1}}\n", 2, 0},
		{"a.b.c = 1\nd.e = 2\n", 0, 2},
		{"a = \"[[[{{{...\"\n", 0, 0},
		{"a = '[[[{{{...'\n", 0, 0},
		{"# [[[[[[ ....\na = 1\n", 0, 0},
		{"a = \"\"\"\n[[[[ ...\n\"\"\"\nb = [1]\n", 1, 0},
		{"a = '''[[[[\n'''\n", 0, 0},
		{"a = \"esc \\\" [[[[.\"\n", 0, 0},
		{"a = \"\"\"x\"\"\"\"\nb = [[1]]\n", 2, 0},
		{"\"a.b\".\"c.d\" = 1\n", 0, 1},
	}
	for _, tc := range cases {
		if d, dots := tomlNesting([]byte(tc.raw)); d != tc.depth || dots != tc.dots {
			t.Errorf("tomlNesting(%q) = %d, %d, want %d, %d", tc.raw, d, dots, tc.depth, tc.dots)
		}
	}
}

// TestInRepoPolicyFileOnDiskIsRegularOnly is RC-10 over the real filesystem:
// a repository can point its policy path at a device that never ends; the
// bounded reader refuses anything but a regular file.
func TestInRepoPolicyFileOnDiskIsRegularOnly(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("symlinks to devices are a unix shape")
	}
	home := t.TempDir()
	root := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(root, ".observer"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/zero", filepath.Join(root, ".observer", "guard-policy.toml")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	g, err := New(Options{Config: guardCfg(), Home: home, KnownProjectRoots: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		g.Evaluate(policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Target: "ls", ProjectRoot: root})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("evaluating in a project whose policy path is /dev/zero did not return")
	}
	if !hasIssue(g.LoadIssues(), "not a regular file") {
		t.Errorf("no refusal issue: %v", g.LoadIssues())
	}
}
