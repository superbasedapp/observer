package shellwrapsvc

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/shellwrap"
)

// fixture is a throwaway home: every path the service touches lives under
// t.TempDir(). The real home, rc files and PATH are never read or written.
type fixture struct {
	t    *testing.T
	home string
	svc  Service
	env  map[string]string
	obs  string
	log  string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("exercises the POSIX layout")
	}
	home := t.TempDir()
	f := &fixture{t: t, home: home, env: map[string]string{}, log: filepath.Join(home, "log")}
	f.obs = filepath.Join(home, "bin", "observer")
	writeFile(t, f.obs, "#!/bin/sh\nprintf 'observer %s\\n' \"$*\" >> '"+f.log+"'\n", 0o755)
	f.svc = Service{
		Home:         home,
		GOOS:         "linux",
		Getenv:       func(k string) string { return f.env[k] },
		ObserverPath: f.obs,
	}
	return f
}

func writeFile(t *testing.T, p, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return string(b)
}

func routedCLI(t *testing.T) shellwrap.Candidate {
	t.Helper()
	for _, c := range shellwrap.Candidates("linux") {
		if c.Kind == integration.LaunchKindTerminal && c.Honesty == shellwrap.HonestyRouted {
			return c
		}
	}
	t.Fatal("no routed CLI row")
	return shellwrap.Candidate{}
}

func secondCLI(t *testing.T, not string) shellwrap.Candidate {
	t.Helper()
	for _, c := range shellwrap.Candidates("linux") {
		if c.Kind == integration.LaunchKindTerminal && c.ID != not {
			return c
		}
	}
	t.Fatal("no second CLI row")
	return shellwrap.Candidate{}
}

func (f *fixture) apply(tools []string, shells ...string) Outcome {
	f.t.Helper()
	out, err := f.svc.Apply(context.Background(), Request{Tools: tools, Shells: shells})
	if err != nil {
		f.t.Fatalf("Apply: %v", err)
	}
	return out
}

func TestEnableDisableRestoresRCByteForByte(t *testing.T) {
	f := newFixture(t)
	c := routedCLI(t)
	bashrc := filepath.Join(f.home, ".bashrc")
	orig := "# my bashrc\nexport A=1" // no trailing newline, on purpose
	writeFile(t, bashrc, orig, 0o600)
	cfgPath := filepath.Join(f.home, ".observer", "config.toml")
	cfgOrig := "# operator comment kept\n[observer]\nlog_level = \"info\"\n"
	writeFile(t, cfgPath, cfgOrig, 0o600)

	out := f.apply([]string{c.ID})
	if out.DryRun || len(out.Plan.Shims) == 0 {
		t.Fatalf("outcome %+v", out)
	}
	shim := filepath.Join(f.home, ".observer", "shims", c.Commands[0])
	fi, err := os.Stat(shim)
	if err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("shim: %v %v", fi, err)
	}
	got := read(t, bashrc)
	if !strings.HasPrefix(got, orig+"\n"+shellwrap.BlockBegin) {
		t.Fatalf("bashrc: %q", got)
	}
	if fi, _ := os.Stat(bashrc); fi.Mode().Perm() != 0o600 {
		t.Fatalf("rc mode changed to %v", fi.Mode().Perm())
	}
	cfgText := read(t, cfgPath)
	if !strings.Contains(cfgText, "# operator comment kept") {
		t.Fatalf("config comments lost:\n%s", cfgText)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ShellWrap.Enabled || !cfg.ShellWrap.Tools[c.ID] {
		t.Fatalf("choice not recorded: %+v", cfg.ShellWrap)
	}
	if !out.Status.Enabled || !out.Status.InSync {
		t.Fatalf("status after apply: %+v", out.Status)
	}

	// Idempotent: a second apply changes nothing.
	again := f.apply([]string{c.ID})
	for _, ch := range again.Changes {
		if ch.Action != ActionUnchanged {
			t.Fatalf("second apply changed %+v", ch)
		}
	}
	if read(t, bashrc) != got {
		t.Fatal("second apply rewrote the rc")
	}

	// Undo: byte-for-byte.
	dis, err := f.svc.Disable(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if read(t, bashrc) != orig {
		t.Fatalf("disable did not restore the rc:\n%q", read(t, bashrc))
	}
	if _, err := os.Stat(filepath.Join(f.home, ".observer", "shims")); !os.IsNotExist(err) {
		t.Fatalf("empty shim dir left behind: %v", err)
	}
	cfg, _ = config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if cfg.ShellWrap.Enabled || !cfg.ShellWrap.Tools[c.ID] {
		t.Fatalf("disable must record enabled=false and KEEP the choice: %+v", cfg.ShellWrap)
	}
	if dis.Status.Active {
		t.Fatalf("status after disable still active: %+v", dis.Status)
	}
}

func TestCreatedRCFilesAreDeletedOnDisable(t *testing.T) {
	f := newFixture(t)
	c := routedCLI(t)
	f.apply([]string{c.ID}, "zsh", "fish")
	zshrc := filepath.Join(f.home, ".zshrc")
	fish := filepath.Join(f.home, ".config", "fish", "conf.d", shellwrap.FishFileName)
	for _, p := range []string{zshrc, fish} {
		if !strings.Contains(read(t, p), shellwrap.BlockBegin) {
			t.Fatalf("%s lacks the block", p)
		}
	}
	if _, err := f.svc.Disable(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{zshrc, fish} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s was created by enable and must be gone after disable: %v", p, err)
		}
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	f := newFixture(t)
	c := routedCLI(t)
	bashrc := filepath.Join(f.home, ".bashrc")
	writeFile(t, bashrc, "x\n", 0o644)
	out, err := f.svc.Apply(context.Background(), Request{Tools: []string{c.ID}, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if !out.DryRun || len(out.Changes) == 0 {
		t.Fatalf("dry run: %+v", out)
	}
	var sawBlock bool
	for _, ch := range out.Changes {
		if ch.Kind == "rc" && strings.Contains(ch.Detail, shellwrap.BlockBegin) {
			sawBlock = true
		}
	}
	if !sawBlock {
		t.Fatal("a preview must show the exact block it would write")
	}
	if read(t, bashrc) != "x\n" {
		t.Fatal("dry run modified the rc")
	}
	for _, p := range []string{filepath.Join(f.home, ".observer", "shims"), filepath.Join(f.home, ".observer", "config.toml")} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("dry run created %s", p)
		}
	}
}

func TestDeselectRemovesThatShimOnly(t *testing.T) {
	f := newFixture(t)
	a := routedCLI(t)
	b := secondCLI(t, a.ID)
	writeFile(t, filepath.Join(f.home, ".bashrc"), "", 0o644)
	f.apply([]string{a.ID, b.ID})
	shims := filepath.Join(f.home, ".observer", "shims")
	f.apply([]string{a.ID})
	if _, err := os.Stat(filepath.Join(shims, a.Commands[0])); err != nil {
		t.Fatalf("kept shim gone: %v", err)
	}
	for _, cmd := range b.Commands {
		if _, err := os.Stat(filepath.Join(shims, cmd)); !os.IsNotExist(err) {
			t.Fatalf("deselected shim %s still present", cmd)
		}
	}
	cfg, _ := config.Load(config.LoadOptions{GlobalPath: filepath.Join(f.home, ".observer", "config.toml")})
	if cfg.ShellWrap.Tools[b.ID] || !cfg.ShellWrap.Tools[a.ID] {
		t.Fatalf("recorded tools %+v", cfg.ShellWrap.Tools)
	}
}

func TestSymlinkedRCIsEditedAtItsTarget(t *testing.T) {
	f := newFixture(t)
	c := routedCLI(t)
	target := filepath.Join(f.home, "dotfiles", "bashrc")
	writeFile(t, target, "orig\n", 0o644)
	link := filepath.Join(f.home, ".bashrc")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	f.apply([]string{c.ID})
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the symlink was replaced: %v %v", fi, err)
	}
	if !strings.Contains(read(t, target), shellwrap.BlockBegin) {
		t.Fatal("target not edited")
	}
	if _, err := f.svc.Disable(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if read(t, target) != "orig\n" {
		t.Fatalf("target not restored: %q", read(t, target))
	}
}

func TestMalformedRCAbortsBeforeAnyWrite(t *testing.T) {
	f := newFixture(t)
	c := routedCLI(t)
	bad := "x\n" + shellwrap.BlockBegin + "\n" // no end marker
	writeFile(t, filepath.Join(f.home, ".bashrc"), bad, 0o644)
	if _, err := f.svc.Apply(context.Background(), Request{Tools: []string{c.ID}}); err == nil {
		t.Fatal("a malformed block must abort")
	}
	if _, err := os.Stat(filepath.Join(f.home, ".observer", "shims")); !os.IsNotExist(err) {
		t.Fatal("shims written before the abort")
	}
	if read(t, filepath.Join(f.home, ".bashrc")) != bad {
		t.Fatal("malformed rc touched")
	}
}

func TestForeignFileInShimDirIsNeverOverwritten(t *testing.T) {
	f := newFixture(t)
	c := routedCLI(t)
	writeFile(t, filepath.Join(f.home, ".bashrc"), "", 0o644)
	mine := filepath.Join(f.home, ".observer", "shims", c.Commands[0])
	writeFile(t, mine, "#!/bin/sh\necho operator-owned\n", 0o755)
	if _, err := f.svc.Apply(context.Background(), Request{Tools: []string{c.ID}}); err == nil {
		t.Fatal("an unmarked file with the shim's name must be refused")
	}
	if read(t, mine) != "#!/bin/sh\necho operator-owned\n" {
		t.Fatal("operator file overwritten")
	}
	// Disable never deletes it either.
	if _, err := f.svc.Disable(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(mine); err != nil {
		t.Fatal("disable deleted an unmarked file")
	}
}

func TestAllUsesTheInstalledProbe(t *testing.T) {
	f := newFixture(t)
	c := routedCLI(t)
	f.svc.Installed = func(id string) bool { return id == c.ID }
	writeFile(t, filepath.Join(f.home, ".bashrc"), "", 0o644)
	out := f.apply([]string{shellwrap.AllTools})
	if len(out.Plan.Tools) != 1 || out.Plan.Tools[0].ID != c.ID {
		t.Fatalf("all expanded to %+v", out.Plan.Tools)
	}
}

// TestEndToEndShellRunsObserver sources the written rc in a real sh and runs
// the command by NAME: the shim must hand it to observer with a `--`.
func TestEndToEndShellRunsObserver(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	f := newFixture(t)
	c := routedCLI(t)
	bashrc := filepath.Join(f.home, ".bashrc")
	writeFile(t, bashrc, "", 0o644)
	f.apply([]string{c.ID})
	script := ". '" + bashrc + "'; " + c.Commands[0] + " --flag 'two words'"
	cmd := exec.Command("sh", "-c", script) //nolint:gosec // test
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + f.home}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run: %v %s", err, out)
	}
	want := c.Wrapped + " -- --flag two words\n"
	if got := read(t, f.log); got != want {
		t.Fatalf("observer got %q, want %q", got, want)
	}
}

func TestStatusReportsDrift(t *testing.T) {
	f := newFixture(t)
	c := routedCLI(t)
	writeFile(t, filepath.Join(f.home, ".bashrc"), "", 0o644)
	f.apply([]string{c.ID})
	// The operator deletes a shim by hand.
	if err := os.Remove(filepath.Join(f.home, ".observer", "shims", c.Commands[0])); err != nil {
		t.Fatal(err)
	}
	st, err := f.svc.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !st.Enabled || st.InSync {
		t.Fatalf("drift not reported: %+v", st)
	}
}
