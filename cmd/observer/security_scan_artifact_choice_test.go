//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan/scalibrfacade"
)

// artifactProject makes a project folder with an ELF-headed file in bin/,
// a JAR-headed archive in build/libs/ and a text file in dist/ (synthetic
// bytes only: no real binary, no environment).
func artifactProject(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range map[string]string{
		"bin/app":            "\x7fELF\x02\x01\x01\x00rest",
		"build/libs/app.jar": "PK\x03\x04\x14\x00\x00\x00rest",
		"dist/notes.txt":     "just text here, no program\n",
		"lib/dep.jar":        "PK\x03\x04\x14\x00\x00\x00rest",
		"tools/mytool":       "\x7fELF\x02\x01\x01\x00rest",
	} {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// TestArtifactChoiceStore: the choice is a node-local file keyed by the
// project root hash (no path stored); a folder is turned on only if it is a
// folder of the project, off whether or not it still exists; a damaged
// file is no choice.
func TestArtifactChoiceStore(t *testing.T) {
	dir := t.TempDir()
	root := artifactProject(t)
	if got := enabledArtifactDirs(dir, root); len(got) != 0 {
		t.Fatalf("nothing is on before a choice: %q", got)
	}
	for _, d := range []string{"bin", "./tools/", filepath.Join(root, "bin")} {
		if _, err := setArtifactDir(dir, root, d, true); err != nil {
			t.Fatalf("enable %s: %v", d, err)
		}
	}
	if got := enabledArtifactDirs(dir, root); !slices.Equal(got, []string{"bin", "tools"}) {
		t.Fatalf("on: %q (deduplicated, sorted, relative)", got)
	}
	raw, err := os.ReadFile(artifactChoicePath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), root) || strings.Contains(string(raw), filepath.ToSlash(root)) {
		t.Fatalf("the file names a path: %s", raw)
	}
	var onDisk map[string][]string
	if err := json.Unmarshal(raw, &onDisk); err != nil || !slices.Equal(onDisk[secposture.ProjectRootHash(root)], []string{"bin", "tools"}) {
		t.Fatalf("file %s (%v)", raw, err)
	}
	// Another project is unaffected.
	if got := enabledArtifactDirs(dir, artifactProject(t)); len(got) != 0 {
		t.Fatalf("another project: %q", got)
	}
	for name, d := range map[string]string{"missing": "nope", "a file": "bin/app", "outside": "..", "the root": ".", "absolute elsewhere": t.TempDir()} {
		if _, err := setArtifactDir(dir, root, d, true); err == nil {
			t.Errorf("enable %s (%s) must be refused", name, d)
		}
	}
	// Off works for a folder that is gone, and the last off removes the project.
	if err := os.RemoveAll(filepath.Join(root, "tools")); err != nil {
		t.Fatal(err)
	}
	if got, err := setArtifactDir(dir, root, "tools", false); err != nil || !slices.Equal(got, []string{"bin"}) {
		t.Fatalf("disable a removed folder: %q %v", got, err)
	}
	if got, err := setArtifactDir(dir, root, "bin", false); err != nil || len(got) != 0 {
		t.Fatalf("disable the last: %q %v", got, err)
	}
	if len(readArtifactChoices(dir)) != 0 {
		t.Fatal("a project with nothing on is not remembered")
	}
	// Damage reads as no choice.
	if err := os.WriteFile(artifactChoicePath(dir), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := enabledArtifactDirs(dir, root); len(got) != 0 {
		t.Fatalf("a damaged file is no choice: %q", got)
	}
}

// TestPlanArtifactScan: until a folder is turned on the plan reads nothing
// (not the default list either) and lists every discovered candidate as
// off; turning on or naming a folder moves it to the folders read.
func TestPlanArtifactScan(t *testing.T) {
	dir := t.TempDir()
	root := artifactProject(t)
	plan := planArtifactScan(dir, root, nil)
	if len(plan.On) != 0 {
		t.Fatalf("nothing is read before the developer turns a folder on: %q", plan.On)
	}
	if !slices.Equal(plan.Off, []string{"bin", "build", "dist"}) {
		t.Fatalf("off: %q (the discovered candidates; lib/ and tools/ are not candidates)", plan.Off)
	}
	if _, err := setArtifactDir(dir, root, "bin", true); err != nil {
		t.Fatal(err)
	}
	plan = planArtifactScan(dir, root, nil)
	if !slices.Equal(plan.On, []string{"bin"}) || !slices.Equal(plan.Off, []string{"build", "dist"}) {
		t.Fatalf("after enable: on %q off %q", plan.On, plan.Off)
	}
	// A folder named for one run joins the plan, stores nothing, and the
	// folders turned on stay.
	plan = planArtifactScan(dir, root, []string{"tools", "build"})
	if !slices.Equal(plan.On, []string{"bin", "build", "tools"}) || !slices.Equal(plan.Off, []string{"dist"}) {
		t.Fatalf("named: on %q off %q", plan.On, plan.Off)
	}
	if got := enabledArtifactDirs(dir, root); !slices.Equal(got, []string{"bin"}) {
		t.Fatalf("a per-run folder was stored: %q", got)
	}
}

// TestArtifactFoldersView: the card's and the list verb's rows: discovered
// candidates, off by default, with their header summary; a folder turned on
// that discovery would not offer is still listed; one that vanished says so.
func TestArtifactFoldersView(t *testing.T) {
	dir := t.TempDir()
	root := artifactProject(t)
	if _, err := setArtifactDir(dir, root, "tools", true); err != nil {
		t.Fatal(err)
	}
	if _, err := setArtifactDir(dir, root, "bin", true); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(root, "tools")); err != nil {
		t.Fatal(err)
	}
	v := artifactFolders(dir, root)
	if v.DriverCompiled != scalibrfacade.Compiled || v.Text == "" || v.Project != root {
		t.Fatalf("view header %+v", v)
	}
	by := map[string]bool{}
	for _, f := range v.Folders {
		by[f.Dir] = f.Enabled
	}
	if len(v.Folders) != 4 || !by["bin"] || by["build"] || by["dist"] || !by["tools"] {
		t.Fatalf("folders %+v", v.Folders)
	}
	for _, f := range v.Folders {
		switch f.Dir {
		case "bin":
			if f.Summary != "1 ELF executable" || !f.Default || !f.Present {
				t.Errorf("bin %+v", f)
			}
		case "build":
			if f.Summary != "1 JAR" || f.Default {
				t.Errorf("build %+v", f)
			}
		case "dist":
			if !f.Default || f.Counts[kindsTotalKey] != 0 {
				t.Errorf("dist %+v", f)
			}
		case "tools":
			if f.Present || f.Summary != "folder not found" {
				t.Errorf("tools %+v", f)
			}
		}
	}
	// The folders are sorted.
	dirs := make([]string, 0, len(v.Folders))
	for _, f := range v.Folders {
		dirs = append(dirs, f.Dir)
	}
	if !slices.IsSorted(dirs) {
		t.Errorf("not sorted: %q", dirs)
	}
}

// kindsTotalKey is a Counts key no folder carries.
const kindsTotalKey = "none"

// TestSecurityScanArtifactsVerbs: `scan artifacts` lists (everything off),
// `enable` and `disable` change the choice, and the list shows it; it
// refuses without a dependency driver selected.
func TestSecurityScanArtifactsVerbs(t *testing.T) {
	cfgPath, secDir := scanConsentConfig(t)
	root := artifactProject(t)
	run := func(args ...string) (string, error) {
		parent := &cobra.Command{Use: "scan", SilenceUsage: true, SilenceErrors: true}
		parent.PersistentFlags().String("config", cfgPath, "")
		parent.AddCommand(newSecurityScanArtifactsCmd())
		var out bytes.Buffer
		parent.SetOut(&out)
		parent.SetErr(&out)
		parent.SetArgs(append([]string{"artifacts"}, append(args, "--project", root)...))
		err := parent.Execute()
		return out.String(), err
	}
	out, err := run()
	if err != nil || !strings.Contains(out, "[off] bin: 1 ELF executable") || strings.Contains(out, "[ON ]") {
		t.Fatalf("list: %v\n%s", err, out)
	}
	// The list needs no driver; the choice verbs need SCALIBR, which an
	// sbo_omit_security_scan_scalibr build (the developer edition) leaves
	// out, and there they refuse with "not in this build".
	if !scalibrfacade.Compiled {
		if _, err = run("enable", "bin"); err == nil || !strings.Contains(err.Error(), "not in this build") {
			t.Fatalf("enable without SCALIBR compiled in = %v, want a not-in-this-build refusal", err)
		}
		t.Skip("SCALIBR is not compiled into this build; the rest needs it")
	}
	if out, err = run("enable", "bin"); err != nil || !strings.Contains(out, "bin is on") {
		t.Fatalf("enable: %v\n%s", err, out)
	}
	if got := enabledArtifactDirs(secDir, root); !slices.Equal(got, []string{"bin"}) {
		t.Fatalf("stored %q", got)
	}
	if out, err = run("list"); err != nil || !strings.Contains(out, "[ON ] bin") || !strings.Contains(out, "[off] build") {
		t.Fatalf("list after enable: %v\n%s", err, out)
	}
	if _, err = run("enable", "no-such-folder"); err == nil {
		t.Fatal("enabling a folder that is not there must fail")
	}
	if out, err = run("disable", "bin"); err != nil || !strings.Contains(out, "bin is off") {
		t.Fatalf("disable: %v\n%s", err, out)
	}
	if got := enabledArtifactDirs(secDir, root); len(got) != 0 {
		t.Fatalf("still on: %q", got)
	}
}

// TestSecurityScanArtifactsNeedADriver: with the drivers removed the verbs
// refuse before touching anything.
func TestSecurityScanArtifactsNeedADriver(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[components]\nremove = [\"security.scan.scalibr\", \"security.scan.osv\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := artifactProject(t)
	parent := &cobra.Command{Use: "scan", SilenceUsage: true, SilenceErrors: true}
	parent.PersistentFlags().String("config", cfgPath, "")
	parent.AddCommand(newSecurityScanArtifactsCmd())
	parent.SetArgs([]string{"artifacts", "enable", "bin", "--project", root})
	if err := parent.Execute(); err == nil {
		t.Fatal("artifacts enable must refuse with no dependency driver selected")
	}
	if _, err := os.Stat(filepath.Join(dir, "security", artifactChoiceFile)); err == nil {
		t.Fatal("a refused verb wrote the choice file")
	}
}
