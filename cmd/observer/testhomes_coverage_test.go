package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
)

// homeScanDirs are the source trees (repo-relative) whose code resolves a
// per-user config location: the hook, MCP and proxy-route writers, the
// detectors and adapters that find installed tools, the agentconfig
// catalogue and this command.
var homeScanDirs = []string{
	"cmd/observer",
	"internal/adapter",
	"internal/agentconfig",
	"internal/hook",
	"internal/integration",
	"internal/mcp",
	"internal/mcpregister",
	"internal/proxyroute",
	"internal/shellwrapsvc",
	"internal/toolresolve",
}

// homeVarLiteral matches a Go string literal that is exactly a home-shaped
// environment variable name (..._HOME, ..._DIR, ..._CONFIG, ..._CONFIG_DIR,
// ..._DATA_DIR, ..._SETTINGS_PATH) or a Windows profile root.
var homeVarLiteral = regexp.MustCompile(`"([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_(?:HOME|DIR|CONFIG|SETTINGS_PATH)|APPDATA|LOCALAPPDATA|USERPROFILE)"`)

// TestToolHomeVarsCoverTheWriters fails when a writer, detector or the
// agentconfig relocation table names a home variable that toolHomeVars
// neither pins nor notAToolHome excludes with a reason: a new tool home
// must join the pin table in the same change.
func TestToolHomeVarsCoverTheWriters(t *testing.T) {
	pinned := map[string]bool{}
	for _, v := range toolHomeVars {
		if pinned[v.name] {
			t.Errorf("toolHomeVars lists %s twice", v.name)
		}
		pinned[v.name] = true
	}
	for name := range notAToolHome {
		if pinned[name] {
			t.Errorf("%s is both pinned and excluded", name)
		}
	}

	found := map[string]string{} // name -> first file
	root := filepath.Join("..", "..")
	for _, dir := range homeScanDirs {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" || d.Name() == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, err := os.ReadFile(path) //nolint:gosec // repo source under the scan dirs
			if err != nil {
				return err
			}
			for _, m := range homeVarLiteral.FindAllStringSubmatch(string(src), -1) {
				if _, ok := found[m[1]]; !ok {
					rel, _ := filepath.Rel(root, path)
					found[m[1]] = filepath.ToSlash(rel)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("scan %s: %v", dir, err)
		}
	}
	for _, f := range agentconfig.Files() {
		for _, r := range agentconfig.RelocationsFor(f.ID) {
			if _, ok := found[r.Env]; !ok {
				found[r.Env] = "agentconfig relocation rule " + f.ID
			}
		}
	}
	if len(found) == 0 {
		t.Fatal("the source scan found no home variable at all; the scan dirs or the pattern are wrong")
	}

	names := make([]string, 0, len(found))
	for name := range found {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if pinned[name] {
			continue
		}
		if _, ok := notAToolHome[name]; ok {
			continue
		}
		t.Errorf("%s (read in %s) is a home-shaped variable the pin table does not cover: add it to toolHomeVars in testhomes_helpers_test.go, or to notAToolHome with the reason it is not a home", name, found[name])
	}
	// A pinned or excluded name nothing reads any more is stale.
	for _, v := range toolHomeVars {
		if _, ok := found[v.name]; !ok && v.name != "HOME" {
			t.Errorf("toolHomeVars pins %s, which no scanned source reads; drop it", v.name)
		}
	}
	for name := range notAToolHome {
		if _, ok := found[name]; !ok {
			t.Errorf("notAToolHome excludes %s, which no scanned source reads; drop it", name)
		}
	}
}

// TestPinToolHomesPinsEveryVariable: after pinToolHomes every profile root
// is under the test home and every tool home variable is unset, whatever
// the developer's shell had.
func TestPinToolHomesPinsEveryVariable(t *testing.T) {
	for _, v := range toolHomeVars {
		t.Setenv(v.name, filepath.Join(string(filepath.Separator), "real", "profile", v.name))
	}
	home := pinToolHomes(t)
	for _, v := range toolHomeVars {
		got, set := os.LookupEnv(v.name)
		switch v.action {
		case homeVarSet:
			if !set || !strings.HasPrefix(got, home) {
				t.Errorf("%s = %q (set %v), want a path under %s", v.name, got, set, home)
			}
		case homeVarClear:
			if set {
				t.Errorf("%s = %q, want unset", v.name, got)
			}
		}
	}
	if h, err := os.UserHomeDir(); err != nil || h != home {
		t.Errorf("os.UserHomeDir() = %q, %v; want %s", h, err, home)
	}
	if d, err := os.UserConfigDir(); err != nil || !strings.HasPrefix(d, home) {
		t.Errorf("os.UserConfigDir() = %q, %v; want a path under %s", d, err, home)
	}
}
