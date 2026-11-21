//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secrulepack"
	"github.com/marmutapp/superbased-observer/internal/secscan/opengrep"
)

func TestCodeScanGone(t *testing.T) {
	mk := func(driver, pack, path string) secfinding.Finding {
		return secfinding.Finding{Engine: secfinding.Engine{Driver: driver}, Rule: secfinding.Rule{Pack: pack}, Location: secfinding.Location{RelPath: path}}
	}
	open := []secfinding.Finding{
		mk(opengrep.DriverID, secrulepack.PackID, "a.py"),
		mk(opengrep.DriverID, secrulepack.PackID, "unread.py"),
		mk("native", "security.secrets", "a.py"),
		mk(opengrep.DriverID, "another-pack", "b.py"),
	}
	g := codeScanGone(open, []string{"a.py", "b.py"})
	if g.Pack != secrulepack.PackID || len(g.Paths) != 1 || g.Paths[0] != "a.py" || len(g.Also) != 0 {
		t.Fatalf("gone %+v: only this driver's pack, in files the run read", g)
	}
	if g := codeScanGone(open, nil); g.Pack != "" {
		t.Fatalf("a run that read nothing (a diff scope) closed %+v", g)
	}
	var many []secfinding.Finding
	var read []string
	for i := 0; i < 600; i++ {
		p := fmt.Sprintf("f%03d.py", i)
		many = append(many, mk(opengrep.DriverID, secrulepack.PackID, p))
		read = append(read, p)
	}
	g = codeScanGone(many, read)
	if len(g.Paths) != maxGonePaths || len(g.Also) != 2 || len(g.Also[1].Paths) != 600-2*maxGonePaths {
		t.Fatalf("chunks %d + %d", len(g.Paths), len(g.Also))
	}
}

// TestCodeScanGoneForTaintHold: a file the intrafile taint pass held closes
// only the findings of the rules that are not taint rules; with no such
// rule list it closes nothing; every other read file closes every rule.
func TestCodeScanGoneForTaintHold(t *testing.T) {
	mk := func(path string) secfinding.Finding {
		return secfinding.Finding{Engine: secfinding.Engine{Driver: opengrep.DriverID}, Rule: secfinding.Rule{Pack: secrulepack.PackID}, Location: secfinding.Location{RelPath: path}}
	}
	open := []secfinding.Finding{mk("free.py"), mk("held.py")}
	scanned := opengrep.Scanned{Files: []string{"free.py", "held.py"}, TaintHold: []string{"held.py"}, TaintHoldRules: []string{"python.weak-cipher"}}
	g := codeScanGoneFor(open, scanned)
	if g.Pack != secrulepack.PackID || len(g.Paths) != 1 || g.Paths[0] != "free.py" || len(g.RulePrefixes) != 0 {
		t.Fatalf("free files close every rule: %+v", g)
	}
	if len(g.Also) != 1 || g.Also[0].Paths[0] != "held.py" || len(g.Also[0].RulePrefixes) != 1 || g.Also[0].RulePrefixes[0] != "python.weak-cipher" {
		t.Fatalf("a held file closes only the search rules: %+v", g.Also)
	}
	scanned.TaintHoldRules = nil
	if g := codeScanGoneFor(open, scanned); len(g.Also) != 0 || len(g.Paths) != 1 || g.Paths[0] != "free.py" {
		t.Fatalf("a held file with no rule list closed %+v", g)
	}
	scanned.TaintHold = nil
	if g := codeScanGoneFor(open, scanned); len(g.Paths) != 2 || len(g.Also) != 0 {
		t.Fatalf("no hold: %+v", g)
	}
	scanned.TaintHold = []string{"free.py", "held.py"}
	scanned.TaintHoldRules = []string{"python.weak-cipher"}
	if g := codeScanGoneFor(open, scanned); len(g.Paths) != 2 || len(g.RulePrefixes) != 1 || len(g.Also) != 0 {
		t.Fatalf("everything held: %+v", g)
	}
}

// TestCodeTaintCacheStore: the cache file round-trips, a missing file is
// empty, and a file that does not decode is an error the driver treats as
// empty.
func TestCodeTaintCacheStore(t *testing.T) {
	dir := t.TempDir()
	s := codeTaintCacheStore{path: filepath.Join(dir, "sub", codeTaintCacheFile)}
	if c, err := s.Load(); err != nil || len(c.Entries) != 0 {
		t.Fatalf("a missing cache: %+v %v", c, err)
	}
	in := opengrep.TaintCache{Version: opengrep.TaintCacheVersion, Entries: map[string]opengrep.TaintCacheEntry{"k": {Used: 7}}}
	if err := s.Save(in); err != nil {
		t.Fatal(err)
	}
	out, err := s.Load()
	if err != nil || out.Version != in.Version || out.Entries["k"].Used != 7 {
		t.Fatalf("round trip %+v %v", out, err)
	}
	if err := os.WriteFile(s.path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err == nil {
		t.Fatal("a broken cache file loaded")
	}
	f := filepath.Join(dir, "a.go")
	if err := os.WriteFile(f, []byte("package a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if n, regular, err := codeLstat(f); err != nil || !regular || n != 10 {
		t.Fatalf("codeLstat %d %v %v", n, regular, err)
	}
	if _, regular, err := codeLstat(dir); err != nil || regular {
		t.Fatalf("a directory is not a regular file: %v %v", regular, err)
	}
}
