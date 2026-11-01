package integration

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestInstallSourcesCoverage pins the in-box install source table (lane
// SBX-P3C): every row names a registry tool, a closed installer kind, a
// package that matches the tool's own grounded npm InstallHint, a binary the
// registry resolves the tool by, a host set of plain lowercase names, and
// the vendor document with the day it was read.
func TestInstallSourcesCoverage(t *testing.T) {
	t.Parallel()
	hostRE := regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	seen := map[string]bool{}
	for _, s := range InstallSources() {
		if seen[s.Tool] {
			t.Errorf("%s: two rows", s.Tool)
		}
		seen[s.Tool] = true
		c, ok := For(s.Tool)
		if !ok {
			t.Errorf("%s: not a registry tool id", s.Tool)
			continue
		}
		if !slices.Contains(InstallerKinds(), s.Kind) {
			t.Errorf("%s: installer kind %q is not in the closed vocabulary", s.Tool, s.Kind)
		}
		if !strings.HasPrefix(s.DocURL, "https://") {
			t.Errorf("%s: doc URL %q is not https", s.Tool, s.DocURL)
		}
		if _, err := time.Parse("2006-01-02", s.DocDate); err != nil {
			t.Errorf("%s: doc date %q is not YYYY-MM-DD", s.Tool, s.DocDate)
		}
		if s.Grounding == "" {
			t.Errorf("%s: no grounding sentence", s.Tool)
		}
		if s.ScriptsGrounding == "" {
			t.Errorf("%s: whether the package needs its install scripts is not grounded", s.Tool)
		}
		if len(s.Hosts) == 0 {
			t.Errorf("%s: no host set", s.Tool)
		}
		for _, h := range s.Hosts {
			if !hostRE.MatchString(h) {
				t.Errorf("%s: host %q is not a plain lowercase host name", s.Tool, h)
			}
		}
		if c.Binary == nil || !slices.Contains(c.Binary.Names.Unix, s.Bin) {
			t.Errorf("%s: bin %q is not among the registry's binary names", s.Tool, s.Bin)
		}
		if s.Kind == InstallerNPM {
			grounded := false
			for _, h := range c.Binary.Installs {
				if h.Channel != "npm" || len(h.Argv) == 0 {
					continue
				}
				pkg := strings.TrimSuffix(h.Argv[len(h.Argv)-1], "@latest")
				grounded = grounded || pkg == s.Package
			}
			if !grounded {
				t.Errorf("%s: package %q is not the tool's grounded npm install", s.Tool, s.Package)
			}
		}
		if s.Kind == InstallerUV {
			grounded := false
			for _, h := range c.Binary.Installs {
				grounded = grounded || (h.Channel == "uv" && len(h.Argv) > 0 && h.Argv[len(h.Argv)-1] == s.Package)
			}
			if !grounded {
				t.Errorf("%s: package %q is not the tool's grounded uv install", s.Tool, s.Package)
			}
		}
	}
	if len(seen) == 0 {
		t.Fatal("the table is empty")
	}
}

// TestInstallSourceHasNoToolNameBranch pins the install step to the table:
// the sandbox install planner and the driver's install files name no
// registry tool id, so a new tool is a row, never a branch.
func TestInstallSourceHasNoToolNameBranch(t *testing.T) {
	t.Parallel()
	files, _ := filepath.Glob("../sandboxoci/install*.go")
	more, _ := filepath.Glob("../../cmd/observer/terminal_sandbox_oci_install*.go")
	files = append(files, more...)
	if len(files) == 0 {
		t.Fatal("no install files found")
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f) //nolint:gosec // G304: a source file of this module
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range InstallSources() {
			if strings.Contains(string(b), `"`+s.Tool+`"`) {
				t.Errorf("%s names the tool %q; the install step must read the table", f, s.Tool)
			}
		}
	}
}
