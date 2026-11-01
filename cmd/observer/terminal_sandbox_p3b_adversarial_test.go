//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	"github.com/marmutapp/superbased-observer/internal/testsupport/publictree"
)

// terminal_sandbox_p3b_adversarial_test.go is the section 13.12 gate for the
// two rows lane SBX-P3B added (oci-runsc and process_lite): the tables in
// docs/sandboxed-terminals.md must carry every case the lane owes (A1 to A9
// and A12, plus A13 for the explicit-only Landlock row), no cell may be
// empty, and every test a cell names must exist in the tree. Like the macOS
// gate this is bookkeeping (the named tests run in their own packages); the
// behaviour it checks itself is A13, through the real selection rule.

// p3bAdversarialTables are the doc headings and the cases each must carry.
var p3bAdversarialTables = []struct {
	heading string
	cases   []string
}{
	{"### Adversarial cases (plan section 13.12, the gVisor row)", []string{"A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "A12"}},
	{"### Adversarial cases (plan section 13.12, the Landlock row)", []string{"A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "A12", "A13"}},
	{"### Adversarial cases (plan section 13.12, the OCI family)", []string{"A12"}},
}

var testNameRE = regexp.MustCompile("`(Test[A-Za-z0-9_]+)`")

func TestP3BAdversarialGate(t *testing.T) {
	publictree.Skip(t, "docs/sandboxed-terminals.md")
	docBytes, err := os.ReadFile(filepath.Join("..", "..", "docs", "sandboxed-terminals.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(docBytes)
	var tests strings.Builder
	for _, dir := range []string{".", "../../internal"} {
		_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(p, "_test.go") {
				if b, rerr := os.ReadFile(p); rerr == nil { //nolint:gosec // G304: the repository's own test files
					tests.Write(b)
				}
			}
			return nil
		})
	}
	src := tests.String()
	for _, tbl := range p3bAdversarialTables {
		i := strings.Index(doc, tbl.heading)
		if i < 0 {
			t.Errorf("docs/sandboxed-terminals.md has no %q", tbl.heading)
			continue
		}
		body := doc[i+len(tbl.heading):]
		if j := strings.Index(body, "\n#"); j >= 0 {
			body = body[:j]
		}
		rows := map[string]string{}
		for _, line := range strings.Split(body, "\n") {
			cells := strings.Split(line, "|")
			if len(cells) < 4 {
				continue
			}
			id, _, _ := strings.Cut(strings.TrimSpace(cells[1]), " ")
			rows[id] = strings.TrimSpace(cells[2])
		}
		for _, c := range tbl.cases {
			cell, ok := rows[c]
			if !ok || cell == "" {
				t.Errorf("%s: case %s has no disposition", tbl.heading, c)
				continue
			}
			for _, m := range testNameRE.FindAllStringSubmatch(cell, -1) {
				if !strings.Contains(src, "func "+m[1]+"(") {
					t.Errorf("%s %s: test %s does not exist", tbl.heading, c, m[1])
				}
			}
		}
	}
}

// TestP3BRowsNeverPickedAutomatically is A13 for both rows: a launch that
// names no backend never takes either (beta, ruling P-062).
func TestP3BRowsNeverPickedAutomatically(t *testing.T) {
	for _, row := range []string{sandboxbackend.BackendOCIRunsc, sandboxbackend.BackendProcessLite} {
		c, ok := sandboxbackend.Get(row)
		if !ok {
			t.Fatalf("%s: no registry row", row)
		}
		v, _ := c.VerificationOn(sandboxbackend.HostLinux)
		if d, dropped := sandboxselect.AutoDrop(c, v.Kind); !dropped {
			t.Errorf("%s: an automatic choice is not refused: %+v", row, d)
		}
	}
}
