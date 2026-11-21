package invariant

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The Go source check, 3b-src (OS and CI vulnerability scanning plan
// section 14.5 item 3b, spike RG-0 "What changes in plan 14.5" item 7):
// osv-scanner's Go call analysis runs the project's own Go toolchain, so it
// is turned on in exactly one place, the source lane's flag row
// (depscan.OSVScannerSourceFlags), and every other osv-scanner run keeps
// --no-call-analysis=all; and the run is reachable only from the developer's
// two surfaces (the CLI verb and the Scanners card's seam), never from the
// daemon loop. Both read source only; nothing is built or run.

// callAnalysisOn is an argument literal that turns call analysis on.
var callAnalysisOn = regexp.MustCompile(`"--call-analysis(=|")`)

func walkGoSources(t *testing.T, dirs []string, fn func(rel, src string)) {
	t.Helper()
	root := repoRoot(t)
	for _, d := range dirs {
		err := filepath.WalkDir(filepath.Join(root, d), func(p string, e os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if e.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			fn(filepath.ToSlash(rel), string(b))
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestReachGoSourceCallAnalysisOnlyInTheSourceRow(t *testing.T) {
	var where []string
	walkGoSources(t, []string{"cmd", "internal"}, func(rel, src string) {
		if callAnalysisOn.MatchString(src) {
			where = append(where, rel)
		}
	})
	if len(where) != 1 || where[0] != "internal/secscan/depscan/rows.go" {
		t.Fatalf("an argument turning osv-scanner's call analysis on appears in %v; only the source lane's row (internal/secscan/depscan/rows.go, OSVScannerSourceFlags) may", where)
	}
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "internal", "secscan", "depscan", "rows.go"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	i := strings.Index(src, "var OSVScannerFlags = ")
	j := strings.Index(src, "var OSVScannerSourceFlags = ")
	if i < 0 || j < 0 {
		t.Fatal("rows.go no longer declares OSVScannerFlags and OSVScannerSourceFlags")
	}
	scan := src[i:]
	if k := strings.Index(scan, "\n}\n"); k > 0 {
		scan = scan[:k]
	}
	if !strings.Contains(scan, `"--no-call-analysis=all"`) || callAnalysisOn.MatchString(scan) {
		t.Fatalf("the scan driver's flag row must keep --no-call-analysis=all and never turn call analysis on:\n%s", scan)
	}
}

func TestReachGoSourceRunOnlyFromTheDevelopersSurfaces(t *testing.T) {
	allowed := map[string]bool{
		// The definition and the omit stub.
		"cmd/observer/security_reach_go_source.go":      true,
		"cmd/observer/security_reach_go_source_omit.go": true,
		// The CLI verb and the Scanners card's seam.
		"cmd/observer/security_reach_go_source_cmd.go": true,
	}
	walkGoSources(t, []string{"cmd", "internal"}, func(rel, src string) {
		if strings.Contains(src, "runReachSource(") && !allowed[rel] {
			t.Errorf("%s reaches the Go source check; only the CLI verb and the card's seam may (never the daemon loop)", rel)
		}
	})
}
