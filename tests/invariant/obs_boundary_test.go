package invariant

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

const obsImportPrefix = "github.com/marmutapp/superbased-observer/internal/obs"

// allowedObsImporters is the EXHAUSTIVE set of files outside internal/obs/
// permitted to import internal/obs/... — the single cmd/observer wiring point
// (plan §2.3/§11). Any other importer fails this test.
var allowedObsImporters = map[string]bool{
	"../../cmd/observer/obs_wire.go": true,
	// 2026-09-02 (G1-JUDGED-ADM, design §4.6 "sharing the admission engine as
	// a library"): the two AI-Gateway BINARIES adapt internal/obs/admission.
	// Evaluate to internal/orgserver/planebadmit's injected Evaluator seam.
	// Still cmd-layer wiring only — no internal/orgserver package imports
	// obs, so the node daemon's separability is untouched.
	"../../cmd/observer-org/planeb_admission_wire.go":       true,
	"../../cmd/observer-aigateway/planeb_admission_wire.go": true,
}

// TestObsReverseImportBoundary enforces the separability spine (plan §2.3/§11,
// CLAUDE.md module rule #1): NO package outside internal/obs/ imports
// internal/obs/..., except the single wiring file. This is what makes "easily
// separable" a mechanical CI guarantee rather than an aspiration — a leaked
// import (e.g. proxy/watcher/store reaching into obs) fails here, before the
// offending commit can land. It textually scans imports (build-tag agnostic),
// so the no_obs stub and the !no_obs wiring file are both covered.
func TestObsReverseImportBoundary(t *testing.T) {
	roots := []string{
		filepath.Join("..", "..", "internal"),
		filepath.Join("..", "..", "cmd"),
	}
	fset := token.NewFileSet()
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			slashed := filepath.ToSlash(path)
			if d.IsDir() {
				// The obs subtree imports its own packages — exempt it whole.
				if slashed == "../../internal/obs" || strings.Contains(slashed, "/internal/obs/") {
					return fs.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}
			// The separability litmus is about the shipped binary's
			// PRODUCTION coupling: a _test.go file that imports obs is
			// removed together with the feature, so it's exempt (e.g. the
			// cmd/observer live-integration test legitimately drives obs).
			if strings.HasSuffix(path, "_test.go") {
				return nil
			}
			af, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if perr != nil {
				t.Fatalf("parse %s: %v", path, perr)
			}
			for _, imp := range af.Imports {
				p := strings.Trim(imp.Path.Value, `"`)
				if p != obsImportPrefix && !strings.HasPrefix(p, obsImportPrefix+"/") {
					continue
				}
				if allowedObsImporters[slashed] {
					continue
				}
				t.Errorf("%s imports %q — only the cmd/observer wiring file may import internal/obs/... (separability boundary, plan §2.3/§11)", slashed, p)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
}
