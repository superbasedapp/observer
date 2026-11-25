package invariant

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

const obsImportPrefix = "github.com/marmutapp/superbased-observer/internal/obs"

// allowedObsImporters is the EXHAUSTIVE set of files outside internal/obs/
// permitted to import internal/obs/... — the single cmd/observer wiring point
// (plan §2.3/§11). Any other importer fails this test.
var allowedObsImporters = map[string]bool{
	"../../cmd/observer/obs_wire.go": true,
	// Its proxy half (lane MP-L1L, T-715, ruling D-518): the obs adapters
	// whose signatures name internal/proxy types, split out so a build
	// without capture.proxy keeps obs_wire.go. Same wiring point, two files.
	"../../cmd/observer/obs_wire_proxy.go": true,
	// Its `observer obs traces` half (Plane A lane B5, W2-5): the CLI file
	// obs_traces.go imports no obs package; this build-tagged file opens the
	// store and copies rows into cmd-side types. Same wiring point.
	"../../cmd/observer/obs_wire_traces.go": true,
	// Its node alert routes half (Plane A lane B9, W3-5): binds
	// internal/obs/httpapi's alert routes to the daemon's config file; only
	// obs_wire.go calls it. Same wiring point.
	"../../cmd/observer/obs_wire_alerts.go": true,
	// Its org app budget half (Plane A lane C1, W4-1): converts the budget
	// rail's verified app caps into internal/obs/admission's policy; only
	// obs_wire.go calls it. Same wiring point.
	"../../cmd/observer/obs_wire_appbudget.go": true,
	// Lane C8 (R-B15): sets openObsPrompts for `observer obs prompts`.
	"../../cmd/observer/obs_wire_prompts.go": true,
	// 2026-09-02 (G1-JUDGED-ADM, design §4.6 "sharing the admission engine as
	// a library"): the two AI-Gateway BINARIES adapt internal/obs/admission.
	// Evaluate to internal/orgserver/planebadmit's injected Evaluator seam.
	// Still cmd-layer wiring only — no internal/orgserver package imports
	// obs, so the node daemon's separability is untouched.
	"../../cmd/observer-org/planeb_admission_wire.go":       true,
	"../../cmd/observer-aigateway/planeb_admission_wire.go": true,
	// Plane A build-out W1c-5 (D15): the SDK control API's org admit()
	// adapts internal/obs/admission.Evaluate to sdkapi's injected
	// Evaluator seam. cmd-layer wiring only, like the two files above.
	"../../cmd/observer-org/sdkapi_admission_wire.go": true,
}

// TestObsReverseImportBoundary enforces the separability spine (plan §2.3/§11,
// CLAUDE.md module rule #1): NO package outside internal/obs/ imports
// internal/obs/..., except the single wiring file. This is what makes "easily
// separable" a mechanical CI guarantee rather than an aspiration — a leaked
// import (e.g. proxy/watcher/store reaching into obs) fails here, before the
// offending commit can land. It textually scans imports (build-tag agnostic),
// so the no_obs stub and the !no_obs wiring file are both covered.
func TestObsReverseImportBoundary(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Dirs: []string{
			filepath.Join("..", "..", "internal"),
			filepath.Join("..", "..", "cmd"),
		},
		Recursive: true,
		// The separability litmus is about the shipped binary's PRODUCTION
		// coupling: a _test.go file that imports obs is removed together
		// with the feature, so it's exempt (e.g. the cmd/observer
		// live-integration test legitimately drives obs). importpin skips
		// test files unless asked.
		Custom: func(file, p string) string {
			if p != obsImportPrefix && !strings.HasPrefix(p, obsImportPrefix+"/") {
				return ""
			}
			// The obs subtree imports its own packages — exempt it whole.
			if dir := filepath.ToSlash(filepath.Dir(file)); dir == "../../internal/obs" || strings.Contains(dir, "/internal/obs/") {
				return ""
			}
			if allowedObsImporters[filepath.ToSlash(file)] {
				return ""
			}
			return "only the cmd/observer wiring file may import internal/obs/... (separability boundary, plan §2.3/§11)"
		},
	})
}
