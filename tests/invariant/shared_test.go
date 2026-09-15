package invariant

// Helpers shared across the sentinels in this package.
//
// Every file here compiles as one test package, so a helper declared inside a
// single sentinel is silently load-bearing for the others. Several of those
// sentinels are private-only and are removed by the public release scrub, which
// then leaves the survivors referencing undefined symbols. Anything used by
// more than one file therefore lives here, where it survives the scrub,
// rather than in whichever sentinel happened to introduce it.

// modulePath is the Go module path; import paths are made module-relative by
// stripping this prefix. Used by the cloud-egress, intel-import, pricing-feed,
// telemetrylog and edge boundary sentinels. Previously declared in
// edge_boundary_test.go, which is private-only.
const modulePath = "github.com/marmutapp/superbased-observer/"

// contains reports whether hay holds needle. Used by the privacy, budget
// posture, intel-import, live-DB-gate, statusline and telemetrylog sentinels.
// Previously declared in release_pipeline_test.go, which is private-only
// because it reads the private release workflow.
func contains(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}
