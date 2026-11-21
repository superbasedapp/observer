//go:build !sbo_omit_security

package invariant

// overviewGolden is the /api/status golden of a build with the security
// module compiled in: its counts carry open_issues.
const overviewGolden = "overview"
