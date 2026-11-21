//go:build sbo_omit_security

package invariant

// overviewGolden is the /api/status golden of a build without the security
// module (sbo_omit_security, the minimal edition): /api/status omits
// counts.open_issues there by design (status_open_issues_omit.go), and
// every other field matches overview.json.
const overviewGolden = "overview.no-security"
