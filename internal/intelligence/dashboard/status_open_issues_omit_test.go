//go:build sbo_omit_security

package dashboard

import "testing"

// TestAPIStatusOpenIssuesCompiledOut: without the security module
// /api/status omits open_issues (the sidebar then hides the badge), rather
// than reporting a zero it never counted.
func TestAPIStatusOpenIssuesCompiledOut(t *testing.T) {
	s, _ := newTestServer(t)
	got := getStatus(t, s)
	counts, _ := got["counts"].(map[string]any)
	if v, ok := counts["open_issues"]; ok {
		t.Errorf("counts.open_issues = %v in a build without security, want absent", v)
	}
}
