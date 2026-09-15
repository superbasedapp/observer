package config

import "testing"

// TestOrgClientConfig_ConfiguredServerURL is a table-driven pin of
// ConfiguredServerURL(): a blank OrgServerURL (including one that is
// only whitespace) reports false, REGARDLESS of Enabled — this method
// deliberately does not fold in Enabled, because the real
// "is this node's org rail actually running" question also depends on a
// persisted org_enrolment DB row this pure config package cannot see
// (BLOCK-1: the prior Enrolled() method conflated "config says a URL"
// with "the node is enrolled," which silently disabled a real enrolment
// whenever its config's org_server_url happened to be blank — see
// ConfiguredServerURL's doc comment and
// cmd/observer/start.go::orgClientShouldStart, which is the actual
// construction gate and the only place that can combine this with the DB
// row).
func TestOrgClientConfig_ConfiguredServerURL(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
		url     string
		want    bool
	}{
		{"disabled, no url", false, "", false},
		{"disabled, url set", false, "https://org.example", true},
		{"enabled, no url", true, "", false},
		{"enabled, whitespace-only url", true, "   ", false},
		{"enabled, url set", true, "https://org.example", true},
		{"enabled, url set with surrounding whitespace", true, "  https://org.example  ", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := OrgClientConfig{Enabled: tt.enabled, OrgServerURL: tt.url}
			if got := c.ConfiguredServerURL(); got != tt.want {
				t.Errorf("ConfiguredServerURL() with Enabled=%v OrgServerURL=%q = %v, want %v", tt.enabled, tt.url, got, tt.want)
			}
		})
	}
}
