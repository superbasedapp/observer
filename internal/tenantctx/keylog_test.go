package tenantctx

import (
	"strings"
	"testing"
)

// pgDefaults is a PostgreSQL 16 server's default logging, under which the
// key reaches no log.
func pgDefaults() map[string]string {
	return map[string]string{
		"log_statement":                     "none",
		"log_min_duration_statement":        "-1",
		"log_min_duration_sample":           "-1",
		"log_statement_sample_rate":         "1",
		"log_parameter_max_length":          "-1",
		"log_parameter_max_length_on_error": "0",
		"log_min_error_statement":           "error",
	}
}

// TestKeyLogExposure: one row per rule of keyLogRules, each with the change
// that triggers it and, where one exists, the setting that defuses it.
func TestKeyLogExposure(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		change map[string]string
		want   string // "" = no exposure
	}{
		{"server defaults", nil, ""},
		{"log_statement mod (a SELECT is not mod)", map[string]string{"log_statement": "mod"}, ""},
		{"log_statement all", map[string]string{"log_statement": "all"}, "log_statement = all"},
		{"log_statement all without parameters", map[string]string{"log_statement": "all", "log_parameter_max_length": "0"}, ""},
		{"slow statement logging", map[string]string{"log_min_duration_statement": "1000"}, "log_min_duration_statement"},
		{"slow statement logging without parameters", map[string]string{"log_min_duration_statement": "0", "log_parameter_max_length": "0"}, ""},
		{"sampled slow statements", map[string]string{"log_min_duration_sample": "100"}, "log_min_duration_sample"},
		{"sampled at rate 0", map[string]string{"log_min_duration_sample": "100", "log_statement_sample_rate": "0"}, ""},
		{"parameters on error", map[string]string{"log_parameter_max_length_on_error": "-1"}, "log_parameter_max_length_on_error"},
		{"parameters on error, errors not logged", map[string]string{"log_parameter_max_length_on_error": "-1", "log_min_error_statement": "panic"}, ""},
		{"pgaudit parameters", map[string]string{"pgaudit.log": "write,function", "pgaudit.log_parameter": "on"}, "pgaudit.log_parameter"},
		{"pgaudit loaded, parameters off", map[string]string{"pgaudit.log": "all", "pgaudit.log_parameter": "off"}, ""},
		{"pgaudit parameters, nothing audited", map[string]string{"pgaudit.log": "none", "pgaudit.log_parameter": "on"}, ""},
		// OVH managed PostgreSQL 16 as delivered (2026-11-14, deploy/saas-ovh):
		// slow statements over 1 s are logged with every parameter in full.
		{"OVH managed defaults", map[string]string{"log_min_duration_statement": "1000", "log_parameter_max_length": "-1"}, "log_min_duration_statement"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := pgDefaults()
			for k, v := range tc.change {
				s[k] = v
			}
			got := KeyLogExposure(s)
			switch {
			case tc.want == "" && len(got) != 0:
				t.Fatalf("exposure %v, want none", got)
			case tc.want != "" && (len(got) != 1 || !strings.Contains(got[0], tc.want)):
				t.Fatalf("exposure %v, want one naming %q", got, tc.want)
			}
		})
	}
	if got := KeyLogExposure(map[string]string{"log_statement": "all", "log_min_duration_statement": "0"}); len(got) != 2 {
		t.Fatalf("two applying rules reported %v", got)
	}
}
