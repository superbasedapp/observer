package config

import "testing"

// TestSecurityOpengrepTaintPassKeys: the intrafile taint pass keys of
// [security.scan.opengrep] default to auto with every number at 0 (its
// default), and a value off the documented range does not validate.
func TestSecurityOpengrepTaintPassKeys(t *testing.T) {
	t.Parallel()
	d := DefaultSecurityConfig().Scan.Opengrep
	if d.TaintPass != "auto" || d.TaintPassBudgetSeconds != 0 || d.TaintPassJobs != 0 || d.TaintPassMemoryMiB != 0 {
		t.Fatalf("defaults %+v", d)
	}
	if err := validateSecurityOpengrep(d); err != nil {
		t.Fatalf("defaults refused: %v", err)
	}
	cases := []struct {
		name string
		mut  func(*SecurityOpengrepConfig)
		ok   bool
	}{
		{"empty reads as auto", func(c *SecurityOpengrepConfig) { c.TaintPass = "" }, true},
		{"off", func(c *SecurityOpengrepConfig) { c.TaintPass = "off" }, true},
		{"an unknown mode", func(c *SecurityOpengrepConfig) { c.TaintPass = "on" }, false},
		{"a budget in range", func(c *SecurityOpengrepConfig) { c.TaintPassBudgetSeconds = 600 }, true},
		{"a budget under 30 s", func(c *SecurityOpengrepConfig) { c.TaintPassBudgetSeconds = 10 }, false},
		{"a budget over an hour", func(c *SecurityOpengrepConfig) { c.TaintPassBudgetSeconds = 3601 }, false},
		{"jobs in range", func(c *SecurityOpengrepConfig) { c.TaintPassJobs = 8 }, true},
		{"too many jobs", func(c *SecurityOpengrepConfig) { c.TaintPassJobs = 9 }, false},
		{"negative jobs", func(c *SecurityOpengrepConfig) { c.TaintPassJobs = -1 }, false},
		{"memory in range", func(c *SecurityOpengrepConfig) { c.TaintPassMemoryMiB = 4096 }, true},
		{"memory under the floor", func(c *SecurityOpengrepConfig) { c.TaintPassMemoryMiB = 100 }, false},
		{"memory over the ceiling", func(c *SecurityOpengrepConfig) { c.TaintPassMemoryMiB = 9000 }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := d
			c.mut(&cfg)
			if err := validateSecurityOpengrep(cfg); (err == nil) != c.ok {
				t.Fatalf("validate = %v, want ok %v", err, c.ok)
			}
		})
	}
}
