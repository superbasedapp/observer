package config

import (
	"strings"
	"testing"
)

// TestValidateSecurityDepsLookup: the package lookup keys (lane RM-2) take
// their pickers only, and the reserved values (remote_via = "service", the
// "os" kind) are refused with a fixed "not in this build" message.
func TestValidateSecurityDepsLookup(t *testing.T) {
	base := Default().Security.Deps
	if base.Match != "" || base.RemoteVia != "shards" || base.RemotePrivate != "withhold" || len(base.RemoteKinds) != 0 {
		t.Fatalf("defaults: %+v", base)
	}
	for _, tc := range []struct {
		name string
		mut  func(*SecurityDepsConfig)
		want string
	}{
		{"default", func(*SecurityDepsConfig) {}, ""},
		{"local", func(d *SecurityDepsConfig) { d.Match = "local" }, ""},
		{"remote", func(d *SecurityDepsConfig) { d.Match = "remote" }, ""},
		{"both", func(d *SecurityDepsConfig) { d.Match = "both" }, ""},
		{"bad mode", func(d *SecurityDepsConfig) { d.Match = "cloud" }, "security.deps.match"},
		{"service reserved", func(d *SecurityDepsConfig) { d.RemoteVia = "service" }, "not in this build"},
		{"bad via", func(d *SecurityDepsConfig) { d.RemoteVia = "api" }, "security.deps.remote_via"},
		{"kinds", func(d *SecurityDepsConfig) { d.RemoteKinds = []string{"language", "actions"} }, ""},
		{"os reserved", func(d *SecurityDepsConfig) { d.RemoteKinds = []string{"os"} }, "not in this build"},
		{"bad kind", func(d *SecurityDepsConfig) { d.RemoteKinds = []string{"code"} }, "security.deps.remote_kinds"},
		{"send", func(d *SecurityDepsConfig) { d.RemotePrivate = "send" }, ""},
		{"bad private", func(d *SecurityDepsConfig) { d.RemotePrivate = "yes" }, "security.deps.remote_private"},
	} {
		d := base
		tc.mut(&d)
		err := validateSecurityDeps(d)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: err %v, want %q", tc.name, err, tc.want)
		}
	}
}
