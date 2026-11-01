package hook

import (
	"os"
	"path/filepath"
	"testing"
)

// TestStatusLineFollowsTheVendorHome (S-21, lane w4-homes-b): the
// status-line writers resolve their file through the tool's catalogued
// artifact, so CodeBuddy's CODEBUDDY_CONFIG_DIR moves the write, VT Code's
// VTCODE_CONFIG moves it, and Kimchi's forced harness dir stays put whatever
// KIMCHI_CODING_AGENT_DIR says. Red on the old writers, which joined the
// spec's home-relative file onto the home.
func TestStatusLineFollowsTheVendorHome(t *testing.T) {
	for _, tc := range []struct {
		tool string
		env  func(home string) map[string]string
		want func(home string) string
	}{
		{
			"codebuddy",
			func(home string) map[string]string {
				return map[string]string{"CODEBUDDY_CONFIG_DIR": filepath.Join(home, "cb")}
			},
			func(home string) string { return filepath.Join(home, "cb", "settings.json") },
		},
		{
			"vtcode",
			func(home string) map[string]string {
				return map[string]string{"VTCODE_CONFIG": filepath.Join(home, "vt")}
			},
			func(home string) string { return filepath.Join(home, "vt", "vtcode.toml") },
		},
		{
			"kimchi",
			func(home string) map[string]string {
				return map[string]string{"KIMCHI_CODING_AGENT_DIR": filepath.Join(home, "elsewhere")}
			},
			func(home string) string { return filepath.Join(home, ".config", "kimchi", "harness", "settings.json") },
		},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			home := t.TempDir()
			env := tc.env(home)
			want := tc.want(home)
			// The writer needs the tool's own directory (an installed tool).
			if err := os.MkdirAll(filepath.Dir(want), 0o755); err != nil {
				t.Fatal(err)
			}
			r := newStatusLineRegistry(t, home, func(o *Options) { o.Getenv = func(k string) string { return env[k] } })
			res := r.RegisterStatusLine(tc.tool)
			if res.Error != nil || res.Skipped {
				t.Fatalf("RegisterStatusLine = %+v", res)
			}
			if res.ConfigPath != want {
				t.Errorf("ConfigPath = %q, want %q", res.ConfigPath, want)
			}
			if _, err := os.Stat(want); err != nil {
				t.Errorf("status line not written at %s: %v", want, err)
			}
		})
	}
}

// TestStatusLineRefusesARelativeHome: a relative CODEBUDDY_CONFIG_DIR names a
// file Observer cannot see, so nothing is written (FU-31).
func TestStatusLineRefusesARelativeHome(t *testing.T) {
	home := t.TempDir()
	r := newStatusLineRegistry(t, home, func(o *Options) {
		o.Getenv = func(k string) string {
			if k == "CODEBUDDY_CONFIG_DIR" {
				return "rel"
			}
			return ""
		}
	})
	res := r.RegisterStatusLine("codebuddy")
	if res.Error == nil && !res.Skipped {
		t.Fatalf("RegisterStatusLine = %+v, want a skip or an error", res)
	}
	if _, err := os.Stat(filepath.Join(home, ".codebuddy")); !os.IsNotExist(err) {
		t.Errorf("the default home was written (err %v)", err)
	}
}
