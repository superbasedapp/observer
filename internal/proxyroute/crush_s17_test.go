package proxyroute

import (
	"path/filepath"
	"testing"
)

// TestResolveCrushConfigPathFollowsCrushGlobalConfig pins S-17: Crush's
// GlobalConfig() reads CRUSH_GLOBAL_CONFIG as a DIRECTORY holding crush.json,
// then XDG_CONFIG_HOME/crush, then ~/.config/crush (the same chain on every
// OS), and never reads CRUSH_CONFIG. The old resolver took CRUSH_CONFIG as a
// file path and ignored CRUSH_GLOBAL_CONFIG. The resolver takes no GOOS (the
// vendor chain has no per-OS branch), and every row sets all three
// variables, so the table holds on any host.
func TestResolveCrushConfigPathFollowsCrushGlobalConfig(t *testing.T) {
	home := t.TempDir()
	global := filepath.Join(home, "global-cfg")
	xdg := filepath.Join(home, "xdg")
	stray := filepath.Join(home, "stray", "crush.json")
	def := filepath.Join(home, ".config", "crush", "crush.json")
	cases := []struct {
		name                     string
		globalCfg, xdgCfg, crCfg string
		want                     string
	}{
		{"nothing set", "", "", "", def},
		{"CRUSH_GLOBAL_CONFIG is a directory", global, "", "", filepath.Join(global, "crush.json")},
		{"CRUSH_GLOBAL_CONFIG beats XDG_CONFIG_HOME", global, xdg, "", filepath.Join(global, "crush.json")},
		{"XDG_CONFIG_HOME", "", xdg, "", filepath.Join(xdg, "crush", "crush.json")},
		{"CRUSH_CONFIG is not a Crush variable", "", "", stray, def},
		{"CRUSH_CONFIG does not beat CRUSH_GLOBAL_CONFIG", global, "", stray, filepath.Join(global, "crush.json")},
		{"blank CRUSH_GLOBAL_CONFIG is unset", "  ", xdg, "", filepath.Join(xdg, "crush", "crush.json")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{"CRUSH_GLOBAL_CONFIG": tc.globalCfg, "XDG_CONFIG_HOME": tc.xdgCfg, "CRUSH_CONFIG": tc.crCfg}
			if got, err := resolveCrushConfigPath(home, func(k string) string { return env[k] }); err != nil || got != tc.want {
				t.Fatalf("resolveCrushConfigPath = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}
