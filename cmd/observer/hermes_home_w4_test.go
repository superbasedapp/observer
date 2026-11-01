package main

import (
	"path/filepath"
	"testing"
)

// TestHermesDefaultHomeCarriesTheSuffix: HERMES_DATA_DIR_SUFFIX is appended
// to the platform default directory name only, never to an explicit
// HERMES_HOME (hermes_constants._platform_default_hermes_home; S-17). Red
// before the suffix was read.
func TestHermesDefaultHomeCarriesTheSuffix(t *testing.T) {
	home := t.TempDir()
	explicit := filepath.Join(t.TempDir(), "hh")
	for _, tc := range []struct {
		name string
		in   hermesHomeInputs
		want string
	}{
		{"posix default", hermesHomeInputs{userHome: home, suffix: "-dev"}, filepath.Join(home, ".hermes-dev")},
		{"windows default", hermesHomeInputs{userHome: home, windows: true, suffix: "-dev"}, filepath.Join(home, "AppData", "Local", "hermes-dev")},
		{"no suffix", hermesHomeInputs{userHome: home}, filepath.Join(home, ".hermes")},
		{"explicit HERMES_HOME ignores the suffix", hermesHomeInputs{userHome: home, env: explicit, suffix: "-dev"}, explicit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hermesResolveHome(tc.in); got != tc.want {
				t.Errorf("hermesResolveHome = %q, want %q", got, tc.want)
			}
		})
	}
}
