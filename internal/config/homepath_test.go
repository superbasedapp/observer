package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadRefusesWithNoHome (R-183): with HOME and USERPROFILE unset (the
// variables os.UserHomeDir reads on Unix and Windows), a default config,
// whose paths start with "~", is refused with the named home_unresolved
// reason instead of being used as a relative "~" folder, and nothing is
// created in the working directory. Runs on every OS.
func TestLoadRefusesWithNoHome(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	t.Setenv("home", "") // plan9
	if _, err := os.UserHomeDir(); err == nil {
		t.Skip("this platform resolves a home without HOME or USERPROFILE")
	}
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(LoadOptions{GlobalPath: cfgPath, Env: func(string) string { return "" }})
	if !errors.Is(err, ErrHomeUnresolved) || !strings.Contains(err.Error(), "home_unresolved") || !strings.Contains(err.Error(), "observer.db_path") {
		t.Fatalf("Load with no home: %v, want the home_unresolved refusal naming observer.db_path", err)
	}
	if _, err := os.Stat("~"); !os.IsNotExist(err) {
		t.Fatalf("a folder named ~ exists in the working directory: %v", err)
	}
}

// TestExpandHomeWith pins the home-relative spellings on both separators.
func TestExpandHomeWith(t *testing.T) {
	home := func() (string, error) { return "/h", nil }
	none := func() (string, error) { return "", errors.New("no home") }
	for _, tc := range []struct {
		p       string
		sep     byte
		home    func() (string, error)
		want    string
		wantErr bool
	}{
		{"~/.observer/x", '/', home, filepath.Join("/h", ".observer/x"), false},
		{"~", '/', home, "/h", false},
		{`~\.observer\x`, '\\', home, filepath.Join("/h", `.observer\x`), false},
		{`~\.observer`, '/', home, `~\.observer`, false}, // a backslash is a name character on POSIX
		{"~user/x", '/', home, "~user/x", false},
		{"/abs/x", '/', none, "/abs/x", false},
		{"rel/x", '/', none, "rel/x", false},
		{"~/.observer/x", '/', none, "", true},
		{`~\.observer`, '\\', none, "", true},
		{"~", '/', none, "", true},
	} {
		got, err := expandHomeWith(tc.p, tc.sep, tc.home)
		if (err != nil) != tc.wantErr || (err != nil && !errors.Is(err, ErrHomeUnresolved)) || got != tc.want {
			t.Errorf("expandHomeWith(%q, %q) = %q, %v; want %q (error %v)", tc.p, tc.sep, got, err, tc.want, tc.wantErr)
		}
	}
}
