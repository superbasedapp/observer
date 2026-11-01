package protectedhome

import (
	"path/filepath"
	"testing"
)

func TestSkipChildTable(t *testing.T) {
	home := filepath.Join(string(filepath.Separator), "Users", "u")
	known := filepath.Join(home, "Documents", "proj")
	cases := []struct {
		name string
		goos string
		dir  string
		keep []string
		want bool
	}{
		{"darwin Desktop", "darwin", "Desktop", nil, true},
		{"darwin Documents", "darwin", "Documents", nil, true},
		{"darwin Downloads", "darwin", "Downloads", nil, true},
		{"darwin Library", "darwin", "Library", nil, true},
		{"darwin Movies", "darwin", "Movies", nil, true},
		{"darwin Music", "darwin", "Music", nil, true},
		{"darwin Pictures", "darwin", "Pictures", nil, true},
		{"darwin Mobile Documents", "darwin", "Mobile Documents", nil, true},
		{"darwin case-insensitive", "darwin", "desktop", nil, true},
		{"darwin ordinary folder", "darwin", "code", nil, false},
		{"darwin known root under Documents keeps it", "darwin", "Documents", []string{known}, false},
		{"darwin known root elsewhere does not keep Desktop", "darwin", "Desktop", []string{known}, true},
		{"darwin a sibling prefix is not under", "darwin", "Doc", []string{known}, false},
		{"darwin known root equal to the folder", "darwin", "Downloads", []string{filepath.Join(home, "Downloads")}, false},
		{"linux has no protected folders", "linux", "Desktop", nil, false},
		{"windows has no protected folders", "windows", "Documents", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SkipChild(tc.goos, home, tc.dir, tc.keep); got != tc.want {
				t.Errorf("SkipChild(%q, %q) = %v, want %v", tc.goos, tc.dir, got, tc.want)
			}
		})
	}
}

func TestNamesIsACopy(t *testing.T) {
	n := Names("darwin")
	if len(n) == 0 {
		t.Fatal("darwin has protected folders")
	}
	n[0] = "changed"
	if Names("darwin")[0] == "changed" {
		t.Error("Names must return a copy")
	}
	if Names("linux") != nil {
		t.Error("linux has none")
	}
}
