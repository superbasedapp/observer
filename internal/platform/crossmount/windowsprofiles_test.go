package crossmount

import (
	"errors"
	"path/filepath"
	"testing"
)

// errNoHome stands in for an unresolvable native home, so these tests
// exercise extraHomes in isolation.
var errNoHome = errors.New("no native home")

// usersRoot is the literal wslWindowsHomes enumerates. Children are
// composed with filepath.Join, exactly as the production code does, so
// these tests run unchanged on a Windows host (where Join yields
// backslashes) as well as on Linux.
const usersRoot = "/mnt/c/Users"

// profilePath is the staged path of one entry under usersRoot.
func profilePath(name string) string { return filepath.Join(usersRoot, name) }

// newProfileFS stages a usersRoot listing where every named entry is a
// directory, plus whatever markers the caller wants underneath.
func newProfileFS(names []string, dirs, files []string) *fakeFS {
	fs := &fakeFS{
		dirs:     map[string]bool{usersRoot: true},
		files:    map[string]bool{},
		listings: map[string][]string{usersRoot: names},
	}
	for _, n := range names {
		fs.dirs[profilePath(n)] = true
	}
	for _, d := range dirs {
		fs.dirs[d] = true
	}
	for _, f := range files {
		fs.files[f] = true
	}
	return fs
}

func profileDetector(fs *fakeFS, env string) *detector {
	return &detector{
		runtimeOS:  OSLinux,
		nativeHome: func() (string, error) { return "", errNoHome },
		statDir:    fs.statDir,
		readDir:    fs.readDir,
		exists:     fs.exists,
		getenv:     func(name string) string { return env },
	}
}

// TestWindowsProfileFilter is the table for ticket "Crossmount root
// hygiene 2026-09-03": which entries under C:\Users become candidate
// homes and which are dropped. Every row states the shape on disk and
// the expected verdict, so a future row is one line rather than a new
// test function.
func TestWindowsProfileFilter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// entry is the directory name under /mnt/c/Users.
		entry string
		// hive stages an NTUSER.DAT file under it.
		hive bool
		// hiveLower stages a lower-case ntuser.dat instead, for a
		// case-sensitive mount.
		hiveLower bool
		// appData stages an AppData directory under it.
		appData bool
		want    bool
		why     string
	}{
		// --- real profiles ---
		{
			name: "user with hive and appdata", entry: "auzy_",
			hive: true, appData: true, want: true,
			why: "the ordinary signed-in profile",
		},
		{
			name: "user with hive only", entry: "auzy_",
			hive: true, want: true,
			why: "provisioned but never signed in — still a real account",
		},
		{
			name: "user with appdata only", entry: "dev2",
			appData: true, want: true,
			why: "the marker that actually matters for watch roots",
		},
		{
			name: "user with lower-case hive", entry: "dev3",
			hiveLower: true, want: true,
			why: "a case-sensitive mount spells the hive differently",
		},
		{
			name: "service account that is signed in", entry: "svc-build",
			hive: true, appData: true, want: true,
			why: "an unusual NAME is not disqualifying — only the markers are",
		},

		// --- well-known non-user entries, dropped BY NAME ---
		{
			name: "Default template", entry: "Default",
			hive: true, appData: true, want: false,
			why: "profile template: carries both markers, still not a user",
		},
		{
			name: "Default User junction", entry: "Default User",
			hive: true, appData: true, want: false,
			why: "junction onto Default; same reasoning",
		},
		{
			name: "lower-case default", entry: "default",
			hive: true, appData: true, want: false,
			why: "the name table is case-folded",
		},
		{
			name: "Public shared tree", entry: "Public",
			appData: true, want: false,
			why: "shared documents, never a home",
		},
		{
			name: "All Users junction", entry: "All Users",
			hive: true, appData: true, want: false,
			why: "junction onto ProgramData",
		},
		{
			name: "OOBE leftover", entry: "defaultuser0",
			hive: true, appData: true, want: false,
			why: "transient out-of-box-experience account",
		},
		{
			name: "Application Guard account", entry: "WDAGUtilityAccount",
			hive: true, appData: true, want: false,
			why: "built-in Defender container account",
		},
		{
			name: "Windows Subsystem installer account", entry: "WsiAccount",
			hive: true, appData: true, want: false,
			why: "service profile the WSL daemon fanned roots across on 2026-09-03",
		},

		// --- dropped by the MARKER gate ---
		{
			name: "bare directory", entry: "CodexSandbox",
			want: false,
			why:  "no hive, no AppData: never held a session store",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			base := profilePath(tc.entry)
			var dirs, files []string
			if tc.hive {
				files = append(files, filepath.Join(base, "NTUSER.DAT"))
			}
			if tc.hiveLower {
				files = append(files, filepath.Join(base, "ntuser.dat"))
			}
			if tc.appData {
				dirs = append(dirs, filepath.Join(base, "AppData"))
			}
			fs := newProfileFS([]string{tc.entry}, dirs, files)
			got := profileDetector(fs, "").extraHomes()
			if (len(got) == 1) != tc.want {
				t.Fatalf("%s (%s): got %d homes, want kept=%v (%+v)",
					tc.entry, tc.why, len(got), tc.want, got)
			}
			if tc.want && got[0].Path != base {
				t.Errorf("path: got %q want %q", got[0].Path, base)
			}
		})
	}
}

// TestWindowsProfileFilterDedupesCaseInsensitiveAliases pins the third
// gate: one profile spelled two ways must not fan out into two full
// sets of watch roots.
func TestWindowsProfileFilterDedupesCaseInsensitiveAliases(t *testing.T) {
	t.Parallel()
	fs := newProfileFS(
		[]string{"Auzy", "auzy", "AUZY"},
		[]string{
			filepath.Join(profilePath("Auzy"), "AppData"),
			filepath.Join(profilePath("auzy"), "AppData"),
			filepath.Join(profilePath("AUZY"), "AppData"),
		},
		nil,
	)
	got := profileDetector(fs, "").extraHomes()
	if len(got) != 1 {
		t.Fatalf("len: got %d want 1: %+v", len(got), got)
	}
	if got[0].Path != profilePath("Auzy") {
		t.Errorf("first spelling must win: got %q want %q", got[0].Path, profilePath("Auzy"))
	}
}

// TestWindowsProfileFilterEscapeHatch pins the documented override: with
// EnvAllWindowsProfiles truthy, every directory enumerates again —
// templates, service accounts and marker-less directories alike.
func TestWindowsProfileFilterEscapeHatch(t *testing.T) {
	t.Parallel()
	names := []string{"auzy_", "Default", "Public", "CodexSandbox"}
	fs := newProfileFS(names, []string{filepath.Join(profilePath("auzy_"), "AppData")}, nil)

	if got := profileDetector(fs, "").extraHomes(); len(got) != 1 {
		t.Fatalf("filtered: got %d want 1: %+v", len(got), got)
	}
	for _, truthy := range []string{"1", "true", "YES", " on "} {
		got := profileDetector(fs, truthy).extraHomes()
		if len(got) != len(names) {
			t.Errorf("%s=%q: got %d homes want %d: %+v",
				EnvAllWindowsProfiles, truthy, len(got), len(names), got)
		}
	}
	for _, falsy := range []string{"", "0", "false", "no", "maybe"} {
		if got := profileDetector(fs, falsy).extraHomes(); len(got) != 1 {
			t.Errorf("%s=%q must NOT disable the filter: got %d homes",
				EnvAllWindowsProfiles, falsy, len(got))
		}
	}
}
