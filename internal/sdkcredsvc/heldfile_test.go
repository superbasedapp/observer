package sdkcredsvc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSDKHeldFilePathLadder is plan 3.4's path table, one case per rung per
// OS.
func TestSDKHeldFilePathLadder(t *testing.T) {
	t.Parallel()
	env := func(kv ...string) func(string) string {
		m := map[string]string{}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return func(k string) string { return m[k] }
	}
	cases := []struct {
		name, goos   string
		getenv       func(string) string
		home         string
		want, source string
	}{
		{"env replaces the path on linux", "linux", env(SDKHeldFileEnv, "/srv/app/key", "XDG_CONFIG_HOME", "/x"), "/home/u", "/srv/app/key", HeldFileSourceEnv},
		{"env replaces the path on windows", "windows", env(SDKHeldFileEnv, `D:\keys\k`, "LOCALAPPDATA", `C:\Users\u\AppData\Local`), `C:\Users\u`, `D:\keys\k`, HeldFileSourceEnv},
		{"blank env is not set", "linux", env(SDKHeldFileEnv, "  "), "/home/u", "/home/u/.config/superbased/sdk-credential", HeldFileSourceHomeConfig},
		{"xdg config home on linux", "linux", env("XDG_CONFIG_HOME", "/home/u/cfg/"), "/home/u", "/home/u/cfg/superbased/sdk-credential", HeldFileSourceXDG},
		{"xdg config home on macos", "darwin", env("XDG_CONFIG_HOME", "/Users/u/.cfg"), "/Users/u", "/Users/u/.cfg/superbased/sdk-credential", HeldFileSourceXDG},
		{"relative xdg config home is ignored", "linux", env("XDG_CONFIG_HOME", "cfg"), "/home/u", "/home/u/.config/superbased/sdk-credential", HeldFileSourceHomeConfig},
		{"home config on linux", "linux", env(), "/home/u", "/home/u/.config/superbased/sdk-credential", HeldFileSourceHomeConfig},
		{"home config on macos (not Library)", "darwin", env(), "/Users/u", "/Users/u/.config/superbased/sdk-credential", HeldFileSourceHomeConfig},
		{"localappdata on windows", "windows", env("LOCALAPPDATA", `C:\Users\u\AppData\Local\`), `C:\Users\u`, `C:\Users\u\AppData\Local\superbased\sdk-credential`, HeldFileSourceLocalAppData},
		{"localappdata is windows only", "linux", env("LOCALAPPDATA", `C:\x`), "/home/u", "/home/u/.config/superbased/sdk-credential", HeldFileSourceHomeConfig},
		{"xdg is not read on windows", "windows", env("XDG_CONFIG_HOME", "/x"), `C:\Users\u`, "", ""},
		{"no home", "linux", env(), "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, src := SDKHeldFilePath(tc.goos, tc.getenv, tc.home)
			if got != tc.want || src != tc.source {
				t.Fatalf("path = %q (%s), want %q (%s)", got, src, tc.want, tc.source)
			}
		})
	}
}

// TestSDKHeldFilePathFollowsTheContract runs credential-file-cases.json's
// path_cases (destination.md section 6a, lane L0) through SDKHeldFilePath,
// so Observer names the same file every SDK reads.
func TestSDKHeldFilePathFollowsTheContract(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "..", "sdk", "contract", "credential-file-cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		PathCases []struct {
			Name string            `json:"name"`
			OS   string            `json:"os"`
			Env  map[string]string `json:"env"`
			Home string            `json:"home"`
			Want struct {
				Path *string `json:"path"`
			} `json:"want"`
		} `json:"path_cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.PathCases) == 0 {
		t.Fatal("no path_cases in the contract")
	}
	for _, c := range doc.PathCases {
		got, _ := SDKHeldFilePath(c.OS, func(k string) string { return c.Env[k] }, c.Home)
		want := ""
		if c.Want.Path != nil {
			want = *c.Want.Path
		}
		if got != want {
			t.Errorf("%s: path %q, want %q", c.Name, got, want)
		}
	}
}

// TestHeldFileOutsideLocalAppData is section 6a's Windows read rule 3.
func TestHeldFileOutsideLocalAppData(t *testing.T) {
	t.Parallel()
	const lad = `C:\Users\me\AppData\Local`
	cases := []struct {
		name, goos, path, lad string
		want                  bool
	}{
		{"the default path", "windows", lad + `\superbased\sdk-credential`, lad, false},
		{"case-insensitive, forward slashes", "windows", `c:/users/ME/appdata/local/superbased/acme`, lad + `\`, false},
		{"another folder", "windows", `D:\keys\acme`, lad, true},
		{"a sibling with the same prefix", "windows", `C:\Users\me\AppData\LocalLow\k`, lad, true},
		{"climbs out", "windows", lad + `\..\Roaming\k`, lad, true},
		{"no LOCALAPPDATA", "windows", lad + `\superbased\sdk-credential`, "", true},
		{"not windows", "linux", "/srv/keys/acme", "", false},
	}
	for _, c := range cases {
		if got := HeldFileOutsideLocalAppData(c.goos, c.path, c.lad); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// TestDescribeHeldFileRows is one case per heldFileStateRows row, the
// refusal reasons in credential-file-cases.json's vocabulary.
func TestDescribeHeldFileRows(t *testing.T) {
	t.Parallel()
	const p = "/home/u/.config/superbased/sdk-credential"
	ok := HeldFileFacts{Exists: true, Regular: true, Size: 120}
	with := func(f func(*HeldFileFacts)) HeldFileFacts { x := ok; f(&x); return x }
	cases := []struct {
		name       string
		goos       string
		path       string
		facts      HeldFileFacts
		machineKey bool
		state      string
		reason     string
		text       string
	}{
		{"no path", "linux", "", ok, false, HeldFileNoPath, "", "names no place"},
		{"stat failed", "linux", p, HeldFileFacts{StatErr: "permission denied"}, false, HeldFileUnchecked, "", "permission denied"},
		{"absent", "linux", p, HeldFileFacts{}, true, HeldFileAbsent, "", "none"},
		{"windows reparse point", "windows", `C:\x`, with(func(f *HeldFileFacts) { f.Link = true }), false, HeldFileRefused, "reparse_point", "reparse point"},
		{"symlink", "linux", p, with(func(f *HeldFileFacts) { f.Link = true }), false, HeldFileRefused, "symlink", "symbolic link"},
		{"not regular", "linux", p, with(func(f *HeldFileFacts) { f.Regular = false }), false, HeldFileRefused, "not_regular", "not a regular file"},
		{"outside LOCALAPPDATA", "windows", `D:\k`, with(func(f *HeldFileFacts) { f.OutsideLocalAppData = true }), false, HeldFileRefused, "outside_localappdata", "LOCALAPPDATA"},
		{"open to others", "linux", p, with(func(f *HeldFileFacts) { f.OpenToOthers = true }), false, HeldFileRefused, "mode", "chmod 600"},
		{"another user's", "linux", p, with(func(f *HeldFileFacts) { f.ForeignOwner = true }), false, HeldFileRefused, "owner", "another user"},
		{"too large", "linux", p, with(func(f *HeldFileFacts) { f.Size = HeldFileMaxBytes + 1 }), false, HeldFileRefused, "too_large", "4096"},
		{"empty", "linux", p, with(func(f *HeldFileFacts) { f.Size = 0 }), false, HeldFileRefused, "empty", "empty"},
		{"machine key wins", "linux", p, ok, true, HeldFileUnused, "", "present but unused"},
		{"present", "darwin", p, ok, false, HeldFilePresent, "", "present"},
		{"refused beats unused", "linux", p, with(func(f *HeldFileFacts) { f.Link = true }), true, HeldFileRefused, "symlink", "symbolic link"},
		{"exactly the limit", "linux", p, with(func(f *HeldFileFacts) { f.Size = HeldFileMaxBytes }), false, HeldFilePresent, "", "present"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := DescribeHeldFile(tc.goos, tc.path, HeldFileSourceHomeConfig, tc.facts, tc.machineKey)
			if got.State != tc.state || got.Reason != tc.reason || !strings.Contains(got.Text, tc.text) || got.Path != tc.path {
				t.Fatalf("got %+v, want state %s reason %q with %q", got, tc.state, tc.reason, tc.text)
			}
		})
	}
}

// TestHeldFileReasonsAreTheContractVocabulary: every refusal reason the
// table can give is one the SDKs' reader cases name.
func TestHeldFileReasonsAreTheContractVocabulary(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "..", "sdk", "contract", "credential-file-cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Reasons []string `json:"reasons"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, r := range doc.Reasons {
		known[r] = true
	}
	for _, r := range heldFileStateRows {
		if (r.state == HeldFileRefused) != (r.reason != "") {
			t.Errorf("row %s/%q: a refusal carries a reason, nothing else does", r.state, r.reason)
		}
		if r.reason != "" && !known[r.reason] {
			t.Errorf("reason %q is not in credential-file-cases.json reasons", r.reason)
		}
	}
}
