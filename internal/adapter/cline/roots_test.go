package cline

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestToolFromPathTable pins the extension-id table BOTH directions:
// all five Roo ids resolve to roo-code (audit IDE-23 — only one of the
// five was recognised before), Cline's own id resolves to cline, and an
// id-less path defaults to cline.
func TestToolFromPathTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path string
		want string
	}{
		{"/x/saoudrizwan.claude-dev/tasks/abc/api_conversation_history.json", models.ToolCline},
		{"/x/roovscode.roo-cline/tasks/abc/api_conversation_history.json", models.ToolRooCode},
		{"/x/roovscode.roo-code/tasks/abc/api_conversation_history.json", models.ToolRooCode},
		{"/x/rooveterinaryinc.roo-cline/tasks/abc/api_conversation_history.json", models.ToolRooCode},
		{"/x/rooveterinaryinc.roo-code/tasks/abc/api_conversation_history.json", models.ToolRooCode},
		{"/x/rooveterinaryinc.roo-code-nightly/tasks/abc/api_conversation_history.json", models.ToolRooCode},
		// Case-insensitive: Windows paths arrive in whatever case the
		// filesystem reports.
		{`C:\X\RooVeterinaryInc.Roo-Code\tasks\abc\api_conversation_history.json`, models.ToolRooCode},
		// Cline Nightly (audit 2026-09-03, ticket U1): a separate
		// Marketplace listing, same legacy layout — retags to Cline.
		{"/x/saoudrizwan.cline-nightly/tasks/abc/api_conversation_history.json", models.ToolCline},
		// ZooCode (2026-09-03, ticket U1): the community continuation
		// of Roo Code, published on the Marketplace as
		// ZooCodeOrganization.zoo-code but lowercased on disk like
		// every other globalStorage directory (VS Code convention).
		{"/x/zoocodeorganization.zoo-code/tasks/abc/api_conversation_history.json", models.ToolZooCode},
		// Mixed-case ZooCode path: toolFromPath lower-cases BOTH sides
		// of the comparison, so a filesystem that reports a different
		// case than the (already-lowercase) table entry still resolves
		// — this is the Windows-mount case-insensitivity guarantee,
		// not a claim about the table's own spelling.
		{`C:\X\ZOOCODEORGANIZATION.ZOO-CODE\tasks\abc\api_conversation_history.json`, models.ToolZooCode},
		// A relocated store carries no id — documented default.
		{"/x/other/tasks/abc/api_conversation_history.json", models.ToolCline},
	}
	for _, tc := range cases {
		if got := toolFromPath(tc.path); got != tc.want {
			t.Errorf("toolFromPath(%q) = %q want %q", tc.path, got, tc.want)
		}
	}
}

// TestClineExtensionsCoversEveryRooID pins that the table stays the ONE
// owner: every id it declares maps to a real tool constant, and the
// five Roo ids are all present — plus, since 2026-09-03 (ticket U1),
// Cline Nightly's own separate-listing id and ZooCode's (the Roo
// community continuation).
func TestClineExtensionsCoversEveryRooID(t *testing.T) {
	t.Parallel()
	want := map[string]bool{
		"roovscode.roo-cline":               false,
		"roovscode.roo-code":                false,
		"rooveterinaryinc.roo-cline":        false,
		"rooveterinaryinc.roo-code":         false,
		"rooveterinaryinc.roo-code-nightly": false,
		"saoudrizwan.claude-dev":            false,
		"saoudrizwan.cline-nightly":         false,
		"zoocodeorganization.zoo-code":      false,
	}
	for _, ext := range clineExtensions {
		if _, ok := want[ext.id]; !ok {
			t.Errorf("unexpected extension id %q in the table", ext.id)
			continue
		}
		want[ext.id] = true
		if ext.tool != models.ToolCline && ext.tool != models.ToolRooCode && ext.tool != models.ToolZooCode {
			t.Errorf("extension %q maps to unexpected tool %q", ext.id, ext.tool)
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("extension id %q missing from clineExtensions", id)
		}
	}
}

// TestRooCustomStoragePath pins the settings.json read, including the
// JSONC liberties VS Code takes (line + block comments, trailing
// commas), the `~`-against-THIS-home expansion, the drop of a value
// that is not absolute, the cross-mount translation of a foreign-OS
// path, and every silent-failure mode.
//
// wantPosix, when set, is the expectation on a non-Windows runner:
// crossmount.TranslateForeignPath rewrites `D:\x` to `/mnt/d/x` there
// and leaves it alone on Windows.
func TestRooCustomStoragePath(t *testing.T) {
	t.Parallel()
	const posixHome = "/home/u"
	cases := []struct {
		name      string
		write     bool
		body      string
		home      string
		want      string
		wantPosix string
	}{
		{name: "missing_file", write: false, home: posixHome, want: ""},
		{
			// A Windows-side settings.json read from a WSL daemon: the
			// value is absolute in Windows terms and must be
			// translated before it can be watched.
			name:      "windows_path_translated",
			write:     true,
			body:      `{"roo-cline.customStoragePath":"D:\\roo-store"}`,
			home:      `C:\Users\u`,
			want:      `D:\roo-store`,
			wantPosix: "/mnt/d/roo-store",
		},
		{
			name:      "tilde_expands_against_this_home",
			write:     true,
			body:      `{"roo-cline.customStoragePath":"~/roo-store"}`,
			home:      posixHome,
			want:      posixHome + "/roo-store",
			wantPosix: posixHome + "/roo-store",
		},
		{
			name:      "windows_tilde_expands_against_windows_home",
			write:     true,
			body:      `{"roo-cline.customStoragePath":"~\\roo-store"}`,
			home:      `C:\Users\u`,
			want:      `C:\Users\u\roo-store`,
			wantPosix: "/mnt/c/Users/u/roo-store",
		},
		{
			// Roo resolves a relative value against a working
			// directory we do not know — dropped, never joined to a
			// guessed base.
			name:  "relative_value_dropped",
			write: true,
			body:  `{"roo-cline.customStoragePath":"roo-store"}`,
			home:  posixHome,
			want:  "",
		},
		{
			name:  "dot_relative_value_dropped",
			write: true,
			body:  `{"roo-cline.customStoragePath":"./roo-store"}`,
			home:  posixHome,
			want:  "",
		},
		{
			// No home to anchor `~` against ⇒ drop, never guess.
			name:  "tilde_without_home_dropped",
			write: true,
			body:  `{"roo-cline.customStoragePath":"~/roo-store"}`,
			home:  "",
			want:  "",
		},
		{
			name:  "trailing_comma",
			write: true,
			body:  "{\n  \"roo-cline.customStoragePath\": \"/srv/roo\",\n}",
			home:  posixHome,
			want:  "/srv/roo",
		},
		{
			name:  "line_comments",
			write: true,
			body:  "{\n  // where Roo keeps tasks\n  \"roo-cline.customStoragePath\": \"/srv/roo\"\n}",
			home:  posixHome,
			want:  "/srv/roo",
		},
		{
			name:  "block_comment",
			write: true,
			body:  "{\n  /* relocated\n     store */\n  \"roo-cline.customStoragePath\": \"/srv/roo\"\n}",
			home:  posixHome,
			want:  "/srv/roo",
		},
		{
			// A `//` inside a STRING must survive — a URL-ish or
			// UNC-ish value would otherwise be truncated.
			name:  "slashes_inside_string_survive",
			write: true,
			body:  `{"roo-cline.customStoragePath":"//server/share/roo"}`,
			home:  posixHome,
			want:  "//server/share/roo",
		},
		{
			name:  "key_absent",
			write: true,
			body:  `{"editor.fontSize":13}`,
			home:  posixHome,
			want:  "",
		},
		{
			name:  "non_string_value",
			write: true,
			body:  `{"roo-cline.customStoragePath":42}`,
			home:  posixHome,
			want:  "",
		},
		{
			name:  "malformed_json_is_silent",
			write: true,
			body:  `{"roo-cline.customStoragePath":`,
			home:  posixHome,
			want:  "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.write {
				if err := os.WriteFile(filepath.Join(dir, settingsFileName), []byte(tc.body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want := tc.want
			if runtime.GOOS != "windows" && tc.wantPosix != "" {
				want = tc.wantPosix
			}
			if got := rooCustomStoragePath(dir, tc.home); got != want {
				t.Errorf("rooCustomStoragePath = %q want %q", got, want)
			}
		})
	}
	if got := rooCustomStoragePath("", posixHome); got != "" {
		t.Errorf("empty userDir = %q want empty", got)
	}
}

// TestWatchPathsCachedAtConstruction pins the hot-path fix: the root
// set — including the settings.json read per VS Code product — is
// composed ONCE in the constructor. WatchPaths and the IsSessionFile
// it backs run per watcher event, so re-deriving them per call was
// hundreds of microseconds and hundreds of allocations each time.
//
// Deliberately NOT parallel: it swaps the package-level openSettings
// seam.
func TestWatchPathsCachedAtConstruction(t *testing.T) {
	orig := openSettings
	t.Cleanup(func() { openSettings = orig })
	var reads int
	openSettings = func(path string) (io.ReadCloser, error) {
		reads++
		return orig(path)
	}

	a := New()
	atConstruction := reads

	for i := 0; i < 5; i++ {
		_ = a.WatchPaths()
		_ = a.IsSessionFile(filepath.Join("nowhere", "api_conversation_history.json"))
	}
	if reads != atConstruction {
		t.Errorf("settings.json read %d times after construction (want 0; %d during)", reads-atConstruction, atConstruction)
	}
	if n := testing.AllocsPerRun(50, func() { _ = a.WatchPaths() }); n != 0 {
		t.Errorf("WatchPaths allocates %v per call, want 0 (it must hand back the cached slice)", n)
	}
	// The cached set is the same one defaultWatchRoots composes — and
	// composing it DOES go through the seam, which is what makes the
	// assertion above meaningful (a runner with no detected home has
	// no products to read, so that case is vacuous by construction).
	before := reads
	fresh := defaultWatchRoots()
	if len(fresh) > 0 && reads == before {
		t.Error("defaultWatchRoots read no settings.json — the openSettings seam is no longer on the path")
	}
	if got := len(a.WatchPaths()); got != len(fresh) {
		t.Errorf("cached roots = %d want %d", got, len(fresh))
	}
}

// TestWatchPathsIncludesClineNightlyAndZooCode pins the 2026-09-03
// (ticket U1) root additions end-to-end: for a controlled fake home,
// WatchPaths() must emit a root ending in
// saoudrizwan.cline-nightly/tasks (Cline's separate nightly listing)
// and one ending in zoocodeorganization.zoo-code/tasks (the ZooCode
// community continuation of Roo Code) — not just that the ids exist in
// the table (TestClineExtensionsCoversEveryRooID / the generic
// TestDefaultWatchRootsEnumeratesForksAndIDs loop already pin that),
// but that the real root-composition path actually produces the paths
// an operator's watcher would register.
//
// Deliberately NOT parallel: it overrides the process-wide home env
// vars crossmount.AllHomes() reads (HOME for POSIX, USERPROFILE +
// APPDATA for Windows, the latter because vscodehost.UserDir prefers a
// set APPDATA over HOME/USERPROFILE-derived paths for the native
// home). t.Setenv already refuses to run alongside t.Parallel.
func TestWatchPathsIncludesClineNightlyAndZooCode(t *testing.T) {
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	t.Setenv("USERPROFILE", fakeHome)
	t.Setenv("APPDATA", filepath.Join(fakeHome, "AppData", "Roaming"))

	a := New()
	roots := a.WatchPaths()

	var haveNightly, haveZoo bool
	for _, r := range roots {
		slash := filepath.ToSlash(r)
		if strings.HasSuffix(slash, "/saoudrizwan.cline-nightly/tasks") {
			haveNightly = true
		}
		if strings.HasSuffix(slash, "/zoocodeorganization.zoo-code/tasks") {
			haveZoo = true
		}
	}
	if !haveNightly {
		t.Errorf("no saoudrizwan.cline-nightly/tasks root among %d roots: %v", len(roots), roots)
	}
	if !haveZoo {
		t.Errorf("no zoocodeorganization.zoo-code/tasks root among %d roots: %v", len(roots), roots)
	}
}

// TestStripTrailingCommas pins the second JSONC liberty: a trailing
// comma before `}` / `]` is dropped, and a comma inside a string
// literal is not.
func TestStripTrailingCommas(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "no_trailing", in: `{"a":1,"b":2}`, want: `{"a":1,"b":2}`},
		{name: "object", in: `{"a":1,}`, want: `{"a":1}`},
		{name: "array", in: `{"a":[1,2,]}`, want: `{"a":[1,2]}`},
		{name: "newline_before_closer", in: "{\"a\":1,\n}", want: "{\"a\":1\n}"},
		{name: "comma_inside_string", in: `{"a":"x,}"}`, want: `{"a":"x,}"}`},
		{name: "nested", in: `{"a":{"b":1,},}`, want: `{"a":{"b":1}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(stripTrailingCommas([]byte(tc.in))); got != tc.want {
				t.Errorf("stripTrailingCommas(%q) = %q want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestIsAbsoluteAnyOS pins that absoluteness is judged in EVERY OS's
// convention, not just the running one — a settings.json written by
// Windows is read by a Linux daemon and vice versa.
func TestIsAbsoluteAnyOS(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"/srv/roo", true},
		{`D:\roo-store`, true},
		{"D:/roo-store", true},
		{`\\server\share`, true},
		{"//server/share", true},
		{"roo-store", false},
		{"./roo-store", false},
		{"../roo-store", false},
		{"~/roo-store", false},
		{"D:", false},
	}
	for _, tc := range cases {
		if got := isAbsoluteAnyOS(tc.in); got != tc.want {
			t.Errorf("isAbsoluteAnyOS(%q) = %v want %v", tc.in, got, tc.want)
		}
	}
}

// TestDefaultWatchRootsEnumeratesForksAndIDs pins that the root set is
// the CROSS PRODUCT of every VS Code-family product and every
// extension id — the audit IDE-14 + IDE-23 fix. Before, only upstream
// "Code" x 2 ids were watched.
//
// The assertions only fire when crossmount detects at least one home
// (every real install); a sandboxed runner with none returns nil and
// the test passes trivially.
func TestDefaultWatchRootsEnumeratesForksAndIDs(t *testing.T) {
	roots := defaultWatchRoots()
	if len(roots) == 0 {
		t.Skip("no crossmount homes detected on this runner")
	}
	var haveCursor, haveInsiders, haveRemote bool
	ids := map[string]bool{}
	for _, r := range roots {
		slash := filepath.ToSlash(r)
		if !strings.HasSuffix(slash, "/tasks") {
			t.Errorf("root does not end in /tasks: %q", r)
		}
		if strings.Contains(slash, "/Cursor/User/globalStorage/") {
			haveCursor = true
		}
		if strings.Contains(slash, "/Code - Insiders/User/globalStorage/") {
			haveInsiders = true
		}
		if strings.Contains(slash, "/.vscode-server/data/User/globalStorage/") {
			haveRemote = true
		}
		for _, ext := range clineExtensions {
			if strings.Contains(slash, "/"+ext.id+"/") {
				ids[ext.id] = true
			}
		}
	}
	if !haveCursor {
		t.Error("no Cursor globalStorage root (IDE-14: fork hosts must be enumerated)")
	}
	if !haveInsiders {
		t.Error("no Code - Insiders globalStorage root")
	}
	if !haveRemote {
		t.Error("no .vscode-server globalStorage root")
	}
	for _, ext := range clineExtensions {
		if !ids[ext.id] {
			t.Errorf("extension %q has no watch root", ext.id)
		}
	}
}

// TestStripJSONComments is the unit pin for the JSONC pre-pass.
func TestStripJSONComments(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "no_comments", in: `{"a":1}`, want: `{"a":1}`},
		{name: "line_comment", in: "{\"a\":1} // tail", want: "{\"a\":1} "},
		{name: "block_comment", in: `{"a":/* x */1}`, want: `{"a":1}`},
		{name: "comment_marker_in_string", in: `{"a":"x // y"}`, want: `{"a":"x // y"}`},
		{name: "escaped_quote_in_string", in: `{"a":"x\" // y"}`, want: `{"a":"x\" // y"}`},
		{name: "unterminated_block", in: `{"a":1 /* x`, want: `{"a":1 `},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(stripJSONComments([]byte(tc.in))); got != tc.want {
				t.Errorf("stripJSONComments(%q) = %q want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestCustomStoragePathAttributesRelocatedStore pins ticket #9 (2026-09-04):
// a store relocated by `zoo-code.customStoragePath` is (a) watched and
// (b) attributed to ZooCode, and a `roo-cline.customStoragePath` store to
// Roo — even though the relocated path carries no extension id. Both keys
// were confirmed from live installs. Deliberately NOT parallel: it swaps
// the package-level openSettings seam and overrides home env vars.
func TestCustomStoragePathAttributesRelocatedStore(t *testing.T) {
	orig := openSettings
	t.Cleanup(func() { openSettings = orig })

	rooDir := filepath.Join(t.TempDir(), "reloc-roo")
	zooDir := filepath.Join(t.TempDir(), "reloc-zoo")
	body := `{
  "roo-cline.customStoragePath": ` + jsonString(rooDir) + `,
  "zoo-code.customStoragePath": ` + jsonString(zooDir) + `
}`
	openSettings = func(string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(body)), nil
	}

	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	t.Setenv("USERPROFILE", fakeHome)
	t.Setenv("APPDATA", filepath.Join(fakeHome, "AppData", "Roaming"))

	a := New()

	rooTasks := filepath.Join(rooDir, "tasks")
	zooTasks := filepath.Join(zooDir, "tasks")
	var haveRoo, haveZoo bool
	for _, r := range a.WatchPaths() {
		if r == rooTasks {
			haveRoo = true
		}
		if r == zooTasks {
			haveZoo = true
		}
	}
	if !haveRoo {
		t.Errorf("relocated Roo store %q not among watch roots", rooTasks)
	}
	if !haveZoo {
		t.Errorf("relocated ZooCode store %q not among watch roots", zooTasks)
	}

	// The relocated path has no ext id, so bare toolFromPath would say
	// cline; toolForPath must recover the owner from the settings key.
	rooTask := filepath.Join(rooTasks, "task-1", "api_conversation_history.json")
	zooTask := filepath.Join(zooTasks, "task-2", "api_conversation_history.json")
	if got := a.toolForPath(rooTask); got != models.ToolRooCode {
		t.Errorf("toolForPath(relocated roo) = %q want %q", got, models.ToolRooCode)
	}
	if got := a.toolForPath(zooTask); got != models.ToolZooCode {
		t.Errorf("toolForPath(relocated zoo) = %q want %q", got, models.ToolZooCode)
	}
	if got := toolFromPath(zooTask); got != models.ToolCline {
		t.Errorf("sanity: bare toolFromPath(relocated zoo) = %q want cline (no id in path)", got)
	}
}

// jsonString quotes s as a JSON string literal for embedding in a
// settings.json body (backslashes in Windows paths must be escaped).
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
