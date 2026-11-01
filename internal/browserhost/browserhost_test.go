package browserhost

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/browserhost/hostfiles"
)

// TestHostFilesByteIdentical is the mechanical drift guard for the two host.js
// copies: the go:embed SHIPPED copy (internal/browserhost/hostfiles/host.js,
// obtained here via the actual embed → hostfiles.WriteHost so we compare the
// artifact that ACTUALLY ships) and the standalone repo copy
// (browser-extension/native-messaging-host/host.js). They are contractually
// byte-identical (host.js's own header documents this); a comment-only or
// behavioral divergence between them is a silent-drift bug. The standalone
// copy is not part of a distribution/module build, so when it's absent we skip
// rather than fail.
func TestHostFilesByteIdentical(t *testing.T) {
	// The embedded (shipped) bytes: write the embed into a temp dir and read
	// host.js back — WriteHost stamps only the launcher, so host.js is the
	// verbatim embedded content.
	dir := t.TempDir()
	if _, err := hostfiles.WriteHost(dir, hostfiles.Env{}); err != nil {
		t.Fatalf("WriteHost: %v", err)
	}
	embedded, err := os.ReadFile(filepath.Join(dir, hostfiles.HostScriptName))
	if err != nil {
		t.Fatalf("read embedded host.js: %v", err)
	}

	// The standalone copy, located relative to THIS test file's package dir
	// (internal/browserhost) so the path holds regardless of the working dir.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Skip("runtime.Caller unavailable; cannot locate the standalone host.js")
	}
	pkgDir := filepath.Dir(thisFile)
	standalonePath := filepath.Join(pkgDir, "..", "..", "browser-extension", "native-messaging-host", "host.js")
	standalone, err := os.ReadFile(standalonePath)
	if os.IsNotExist(err) {
		t.Skipf("standalone host.js absent (%s) — distribution build; skipping drift guard", standalonePath)
	}
	if err != nil {
		t.Fatalf("read standalone host.js: %v", err)
	}

	if !bytes.Equal(embedded, standalone) {
		t.Errorf("host.js copies have DRIFTED — the embedded (shipped) hostfiles/host.js and "+
			"browser-extension/native-messaging-host/host.js must be byte-identical.\n"+
			"embedded=%d bytes, standalone=%d bytes. Re-sync them (edit both identically).",
			len(embedded), len(standalone))
	}
}

// mkProfile creates the browser's user-data dir under home so Detect sees it.
func mkProfile(t *testing.T, home, goos, browserID string) {
	t.Helper()
	for _, b := range browsers {
		if b.ID != browserID {
			continue
		}
		dir, ok := b.profileDir(home, goos)
		if !ok {
			t.Fatalf("no dir for %s on %s", browserID, goos)
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir profile: %v", err)
		}
		return
	}
	t.Fatalf("unknown browser %q", browserID)
}

func TestDetectSkipsMissingProfileDirs(t *testing.T) {
	home := t.TempDir()
	r, err := NewRegistrar(Options{Home: home, GOOS: "linux"})
	if err != nil {
		t.Fatalf("NewRegistrar: %v", err)
	}
	if got := r.Detect(); len(got) != 0 {
		t.Fatalf("Detect on empty home = %v, want none", got)
	}
	// Create chrome + brave profile dirs; edge/chromium stay absent.
	mkProfile(t, home, "linux", "chrome")
	mkProfile(t, home, "linux", "brave")
	got := r.Detect()
	if len(got) != 2 {
		t.Fatalf("Detect = %d browsers, want 2", len(got))
	}
	// Deterministic sort by ID: brave, chrome.
	if got[0].ID != "brave" || got[1].ID != "chrome" {
		t.Errorf("Detect order = %v, want [brave chrome]", []string{got[0].ID, got[1].ID})
	}
}

func TestRegisterWritesManifestPerBrowser(t *testing.T) {
	home := t.TempDir()
	mkProfile(t, home, "linux", "chrome")
	mkProfile(t, home, "linux", "edge")
	r, err := NewRegistrar(Options{
		Home: home, GOOS: "linux",
		HostPath:     "/opt/observer/browser-host/host-launcher",
		ExtensionIDs: []string{"abcdefghijklmnopabcdefghijklmnop"},
	})
	if err != nil {
		t.Fatalf("NewRegistrar: %v", err)
	}
	results := r.Register()
	if len(results) != 2 {
		t.Fatalf("Register = %d results, want 2", len(results))
	}
	for _, res := range results {
		if res.Error != nil {
			t.Fatalf("%s: %v", res.Browser, res.Error)
		}
		if !res.Wrote {
			t.Errorf("%s: Wrote=false, want true", res.Browser)
		}
		// The manifest must live under the browser's own NativeMessagingHosts.
		if filepath.Base(res.ConfigPath) != manifestFileName {
			t.Errorf("%s: ConfigPath = %q, want basename %q", res.Browser, res.ConfigPath, manifestFileName)
		}
		if filepath.Base(filepath.Dir(res.ConfigPath)) != "NativeMessagingHosts" {
			t.Errorf("%s: manifest not under NativeMessagingHosts: %q", res.Browser, res.ConfigPath)
		}
		raw, err := os.ReadFile(res.ConfigPath)
		if err != nil {
			t.Fatalf("read %s: %v", res.ConfigPath, err)
		}
		var m manifest
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("manifest not valid JSON: %v", err)
		}
		if m.Name != HostName {
			t.Errorf("manifest name = %q, want %q", m.Name, HostName)
		}
		if m.Path != "/opt/observer/browser-host/host-launcher" {
			t.Errorf("manifest path = %q", m.Path)
		}
		if len(m.AllowedOrigins) != 1 || m.AllowedOrigins[0] != "chrome-extension://abcdefghijklmnopabcdefghijklmnop/" {
			t.Errorf("manifest allowed_origins = %v", m.AllowedOrigins)
		}
		if m.Type != "stdio" {
			t.Errorf("manifest type = %q, want stdio", m.Type)
		}
	}
}

func TestRegisterIdempotent(t *testing.T) {
	home := t.TempDir()
	mkProfile(t, home, "linux", "chrome")
	opts := Options{Home: home, GOOS: "linux", HostPath: "/x/host", ExtensionIDs: []string{"id"}}
	r, _ := NewRegistrar(opts)

	first := r.Register()
	if len(first) != 1 || !first[0].Wrote {
		t.Fatalf("first Register = %+v, want one Wrote", first)
	}
	second := r.Register()
	if len(second) != 1 || !second[0].AlreadySet {
		t.Fatalf("second Register = %+v, want AlreadySet (idempotent)", second)
	}
	if second[0].Wrote {
		t.Errorf("idempotent re-run must not report Wrote")
	}
}

func TestRegisterRewritesOnChange(t *testing.T) {
	home := t.TempDir()
	mkProfile(t, home, "linux", "chrome")
	r1, _ := NewRegistrar(Options{Home: home, GOOS: "linux", HostPath: "/a", ExtensionIDs: []string{"id1"}})
	r1.Register()
	// A different extension id must produce a fresh write, not AlreadySet.
	r2, _ := NewRegistrar(Options{Home: home, GOOS: "linux", HostPath: "/a", ExtensionIDs: []string{"id2"}})
	res := r2.Register()
	if len(res) != 1 || !res[0].Wrote {
		t.Fatalf("changed manifest Register = %+v, want Wrote", res)
	}
}

func TestRegisterDryRunDoesNotWrite(t *testing.T) {
	home := t.TempDir()
	mkProfile(t, home, "linux", "chrome")
	r, _ := NewRegistrar(Options{Home: home, GOOS: "linux", HostPath: "/x", ExtensionIDs: []string{"id"}, DryRun: true})
	res := r.Register()
	if len(res) != 1 || !res[0].Wrote {
		t.Fatalf("dry-run Register = %+v, want Wrote (preview)", res)
	}
	if _, err := os.Stat(res[0].ConfigPath); !os.IsNotExist(err) {
		t.Errorf("dry-run must not create the manifest file (stat err = %v)", err)
	}
}

func TestPlaceholderExtensionIDWhenAbsent(t *testing.T) {
	home := t.TempDir()
	mkProfile(t, home, "linux", "chrome")
	r, _ := NewRegistrar(Options{Home: home, GOOS: "linux", HostPath: "/x"})
	res := r.Register()
	raw, _ := os.ReadFile(res[0].ConfigPath)
	var m manifest
	_ = json.Unmarshal(raw, &m)
	want := "chrome-extension://" + PlaceholderExtensionID + "/"
	if m.AllowedOrigins[0] != want {
		t.Errorf("allowed_origins[0] = %q, want %q", m.AllowedOrigins[0], want)
	}
}

func TestAllowedOriginsForMultipleIDs(t *testing.T) {
	ph := "chrome-extension://" + PlaceholderExtensionID + "/"
	tests := []struct {
		name string
		ids  []string
		want []string
	}{
		{
			name: "nil is placeholder",
			ids:  nil,
			want: []string{ph},
		},
		{
			name: "empty slice is placeholder",
			ids:  []string{},
			want: []string{ph},
		},
		{
			name: "all-blank is placeholder",
			ids:  []string{"", "   "},
			want: []string{ph},
		},
		{
			name: "single id byte-identical",
			ids:  []string{"abcdefghijklmnopabcdefghijklmnop"},
			want: []string{"chrome-extension://abcdefghijklmnopabcdefghijklmnop/"},
		},
		{
			name: "two ids order preserved",
			ids:  []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
			want: []string{
				"chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",
				"chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/",
			},
		},
		{
			name: "duplicates deduped preserving first-seen order",
			ids:  []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			want: []string{
				"chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",
				"chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/",
			},
		},
		{
			name: "whitespace trimmed before dedup",
			ids:  []string{" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			want: []string{"chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := allowedOriginsFor(tc.ids)
			if len(got) != len(tc.want) {
				t.Fatalf("allowedOriginsFor(%v) = %v, want %v", tc.ids, got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("origin[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestRegisterWritesAllExtensionIDs(t *testing.T) {
	home := t.TempDir()
	mkProfile(t, home, "linux", "chrome")
	r, err := NewRegistrar(Options{
		Home: home, GOOS: "linux", HostPath: "/x",
		ExtensionIDs: []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
	})
	if err != nil {
		t.Fatalf("NewRegistrar: %v", err)
	}
	res := r.Register()
	raw, _ := os.ReadFile(res[0].ConfigPath)
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("manifest not valid JSON: %v", err)
	}
	want := []string{
		"chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",
		"chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/",
	}
	if len(m.AllowedOrigins) != len(want) {
		t.Fatalf("allowed_origins = %v, want %v", m.AllowedOrigins, want)
	}
	for i := range want {
		if m.AllowedOrigins[i] != want[i] {
			t.Errorf("allowed_origins[%d] = %q, want %q", i, m.AllowedOrigins[i], want[i])
		}
	}
}

func TestPerBrowserDirTable(t *testing.T) {
	// Pins the per-browser × per-OS lookup table: each browser resolves a
	// distinct NativeMessagingHosts dir on linux + darwin.
	tests := []struct {
		id, goos, wantContains string
	}{
		{"chrome", "linux", ".config/google-chrome/NativeMessagingHosts"},
		{"chromium", "linux", ".config/chromium/NativeMessagingHosts"},
		{"edge", "linux", ".config/microsoft-edge/NativeMessagingHosts"},
		{"brave", "linux", ".config/BraveSoftware/Brave-Browser/NativeMessagingHosts"},
		{"chrome", "darwin", "Library/Application Support/Google/Chrome/NativeMessagingHosts"},
		{"edge", "darwin", "Library/Application Support/Microsoft Edge/NativeMessagingHosts"},
	}
	home := "/home/u"
	for _, tc := range tests {
		var b Browser
		for _, cand := range browsers {
			if cand.ID == tc.id {
				b = cand
			}
		}
		got, ok := b.nativeMessagingDir(home, tc.goos)
		if !ok {
			t.Errorf("%s/%s: no dir", tc.id, tc.goos)
			continue
		}
		want := filepath.Join(home, filepath.FromSlash(tc.wantContains))
		if got != want {
			t.Errorf("%s/%s dir = %q, want %q", tc.id, tc.goos, got, want)
		}
	}
}

func TestInstalledReportsDetectedIDs(t *testing.T) {
	home := t.TempDir()
	mkProfile(t, home, "linux", "chrome")
	mkProfile(t, home, "linux", "chromium")
	r, _ := NewRegistrar(Options{Home: home, GOOS: "linux"})
	got := r.Installed()
	if len(got) != 2 {
		t.Fatalf("Installed = %v, want 2", got)
	}
	// Sorted by ID: chrome, chromium.
	if got[0] != "chrome" || got[1] != "chromium" {
		t.Errorf("Installed = %v, want [chrome chromium]", got)
	}
}

func TestNewRegistrarDefaultsToRealHomeAndGOOS(t *testing.T) {
	// No Home/GOOS override → resolves os.UserHomeDir + runtime.GOOS without
	// erroring (the default-path branch). Detect may be empty on CI; we only
	// assert construction succeeds.
	r, err := NewRegistrar(Options{})
	if err != nil {
		t.Fatalf("NewRegistrar default: %v", err)
	}
	_ = r.Detect()
}

func TestDetectIgnoresAFileNamedLikeAProfileDir(t *testing.T) {
	home := t.TempDir()
	// Create a FILE where chrome's profile dir would be — Detect must not
	// treat it as a browser (it stats for IsDir()).
	chromeParent := filepath.Join(home, ".config")
	if err := os.MkdirAll(chromeParent, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(chromeParent, "google-chrome"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	r, _ := NewRegistrar(Options{Home: home, GOOS: "linux"})
	if got := r.Detect(); len(got) != 0 {
		t.Errorf("Detect = %v, want none (a file is not a profile dir)", got)
	}
}

func TestValidExtensionID(t *testing.T) {
	valid := []string{
		"abcdefghijklmnopabcdefghijklmnop", // 32 chars, all a-p
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"pppppppppppppppppppppppppppppppp",
	}
	for _, id := range valid {
		if !ValidExtensionID(id) {
			t.Errorf("ValidExtensionID(%q) = false, want true", id)
		}
	}
	invalid := []string{
		"",
		"tooshort",
		"abcdefghijklmnopabcdefghijklmno",   // 31
		"abcdefghijklmnopabcdefghijklmnopq", // 33
		"abcdefghijklmnopabcdefghijklmnoz",  // 'z' out of a-p
		"ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP",  // uppercase
		"chrome-extension://abcd/",          // a pasted URL
		"abcdefghijklmnop abcdefghijklmno",  // space
	}
	for _, id := range invalid {
		if ValidExtensionID(id) {
			t.Errorf("ValidExtensionID(%q) = true, want false", id)
		}
	}
}

func TestHostInstallDir(t *testing.T) {
	got, err := HostInstallDir("/home/u")
	if err != nil {
		t.Fatalf("HostInstallDir: %v", err)
	}
	want := filepath.Join("/home/u", ".observer", "browser-host")
	if got != want {
		t.Errorf("HostInstallDir = %q, want %q", got, want)
	}
	// Empty home resolves the real home without erroring.
	if _, err := HostInstallDir(""); err != nil {
		t.Fatalf("HostInstallDir(\"\"): %v", err)
	}
}

func TestWindowsHasNoGroundedDir(t *testing.T) {
	// Windows is registry-based, not dir-based — the table omits it, so
	// Register honestly writes nothing rather than a file the browser
	// never reads.
	home := t.TempDir()
	// Even if a chrome profile dir "existed", windows has no map entry.
	r, _ := NewRegistrar(Options{Home: home, GOOS: "windows"})
	if got := r.Detect(); len(got) != 0 {
		t.Errorf("Detect on windows = %v, want none (registry-based, not wired)", got)
	}
}

// TestManifests pins the PRESENCE-only contract of the doctor's
// browser-extension health probe (internal/diag): a detected browser with no
// manifest file on disk reports Present=false; after Register writes it,
// Present flips to true; a browser with no grounded dir on this GOOS (e.g.
// windows) never appears in the result at all.
func TestManifests(t *testing.T) {
	home := t.TempDir()
	mkProfile(t, home, "linux", "chrome")
	mkProfile(t, home, "linux", "brave")
	r, err := NewRegistrar(Options{Home: home, GOOS: "linux"})
	if err != nil {
		t.Fatalf("NewRegistrar: %v", err)
	}

	before := r.Manifests()
	if len(before) != 2 {
		t.Fatalf("Manifests before Register = %d entries, want 2: %+v", len(before), before)
	}
	for _, m := range before {
		if m.Present {
			t.Errorf("Manifests before Register: %s reported Present=true", m.Browser)
		}
		if m.Path == "" {
			t.Errorf("Manifests: %s has an empty Path", m.Browser)
		}
	}
	// Deterministic sort by browser ID: brave, chrome.
	if before[0].Browser != "brave" || before[1].Browser != "chrome" {
		t.Errorf("Manifests order = %v, want [brave chrome]", []string{before[0].Browser, before[1].Browser})
	}

	rw, err := NewRegistrar(Options{Home: home, GOOS: "linux", HostPath: "/x", ExtensionIDs: []string{"id"}})
	if err != nil {
		t.Fatalf("NewRegistrar: %v", err)
	}
	rw.Register()

	after := r.Manifests()
	for _, m := range after {
		if !m.Present {
			t.Errorf("Manifests after Register: %s still reports Present=false (path %s)", m.Browser, m.Path)
		}
	}

	// windows has no dir-based entry in the per-browser table, so it never
	// appears in Manifests() even though a "browser" could be detected on
	// this GOOS in principle — see TestWindowsHasNoGroundedDir.
	rWin, err := NewRegistrar(Options{Home: home, GOOS: "windows"})
	if err != nil {
		t.Fatalf("NewRegistrar: %v", err)
	}
	if got := rWin.Manifests(); len(got) != 0 {
		t.Errorf("Manifests on windows = %v, want none (registry-based, not dir-based)", got)
	}
}

// TestRegisterKeepsAForeignManifest (audit row 8 on the w13 hand-back, the
// FU-207 rule): a com.superbased.observer.json that is not Observer's is
// kept byte for byte without Force, dry run too, and refused naming the
// path; Force replaces it keeping .bak; Observer's own older manifest is
// still rewritten.
func TestRegisterKeepsAForeignManifest(t *testing.T) {
	home := t.TempDir()
	mkProfile(t, home, "linux", "chrome")
	first, _ := NewRegistrar(Options{Home: home, GOOS: "linux", HostPath: "/x/host", ExtensionIDs: []string{"id"}})
	res := first.Register()
	if len(res) != 1 || !res[0].Wrote {
		t.Fatalf("first Register = %+v", res)
	}
	path := res[0].ConfigPath
	ours, _ := os.ReadFile(path)
	const foreign = `{"name":"com.superbased.observer","description":"someone else's host","path":"/opt/other/host","type":"stdio","allowed_origins":[]}` + "\n"
	if err := os.WriteFile(path, []byte(foreign), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, dry := range []bool{true, false} {
		r, _ := NewRegistrar(Options{Home: home, GOOS: "linux", HostPath: "/x/host", ExtensionIDs: []string{"id"}, DryRun: dry})
		got := r.Register()
		if len(got) != 1 || got[0].Error == nil || !strings.Contains(got[0].Error.Error(), "doesn't look like an observer-managed file; pass --force to overwrite") || !strings.Contains(got[0].Error.Error(), path) {
			t.Errorf("dry=%v: Register over a foreign manifest = %+v, want the refusal naming %s", dry, got, path)
		}
		if b, _ := os.ReadFile(path); string(b) != foreign {
			t.Fatalf("dry=%v: the foreign manifest changed without Force:\n%s", dry, b)
		}
	}
	forced, _ := NewRegistrar(Options{Home: home, GOOS: "linux", HostPath: "/x/host", ExtensionIDs: []string{"id"}, Force: true})
	if got := forced.Register(); len(got) != 1 || got[0].Error != nil || !got[0].Wrote {
		t.Fatalf("Force Register = %+v", got)
	}
	if b, _ := os.ReadFile(path); string(b) != string(ours) {
		t.Errorf("Force did not write Observer's manifest:\n%s", b)
	}
	if b, err := os.ReadFile(path + ".bak"); err != nil || string(b) != foreign {
		t.Errorf("Force kept no .bak of the foreign manifest: %q, %v", b, err)
	}
	// Observer's own manifest for another extension id is rewritten.
	other, _ := NewRegistrar(Options{Home: home, GOOS: "linux", HostPath: "/x/host", ExtensionIDs: []string{"id2"}})
	if got := other.Register(); len(got) != 1 || got[0].Error != nil || !got[0].Wrote {
		t.Errorf("Observer's own older manifest was not rewritten: %+v", got)
	}
}
