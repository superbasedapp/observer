package proxyroute

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/credfile"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/routeprov"
)

// The Cline extension route (IDE-8, D9): globalState.json is the lever
// current Cline builds read, so the old "state.vscdb only, manual paste"
// claim is gone. Every test is red on the old code (there was no writer).

//nolint:gosec // G101: a fake fixture value, not a credential.
const clineFakeKey = "sk-test-not-real-0000"

// clineHermetic clears the Cline relocation variables for one test.
func clineHermetic(t *testing.T) {
	t.Helper()
	for _, k := range []string{"CLINE_DIR", "CLINE_DATA_DIR"} {
		t.Setenv(k, "")
	}
}

func clineStatePath(home string) string {
	return filepath.Join(home, ".cline", "data", "globalState.json")
}

func seedClineState(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// clineState renders a globalState.json in the extension's own
// JSON.stringify(data, null, 2) layout, with a fake key under an unrelated
// member so a re-serialization or a quoted error would show.
func clineState(members string) string {
	return "{\n  \"welcomeViewCompleted\": true,\n  \"someLegacyKey\": \"" + clineFakeKey + "\"" + members + ",\n  \"mode\": \"act\"\n}"
}

func TestRegisterClineRules(t *testing.T) {
	cases := []struct {
		name, seed  string
		absent      bool
		wantAdded   bool
		wantSet     bool
		wantMissing bool
		wantErr     string
		wantMember  string // the member line expected in the file after
	}{
		{name: "file absent: Cline never started", absent: true, wantMissing: true},
		{name: "no provider selected", seed: clineState(""), wantErr: "names no provider"},
		{name: "a provider the proxy cannot carry", seed: clineState(",\n  \"actModeApiProvider\": \"openrouter\""), wantErr: "cannot carry"},
		{name: "act and plan on different endpoints", seed: clineState(",\n  \"actModeApiProvider\": \"openai\",\n  \"planModeApiProvider\": \"anthropic\""), wantErr: "different endpoints"},
		{
			name: "openai compatible, no base URL: added", seed: clineState(",\n  \"actModeApiProvider\": \"openai\",\n  \"planModeApiProvider\": \"openai\""),
			wantAdded: true, wantMember: "\"openAiBaseUrl\": \"http://127.0.0.1:8820/v1\"",
		},
		{
			name: "openai compatible, empty base URL: set", seed: clineState(",\n  \"actModeApiProvider\": \"openai\",\n  \"openAiBaseUrl\": \"\""),
			wantAdded: true, wantMember: "\"openAiBaseUrl\": \"http://127.0.0.1:8820/v1\"",
		},
		{
			name: "anthropic: the bare proxy root", seed: clineState(",\n  \"actModeApiProvider\": \"anthropic\""),
			wantAdded: true, wantMember: "\"anthropicBaseUrl\": \"http://127.0.0.1:8820\"",
		},
		{
			name: "already routed", seed: clineState(",\n  \"actModeApiProvider\": \"openai\",\n  \"openAiBaseUrl\": \"http://127.0.0.1:8820/v1\""),
			wantSet: true,
		},
		{
			name: "another local observer port is left alone", seed: clineState(",\n  \"actModeApiProvider\": \"openai\",\n  \"openAiBaseUrl\": \"http://127.0.0.1:9900/v1\""),
			wantSet: true,
		},
		{
			name: "a foreign endpoint is refused", seed: clineState(",\n  \"actModeApiProvider\": \"openai\",\n  \"openAiBaseUrl\": \"https://gateway.corp.example/v1\""),
			wantErr: "non-observer URL",
		},
		{name: "a non-string provider is refused", seed: clineState(",\n  \"actModeApiProvider\": 7"), wantErr: "not a string"},
		{name: "not JSON", seed: "{\"actModeApiProvider\": ", wantErr: "left unchanged"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clineHermetic(t)
			home := t.TempDir()
			path := clineStatePath(home)
			if !tc.absent {
				seedClineState(t, path, tc.seed)
			}
			r, err := NewRegistrar(RegisterOptions{ProxyPort: 8820, HomeDir: home})
			if err != nil {
				t.Fatal(err)
			}
			res := r.RegisterCline()
			if res.ConfigMissing != tc.wantMissing || res.Added != tc.wantAdded || res.AlreadySet != tc.wantSet {
				t.Fatalf("result = %+v", res)
			}
			after, _ := os.ReadFile(path)
			if tc.wantErr != "" {
				if res.Error == nil || !strings.Contains(res.Error.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to mention %q", res.Error, tc.wantErr)
				}
				if strings.Contains(res.Error.Error(), clineFakeKey) || strings.Contains(res.Error.Error(), "gateway.corp") {
					t.Errorf("the error quotes the file: %v", res.Error)
				}
			} else if res.Error != nil {
				t.Fatalf("err = %v", res.Error)
			}
			if !tc.wantAdded {
				if !tc.absent && string(after) != tc.seed {
					t.Errorf("the file changed although nothing was routed:\n%s", after)
				}
				return
			}
			if !strings.Contains(string(after), tc.wantMember) {
				t.Errorf("route member missing:\n%s", after)
			}
			// Every byte the writer does not own is kept, the fake key
			// included, and the file keeps its mode.
			kept := strings.Replace(string(after), ",\n  "+tc.wantMember, "", 1)
			if strings.Contains(tc.seed, "\"openAiBaseUrl\": \"\"") {
				kept = strings.Replace(string(after), tc.wantMember, "\"openAiBaseUrl\": \"\"", 1)
			}
			if kept != tc.seed {
				t.Errorf("the write changed more than the route member:\n%s\nseed:\n%s", after, tc.seed)
			}
			if runtime.GOOS != "windows" {
				if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o644 {
					t.Errorf("mode = %v, want 0644 kept", fi.Mode().Perm())
				}
			}
			entries, _ := os.ReadDir(filepath.Dir(path))
			if len(entries) != 1 {
				t.Errorf("the write left a backup or temp file: %v", entries)
			}
		})
	}
}

// TestRegisterClineFollowsClineDataDir: the writer edits the globalState.json
// the extension reads, CLINE_DATA_DIR before CLINE_DIR, whether the lookup
// is injected (a pinned home) or the process environment of an unpinned,
// non-isolated home (the production shape).
func TestRegisterClineFollowsClineDataDir(t *testing.T) {
	for _, tc := range []struct {
		name   string
		pinned bool
	}{{"injected lookup under a pinned home", true}, {"process environment, home not pinned", false}} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			data := t.TempDir()
			env := map[string]string{"CLINE_DIR": filepath.Join(home, "ignored"), "CLINE_DATA_DIR": data}
			opts := RegisterOptions{ProxyPort: 8820, DryRun: true}
			if tc.pinned {
				clineHermetic(t)
				opts.HomeDir = home
				opts.Getenv = func(k string) string { return env[k] }
			} else {
				t.Setenv("HOME", home)
				t.Setenv("USERPROFILE", home)
				for k, v := range env {
					t.Setenv(k, v)
				}
			}
			path := filepath.Join(data, "globalState.json")
			seedClineState(t, path, clineState(",\n  \"actModeApiProvider\": \"openai\""))
			r, err := NewRegistrar(opts)
			if err != nil {
				t.Fatal(err)
			}
			if res := r.RegisterCline(); res.Error != nil || !res.Added || res.ConfigPath != path {
				t.Fatalf("result = %+v, want a dry-run add at %s", res, path)
			}
			if got, _ := os.ReadFile(path); strings.Contains(string(got), "openAiBaseUrl") {
				t.Error("a dry run wrote the file")
			}
		})
	}
}

// TestRegisterClineKeepsAPinnedOrIsolatedHome (audit finding 2 of the
// surface-gap Waves 1-3 hand-back): with HOME at a temp dir and the
// developer's CLINE_DATA_DIR exported, a registrar whose home is pinned, or
// whose process home is isolated from the real one (the LEFT2 rule,
// crossmount.IsolationReason), edits the globalState.json under that home
// and never the one CLINE_DATA_DIR names (the mcpregister precedent).
func TestRegisterClineKeepsAPinnedOrIsolatedHome(t *testing.T) {
	for _, tc := range []struct {
		name     string
		pinned   bool
		isolated bool
	}{{"pinned home", true, false}, {"isolated process home", false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			real := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			t.Setenv("CLINE_DIR", "")
			t.Setenv("CLINE_DATA_DIR", real)
			if tc.isolated {
				crossmount.StageForeignLayoutForTest(t, crossmount.ForeignLayoutForTest{Root: t.TempDir(), RealHome: t.TempDir()})
				if crossmount.IsolationReason() == "" {
					t.Fatal("the staged layout did not isolate the home")
				}
			}
			body := clineState(",\n  \"actModeApiProvider\": \"openai\"")
			realPath := filepath.Join(real, "globalState.json")
			seedClineState(t, realPath, body)
			seedClineState(t, clineStatePath(home), body)
			opts := RegisterOptions{ProxyPort: 8820}
			if tc.pinned {
				opts.HomeDir = home
			}
			r, err := NewRegistrar(opts)
			if err != nil {
				t.Fatal(err)
			}
			res := r.RegisterCline()
			if res.Error != nil || !res.Added || res.ConfigPath != clineStatePath(home) {
				t.Fatalf("result = %+v, want an add at %s", res, clineStatePath(home))
			}
			if got, _ := os.ReadFile(realPath); string(got) != body {
				t.Errorf("the CLINE_DATA_DIR globalState.json was edited:\n%s", got)
			}
		})
	}
}

// TestRegisterClineRefusesASymlink: replacing a symlinked globalState.json
// would cut the link, so the writer refuses.
func TestRegisterClineRefusesASymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	clineHermetic(t)
	home := t.TempDir()
	real := filepath.Join(t.TempDir(), "state.json")
	seedClineState(t, real, clineState(",\n  \"actModeApiProvider\": \"openai\""))
	path := clineStatePath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, path); err != nil {
		t.Fatal(err)
	}
	r, _ := NewRegistrar(RegisterOptions{ProxyPort: 8820, HomeDir: home})
	res := r.RegisterCline()
	var safe *credfile.SafeError
	if res.Error == nil || !errors.As(res.Error, &safe) || res.Added {
		t.Fatalf("result = %+v, want a safe refusal", res)
	}
}

// TestClineRouteLeaveRoundTrip: a route enrolment wrote is recorded with
// its member and leaves with the organization, giving the file back.
func TestClineRouteLeaveRoundTrip(t *testing.T) {
	clineHermetic(t)
	home := t.TempDir()
	path := clineStatePath(home)
	seed := clineState(",\n  \"actModeApiProvider\": \"anthropic\"")
	seedClineState(t, path, seed)
	r, err := NewRegistrar(RegisterOptions{ProxyPort: 8820, HomeDir: home, Writer: routeprov.WriterEnrolment})
	if err != nil {
		t.Fatal(err)
	}
	if res := r.RegisterCline(); res.Error != nil || !res.Added || res.ProvenanceError != nil {
		t.Fatalf("register = %+v", res)
	}
	if v, ok, err := readClineRouteFor(path, &routeprov.Record{RouteKey: []string{"anthropicBaseUrl"}}); err != nil || !ok || v != "http://127.0.0.1:8820" {
		t.Fatalf("read = %q, %v, %v", v, ok, err)
	}
	if want, ok := clineWant(routeprov.Record{RouteKey: []string{"anthropicBaseUrl"}}, 9100); !ok || want != "http://127.0.0.1:9100" {
		t.Errorf("clineWant = %q, %v", want, ok)
	}
	routes, err := r.LeaveRoutes(true)
	if err != nil {
		t.Fatal(err)
	}
	removed := false
	for _, lr := range routes {
		if lr.Tool == "cline" && lr.Removed {
			removed = true
		}
	}
	if !removed {
		t.Fatalf("Leave did not remove the cline route: %+v", routes)
	}
	if got, _ := os.ReadFile(path); string(got) != seed {
		t.Errorf("Leave did not give the file back:\n%s", got)
	}
	if _, ok := clineRecordKey(&routeprov.Record{RouteKey: []string{"apiKey"}}); ok {
		t.Error("a record naming a member the writer does not own was accepted")
	}
}
