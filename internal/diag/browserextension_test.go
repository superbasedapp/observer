//go:build !sbo_omit_capture_browser

package diag

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/browserhost"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/remedy"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// swapBrowserManifestsFn replaces the browserManifestsFn seam for the
// duration of the test and restores it on cleanup — no test may stat the
// real machine's browser profile dirs.
func swapBrowserManifestsFn(t *testing.T, fn func() []browserhost.ManifestStatus) {
	t.Helper()
	orig := browserManifestsFn
	browserManifestsFn = fn
	t.Cleanup(func() { browserManifestsFn = orig })
}

// swapBrowserWindowsHomesFn replaces the browserWindowsHomesFn seam for the
// duration of the test and restores it on cleanup — no test may enumerate
// the real machine's home directories.
func swapBrowserWindowsHomesFn(t *testing.T, fn func() []crossmount.HomeRoot) {
	t.Helper()
	orig := browserWindowsHomesFn
	browserWindowsHomesFn = fn
	t.Cleanup(func() { browserWindowsHomesFn = orig })
}

// swapBrowserStatExistsFn replaces the browserStatExistsFn seam for the
// duration of the test and restores it on cleanup — no test may stat real
// paths on the host running the suite.
func swapBrowserStatExistsFn(t *testing.T, fn func(string) bool) {
	t.Helper()
	orig := browserStatExistsFn
	browserStatExistsFn = fn
	t.Cleanup(func() { browserStatExistsFn = orig })
}

// swapBrowserHealthNowFn pins browserHealthNowFn to a fixed instant for the
// duration of the test and restores it on cleanup.
func swapBrowserHealthNowFn(t *testing.T, now time.Time) {
	t.Helper()
	orig := browserHealthNowFn
	browserHealthNowFn = func() time.Time { return now }
	t.Cleanup(func() { browserHealthNowFn = orig })
}

func TestBrowserManifestStatus(t *testing.T) {
	tests := []struct {
		name      string
		manifests []browserhost.ManifestStatus
		homes     []crossmount.HomeRoot
		statExist map[string]bool
		wantOK    bool
		wantSub   string
	}{
		{
			name:      "no browsers detected at all",
			manifests: nil,
			homes:     nil,
			wantOK:    false,
			wantSub:   "no native-messaging host manifest found for any Chromium-family browser",
		},
		{
			name: "browser detected but manifest missing",
			manifests: []browserhost.ManifestStatus{
				{Browser: "chrome", Name: "Google Chrome", Present: false},
			},
			wantOK:  false,
			wantSub: "browser(s) detected on this host (chrome)",
		},
		{
			name: "dir-based manifest present",
			manifests: []browserhost.ManifestStatus{
				{Browser: "chrome", Name: "Google Chrome", Present: true},
			},
			wantOK:  true,
			wantSub: "native-messaging host manifest registered: chrome",
		},
		{
			name:      "windows cross-mount manifest present, no local browsers",
			manifests: nil,
			homes: []crossmount.HomeRoot{
				{Path: "/mnt/c/Users/alice", OS: crossmount.OSWindows},
			},
			statExist: map[string]bool{"present": true},
			wantOK:    true,
			wantSub:   "windows(alice)",
		},
		{
			name:      "non-windows home is ignored",
			manifests: nil,
			homes: []crossmount.HomeRoot{
				{Path: "/home/alice", OS: crossmount.OSLinux},
			},
			wantOK:  false,
			wantSub: "no native-messaging host manifest found",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			swapBrowserManifestsFn(t, func() []browserhost.ManifestStatus { return tc.manifests })
			swapBrowserWindowsHomesFn(t, func() []crossmount.HomeRoot { return tc.homes })
			swapBrowserStatExistsFn(t, func(string) bool { return tc.statExist["present"] })
			ok, detail := browserManifestStatus()
			if ok != tc.wantOK {
				t.Errorf("browserManifestStatus() ok = %v, want %v (detail=%q)", ok, tc.wantOK, detail)
			}
			if !strings.Contains(detail, tc.wantSub) {
				t.Errorf("browserManifestStatus() detail = %q, want substring %q", detail, tc.wantSub)
			}
		})
	}
}

func TestBrowserHeartbeatStatus(t *testing.T) {
	fixedNow := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

	writeHealthFile := func(t *testing.T, dir string, sites map[string]browserHealthEntryMinimal) string {
		t.Helper()
		hf := browserHealthFileMinimal{Sites: sites}
		raw, err := json.Marshal(hf)
		if err != nil {
			t.Fatalf("marshal fixture: %v", err)
		}
		path := filepath.Join(dir, browserHealthFileName)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		return path
	}

	t.Run("no DB path configured", func(t *testing.T) {
		swapBrowserHealthNowFn(t, fixedNow)
		ok, detail := browserHeartbeatStatus("chatgpt-web", config.Config{})
		if ok {
			t.Error("expected ok=false with no DB path configured")
		}
		if !strings.Contains(detail, "no observer DB path configured") {
			t.Errorf("detail = %q", detail)
		}
	})

	t.Run("health file missing", func(t *testing.T) {
		swapBrowserHealthNowFn(t, fixedNow)
		dir := t.TempDir()
		var cfg config.Config
		cfg.Observer.DBPath = filepath.Join(dir, "observer.db")
		ok, detail := browserHeartbeatStatus("chatgpt-web", cfg)
		if ok {
			t.Error("expected ok=false with no health file present")
		}
		if !strings.Contains(detail, "no browser-health.json found") {
			t.Errorf("detail = %q", detail)
		}
	})

	t.Run("site not recorded", func(t *testing.T) {
		swapBrowserHealthNowFn(t, fixedNow)
		dir := t.TempDir()
		writeHealthFile(t, dir, map[string]browserHealthEntryMinimal{
			"claude-web": {Status: "ok", RecordedAt: fixedNow.UnixMilli()},
		})
		var cfg config.Config
		cfg.Observer.DBPath = filepath.Join(dir, "observer.db")
		ok, detail := browserHeartbeatStatus("chatgpt-web", cfg)
		if ok {
			t.Error("expected ok=false when the tool's site is absent from the health file")
		}
		if !strings.Contains(detail, "no capture activity recorded yet for chatgpt-web") {
			t.Errorf("detail = %q", detail)
		}
	})

	t.Run("fresh activity is OK", func(t *testing.T) {
		swapBrowserHealthNowFn(t, fixedNow)
		dir := t.TempDir()
		writeHealthFile(t, dir, map[string]browserHealthEntryMinimal{
			"chatgpt-web": {Status: "ok", RecordedAt: fixedNow.Add(-5 * time.Minute).UnixMilli(), Ingested: 42},
		})
		var cfg config.Config
		cfg.Observer.DBPath = filepath.Join(dir, "observer.db")
		ok, detail := browserHeartbeatStatus("chatgpt-web", cfg)
		if !ok {
			t.Errorf("expected ok=true for fresh activity, detail=%q", detail)
		}
		if !strings.Contains(detail, "ingested=42") {
			t.Errorf("detail = %q", detail)
		}
	})

	t.Run("stale activity warns", func(t *testing.T) {
		swapBrowserHealthNowFn(t, fixedNow)
		dir := t.TempDir()
		writeHealthFile(t, dir, map[string]browserHealthEntryMinimal{
			"chatgpt-web": {Status: "ok", RecordedAt: fixedNow.Add(-30 * 24 * time.Hour).UnixMilli()},
		})
		var cfg config.Config
		cfg.Observer.DBPath = filepath.Join(dir, "observer.db")
		ok, detail := browserHeartbeatStatus("chatgpt-web", cfg)
		if ok {
			t.Error("expected ok=false for month-old activity")
		}
		if !strings.Contains(detail, "stale") {
			t.Errorf("detail = %q", detail)
		}
	})

	t.Run("degraded status warns even when fresh", func(t *testing.T) {
		swapBrowserHealthNowFn(t, fixedNow)
		dir := t.TempDir()
		writeHealthFile(t, dir, map[string]browserHealthEntryMinimal{
			"chatgpt-web": {Status: "degraded", RecordedAt: fixedNow.Add(-1 * time.Minute).UnixMilli()},
		})
		var cfg config.Config
		cfg.Observer.DBPath = filepath.Join(dir, "observer.db")
		ok, detail := browserHeartbeatStatus("chatgpt-web", cfg)
		if ok {
			t.Error("expected ok=false for degraded status")
		}
		if !strings.Contains(detail, "degraded") {
			t.Errorf("detail = %q", detail)
		}
	})
}

// TestCheckAdapterBrowserExtensionBranch pins that CheckAdapter dispatches
// the 5 *-web rows to the browser-extension health probe instead of the
// generic (always-nil) watch-path check, and that a normal watcher/hook
// adapter is unaffected — the capability-shape branch this file adds
// (docs/plans/adapter-parity-audit-2026-08-25.md §2.10).
func TestCheckAdapterBrowserExtensionBranch(t *testing.T) {
	swapLaunchResolve(t, func(integration.BinaryResolveSpec) toolresolve.Resolution {
		return toolresolve.Resolution{Verdict: toolresolve.VerdictNotFound}
	})

	web, ok := integration.For("chatgpt-web")
	if !ok || web.Hook.Mechanism != integration.HookBrowserExtension {
		t.Fatalf("fixture assumption broken: chatgpt-web Hook = %+v (want HookBrowserExtension)", web.Hook)
	}

	t.Run("web adapter never emits the generic watch-path WARN", func(t *testing.T) {
		swapBrowserManifestsFn(t, func() []browserhost.ManifestStatus { return nil })
		swapBrowserWindowsHomesFn(t, func() []crossmount.HomeRoot { return nil })
		swapBrowserStatExistsFn(t, func(string) bool { return false })
		swapBrowserHealthNowFn(t, time.Now())

		c, ok := CheckAdapter("chatgpt-web", config.Config{})
		if !ok {
			t.Fatal("chatgpt-web should be a known adapter")
		}
		if joinedHas(c.Details, "no watch path found") {
			t.Errorf("chatgpt-web should never emit the generic watch-path WARN: %v", c.Details)
		}
		if !joinedHas(c.Details, "observer init --browser") {
			t.Errorf("expected an actionable remediation hint: %v", c.Details)
		}
		// The same fix as a dashboard button (Settings > Browser capture).
		assertSpelled(t, c, remedy.BrowserHostSetup)
	})

	t.Run("watcher-only adapter is unaffected", func(t *testing.T) {
		cursor, ok := integration.For("cursor")
		if !ok || cursor.Hook.Mechanism == integration.HookBrowserExtension {
			t.Fatalf("fixture assumption broken: cursor Hook = %+v", cursor.Hook)
		}
		c, ok := CheckAdapter("cursor", config.Config{})
		if !ok {
			t.Fatal("cursor should be a known adapter")
		}
		if !joinedHas(c.Details, "watch path") {
			t.Errorf("cursor should still get the generic watch-path check: %v", c.Details)
		}
	})
}
