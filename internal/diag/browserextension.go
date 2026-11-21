//go:build !sbo_omit_capture_browser

package diag

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/browserhost"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/remedy"
)

// browserExtensionHealthNote is CheckAdapter's capability-shape special
// case for the 5 *-web registry rows (chatgpt-web / claude-web /
// perplexity-web / gemini-web / copilot-web — every adapter whose
// integration.Capability.Hook.Mechanism is integration.HookBrowserExtension).
// CheckAdapter dispatches here instead of the generic watch-path check
// (CLAUDE.md #3 — capability SHAPE, never tool name): those adapters have no
// filesystem store at all (capture arrives over the browser's
// native-messaging bridge), so WatchPaths() is unconditionally nil and the
// generic check would file an unconditional, misleading WARN for every
// install — the bug this file fixes
// (docs/plans/adapter-parity-audit-2026-08-25.md §2.10).
//
// It reports two independent, honestly-graded signals instead:
//
//  1. is the native-messaging host manifest registered for at least one
//     Chromium-family browser — dir-based (Linux/macOS, via
//     browserhost.Registrar) and/or the cross-mounted Windows-side manifest
//     a WSL daemon writes under a Windows home's .observer/browser-host/
//     (the WindowsRegistrar's target — checked by file presence, never by
//     shelling reg.exe, so this probe stays read-only and registry-free);
//  2. has this tool's site recorded any capture activity in the node-local
//     browser-health.json heartbeat, and how fresh is it.
//
// Neither signal is StatusFail — a fresh install genuinely has neither yet,
// and the fix in both cases is one command (`observer init --browser`, or
// Settings > Browser capture in the dashboard), reported through fix as a
// structured remediation.
func browserExtensionHealthNote(tool string, cfg config.Config, note func(Status, string), fix func(remedy.Remediation)) {
	if ok, detail := browserManifestStatus(); ok {
		note(StatusOK, detail)
	} else {
		setup := remedy.Of(remedy.BrowserHostSetup, "")
		note(StatusWarn, detail+" - set it up in Settings > Browser capture, or run "+remedy.Quote(setup)+" to write it")
		if fix != nil {
			fix(setup)
		}
	}

	ok, detail := browserHeartbeatStatus(tool, cfg)
	if ok {
		note(StatusOK, detail)
	} else {
		note(StatusWarn, detail)
	}
}

// browserManifestsFn resolves the dir-based (Linux/macOS) native-messaging
// manifest presence for every browser observer has a grounded location for
// on this host. A package-level var (mirroring launchResolve/adapterDetected
// elsewhere in this package) so tests inject a fake instead of statting the
// real machine's browser profile dirs.
var browserManifestsFn = func() []browserhost.ManifestStatus {
	reg, err := browserhost.NewRegistrar(browserhost.Options{})
	if err != nil {
		return nil
	}
	return reg.Manifests()
}

// browserWindowsHomesFn resolves cross-mounted Windows homes — the WSL
// daemon + Windows-side browser topology the dir-based check above cannot
// see. Production wires crossmount.AllHomes(); tests inject a fake so
// nothing here touches the real machine's home directories.
var browserWindowsHomesFn = crossmount.AllHomes

// browserStatExistsFn reports whether path exists. A package-level var
// (production: os.Stat) so tests never touch the real filesystem.
var browserStatExistsFn = func(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// browserManifestStatus reports whether a native-messaging host manifest is
// registered for at least one Chromium-family browser, across both
// topologies observer supports: dir-based (the daemon's own host OS) and the
// cross-mounted Windows-side manifest a WSL daemon writes. It never shells
// out to reg.exe — the Windows signal is the manifest FILE the
// WindowsRegistrar itself writes before setting the registry key, so file
// presence is the same ground truth the registry entry points at, checked
// read-only.
func browserManifestStatus() (ok bool, detail string) {
	var registered, seen []string
	for _, m := range browserManifestsFn() {
		seen = append(seen, m.Browser)
		if m.Present {
			registered = append(registered, m.Browser)
		}
	}
	for _, h := range browserWindowsHomesFn() {
		if h.OS != crossmount.OSWindows {
			continue
		}
		dir, err := browserhost.HostInstallDir(h.Path)
		if err != nil {
			continue
		}
		path := filepath.Join(dir, browserhost.WindowsManifestName)
		if browserStatExistsFn(path) {
			registered = append(registered, "windows("+filepath.Base(h.Path)+")")
		}
	}
	if len(registered) > 0 {
		return true, "native-messaging host manifest registered: " + strings.Join(registered, ", ")
	}
	if len(seen) > 0 {
		return false, "browser(s) detected on this host (" + strings.Join(seen, ", ") + ") but no native-messaging host manifest found"
	}
	return false, "no native-messaging host manifest found for any Chromium-family browser"
}

// browserHealthFileName is the node-local file the extension's capture
// telemetry + health beacon land in, next to the observer DB. Must match
// cmd/observer/browser.go::browserHealthFileName — duplicated rather than
// imported because internal/diag cannot import package main.
const browserHealthFileName = "browser-health.json"

// browserHeartbeatStaleAfter is how long since a site's last recorded
// activity (ingest OR drop — either is proof of life) before the doctor
// reports it as stale rather than live. Generous: a quiet chat site between
// sessions is normal, not a fault.
const browserHeartbeatStaleAfter = 7 * 24 * time.Hour

// browserHealthEntryMinimal is the subset of cmd/observer's
// browserHealthEntry the doctor needs: status + the daemon-side liveness
// timestamp. Deliberately minimal (not a full mirror) — this file only ever
// reads, never writes, the health file.
type browserHealthEntryMinimal struct {
	Status     string `json:"status"`
	RecordedAt int64  `json:"recorded_at"`
	Ingested   int64  `json:"ingested"`
	Dropped    int64  `json:"dropped"`
}

// browserHealthFileMinimal mirrors cmd/observer's browserHealthFile shape
// (sites keyed by site — which is the SAME string as the *-web tool name,
// e.g. "chatgpt-web"; see internal/adapter/browserchat/doc.go).
type browserHealthFileMinimal struct {
	Sites map[string]browserHealthEntryMinimal `json:"sites"`
}

// browserHealthNowFn yields the current instant for freshness math. A
// package-level var so tests pin a deterministic clock instead of racing
// real wall-clock time.
var browserHealthNowFn = time.Now

// browserHeartbeatStatus reports whether tool's site has recorded any
// capture activity in the node-local browser-health.json, and whether that
// activity is fresh. tool is used directly as the site key (the *-web
// adapters' registry name IS the site string the extension sends — see
// models.ToolChatGPTWeb == "chatgpt-web" etc).
func browserHeartbeatStatus(tool string, cfg config.Config) (ok bool, detail string) {
	dbPath := strings.TrimSpace(cfg.Observer.DBPath)
	if dbPath == "" {
		return false, "no observer DB path configured - cannot locate browser-health.json"
	}
	path := filepath.Join(filepath.Dir(dbPath), browserHealthFileName)
	raw, err := os.ReadFile(path) //nolint:gosec // G304: path is <observer dir>/browser-health.json, config-derived, not user input.
	if err != nil {
		return false, fmt.Sprintf("no browser-health.json found at %s yet - capture a chat turn on %s to confirm the extension is connected", path, tool)
	}
	var hf browserHealthFileMinimal
	if err := json.Unmarshal(raw, &hf); err != nil {
		return false, fmt.Sprintf("%s exists but could not be parsed: %v", path, err)
	}
	e, found := hf.Sites[tool]
	if !found {
		return false, fmt.Sprintf("no capture activity recorded yet for %s in %s - capture a chat turn on the site to confirm the extension → daemon pipe is live", tool, path)
	}
	age := browserHealthNowFn().Sub(time.UnixMilli(e.RecordedAt))
	status := e.Status
	if status == "" {
		status = "unknown"
	}
	summary := fmt.Sprintf("browser-health.json: status=%s, last activity %s ago, ingested=%d, dropped=%d",
		status, age.Round(time.Second), e.Ingested, e.Dropped)
	if age > browserHeartbeatStaleAfter {
		return false, summary + " - stale (no activity in over a week); confirm the extension is still installed and enabled for this site"
	}
	if status == "degraded" {
		return false, summary + " - extension reports degraded status"
	}
	return true, summary
}
