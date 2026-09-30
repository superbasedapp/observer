package diag

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cursorusage"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// checkCursorHooks reports whether Cursor's hooks.json — the native
// $HOME/.cursor/hooks.json and any cross-mounted Windows-side copy a WSL
// daemon bridges into — is wired through the observer registrar cleanly.
//
// It exists because of a live incident: a lost, never-committed
// 2026-09-08 observer build wrote hook entries that POSTed payloads to a
// loopback HTTP route (`/api/cursor/hook/<event>`) that no committed
// build has ever served. The dashboard's SPA fallback answers every such
// POST with a 200 text/html, so every event wired that way silently drops
// — and because that shape didn't match the registrar's own
// `hook cursor <event>` signature, it used to be classified as a foreign
// hook, so auto-register on `observer start` refused to heal it without
// --force (see hook.IsOrphanedObserverCursorHTTPHook, which this check
// reuses so the FAIL condition here can never drift from what the
// registrar itself now self-heals).
//
// Each home's hooks.json is classified per event into one of three
// buckets: canonical (a command containing " hook cursor <event>" —
// either the native invocation or the wsl.exe cross-OS bridge, both of
// which carry that exact token sequence), orphaned observer HTTP (the
// lost-build shape above), or foreign (anything else, including a
// genuinely user-authored hook). Status:
//
//   - StatusFail when any home's hooks.json carries an orphaned HTTP
//     entry for any event — those events are actively being dropped;
//   - StatusWarn when no orphaned entry exists but some of
//     hook.CursorEvents() has no observer entry (canonical or orphaned)
//     at all — that event was never registered;
//   - StatusOK otherwise, including "cursor not installed" when no home
//     carries a hooks.json at all.
//
// Pure file inspection: it never writes hooks.json and never opens the
// observer DB. Like checkClaudeCodePlugin's Windows probe, it honours the
// caller's sandbox — homeOverride non-empty (a sandboxed doctor run, e.g.
// under test) suppresses cross-mount auto-detection
// (crossmount.AutoDetectSuppressed) so a sandboxed run never reads a real
// foreign-OS home.
//
// Named with the "cursor.hooks" substring so `observer doctor cursor`
// scopes to it (Report.Filter matches on Name).
func checkCursorHooks(homeDir, homeOverride string) Check {
	const name = "cursor.hooks"

	files := cursorHooksFiles(homeDir, homeOverride)
	if len(files) == 0 {
		return Check{Name: name, Status: StatusOK, Message: "cursor not installed"}
	}

	var details []string
	var droppedFrom []string
	var incomplete []string
	for _, f := range files {
		if f.readErr != nil {
			// A read/parse failure means coverage for this file can't be
			// confirmed at all — treated the same as every event missing
			// (f.missingEvents is pre-populated with the full list by
			// inspectCursorHooksFile) rather than silently reported as
			// clean. Still surfaces the underlying error in Details.
			details = append(details, fmt.Sprintf("%s (%s): %v", f.path, f.origin, f.readErr))
		} else {
			details = append(details, fmt.Sprintf(
				"%s (%s): %d canonical, %d orphaned-http, %d foreign, %d/%d events covered",
				f.path, f.origin, f.canonical, f.orphanedHTTP, f.foreign,
				len(hook.CursorEvents())-len(f.missingEvents), len(hook.CursorEvents()),
			))
		}
		if f.orphanedHTTP > 0 {
			droppedFrom = append(droppedFrom, fmt.Sprintf("%s (%s)", f.path, f.origin))
		}
		if len(f.missingEvents) > 0 {
			incomplete = append(incomplete, fmt.Sprintf("%s (%s): missing %s",
				f.path, f.origin, strings.Join(f.missingEvents, ", ")))
		}
	}

	if len(droppedFrom) > 0 {
		details = append(details,
			"fix: restart the daemon so auto-register heals the orphaned entries on its own "+
				"(no --force needed), or run `observer init --cursor --force` yourself",
		)
		return Check{
			Name:   name,
			Status: StatusFail,
			Message: fmt.Sprintf(
				"Cursor events from %s are being dropped — hooks.json still carries the orphaned "+
					"observer HTTP-hook shape from a lost build (this build serves no /api/cursor/hook/ route; "+
					"the dashboard's SPA fallback answers it with HTML)",
				strings.Join(droppedFrom, ", "),
			),
			Details: details,
		}
	}

	if len(incomplete) > 0 {
		details = append(details, incomplete...)
		return Check{
			Name:    name,
			Status:  StatusWarn,
			Message: "some Cursor hook events have no observer entry — run `observer init --cursor` to register them",
			Details: details,
		}
	}

	return Check{
		Name:    name,
		Status:  StatusOK,
		Message: "Cursor hooks wired for every event",
		Details: details,
	}
}

// cursorHooksFiles inspects every Cursor hooks.json this doctor can see:
// the native $HOME/.cursor/hooks.json plus, unless the run is sandboxed
// (homeOverride non-empty), each cross-mounted foreign-OS home's copy. A
// home without a hooks.json contributes nothing. The one home walk shared by
// checkCursorHooks and CursorFinishHooksWiring, so the doctor line and the
// usage note can never disagree about what is registered.
func cursorHooksFiles(homeDir, homeOverride string) []cursorHooksFileResult {
	nativePath := filepath.Join(homeDir, ".cursor", "hooks.json")
	var files []cursorHooksFileResult
	if res, ok := inspectCursorHooksFile(nativePath, "native"); ok {
		files = append(files, res)
	}

	if !crossmount.AutoDetectSuppressed(homeOverride, "") {
		seen := map[string]bool{nativePath: true}
		for _, h := range crossmount.AllHomes() {
			if h.Origin == "native" {
				continue
			}
			p := filepath.Join(h.Path, ".cursor", "hooks.json")
			if seen[p] {
				continue
			}
			seen[p] = true
			if res, ok := inspectCursorHooksFile(p, fmt.Sprintf("%s cross-mount", h.OS)); ok {
				files = append(files, res)
			}
		}
	}
	return files
}

// CursorFinishHooksWiring reports whether the Cursor hook events that carry
// usage (cursorusage.FinishHookEvents: stop and afterAgentResponse) are
// registered through the observer registrar in any hooks.json this node can
// see. It is the registration-state input internal/cursorusage needs to pick
// an honest remedy for a Cursor session with no captured usage: re-running
// `observer init --cursor` is advice only when those hooks are NOT
// registered. An event counts only with a canonical `hook cursor <event>`
// entry (an orphaned HTTP-shape entry drops the event, so it does not
// count). HookWiringComplete when some hooks.json wires every finish event;
// HookWiringIncomplete otherwise, including when no hooks.json exists.
//
// homeOverride is the caller's sandbox home ("" in production = the real
// $HOME, with cross-mount auto-detection on). Read-only file inspection.
func CursorFinishHooksWiring(homeOverride string) cursorusage.HookWiring {
	homeDir := homeOverride
	if homeDir == "" {
		if h, err := os.UserHomeDir(); err == nil {
			homeDir = h
		}
	}
	return cursorFinishHooksWiring(cursorHooksFiles(homeDir, homeOverride))
}

// cursorFinishHooksWiring folds inspected hooks.json files into the wiring
// state (see CursorFinishHooksWiring).
func cursorFinishHooksWiring(files []cursorHooksFileResult) cursorusage.HookWiring {
	for _, f := range files {
		if f.readErr != nil {
			continue
		}
		all := true
		for _, ev := range cursorusage.FinishHookEvents {
			if !f.canonicalEvents[ev] {
				all = false
				break
			}
		}
		if all {
			return cursorusage.HookWiringComplete
		}
	}
	return cursorusage.HookWiringIncomplete
}

// cursorHooksFileResult is the per-hooks.json tally checkCursorHooks
// composes into one Check.
type cursorHooksFileResult struct {
	path          string
	origin        string
	canonical     int
	orphanedHTTP  int
	foreign       int
	missingEvents []string
	// canonicalEvents is the set of events carrying a canonical
	// `hook cursor <event>` entry (the finish-hook wiring input).
	canonicalEvents map[string]bool
	readErr         error
}

// inspectCursorHooksFile reads and classifies one hooks.json. ok is
// false only when the file doesn't exist — nothing to report for that
// home. A genuine read or parse error is still reported (ok true, res
// carrying readErr) rather than silently skipped: it marks every event
// as missing, since coverage can't be confirmed at all, so a corrupt
// hooks.json surfaces as an incomplete-coverage WARN plus the underlying
// error in Details rather than a false "wired for every event" OK.
func inspectCursorHooksFile(path, origin string) (res cursorHooksFileResult, ok bool) {
	res = cursorHooksFileResult{path: path, origin: origin}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return res, false
		}
		res.readErr = err
		res.missingEvents = hook.CursorEvents()
		return res, true
	}
	var settings struct {
		Hooks map[string][]struct {
			Command string `json:"command"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(raw, &settings); err != nil {
		res.readErr = err
		res.missingEvents = hook.CursorEvents()
		return res, true
	}

	for _, event := range hook.CursorEvents() {
		var hasObserverEntry bool
		for _, e := range settings.Hooks[event] {
			switch {
			case strings.Contains(e.Command, " hook cursor "+event):
				res.canonical++
				hasObserverEntry = true
				if res.canonicalEvents == nil {
					res.canonicalEvents = map[string]bool{}
				}
				res.canonicalEvents[event] = true
			case hook.IsOrphanedObserverCursorHTTPHook(e.Command):
				res.orphanedHTTP++
				hasObserverEntry = true
			default:
				res.foreign++
			}
		}
		if !hasObserverEntry {
			res.missingEvents = append(res.missingEvents, event)
		}
	}
	return res, true
}
