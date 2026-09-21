package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/remoteauth"
)

// capLetter maps the compact test letters to Capability values.
func capLetter(t *testing.T, letter string) Capability {
	t.Helper()
	switch letter {
	case "P":
		return CapabilityPublic
	case "V":
		return CapabilityView
	case "L":
		return CapabilityLocal
	case "X":
		return CapabilityExecute
	}
	t.Fatalf("unknown capability letter %q", letter)
	return CapabilityUnclassified
}

// expectedClassification is the AUTHORITATIVE route→capability table
// (dashboard-management-surface plan §9.3, realised as whole-route classes — see
// the mechanism note in registerRoutes). It is the source of truth
// TestFullRegistryClassification asserts capMap against exactly: a new route
// added without a classification decision fails the build, and any drift is
// loud. P=public, V=view, L=owner-local-only, X=execute.
var expectedClassification = map[string]string{
	"/":                                 "P",
	"/api/action/":                      "V",
	"/api/actions":                      "V",
	"/api/actions/day-counts":           "V",
	"/api/admin/antigravity-bridge.exe": "V",
	"/api/admin/restart":                "L",
	"/api/analysis/cache-savings-trend": "V",
	"/api/analysis/cost-by-dow-hour":    "V",
	"/api/analysis/cost-by-hour":        "V",
	"/api/analysis/headline":            "V",
	"/api/analysis/movers":              "V",
	"/api/analysis/routing-suggestions": "V",
	"/api/analysis/top-sessions":        "V",
	"/api/analysis/trend":               "V",
	// Admin-authored banner copy, identical for every viewer of this
	// dashboard — no install state, nothing sensitive.
	"/api/announcements":      "V",
	"/api/attach/sessions":    "V",
	"/api/backfill/jobs":      "V",
	"/api/backfill/jobs/":     "V",
	"/api/backfill/run":       "L",
	"/api/backfill/status":    "V",
	"/api/benchmarks":         "V",
	"/api/benchmarks/":        "V",
	"/api/budget":             "V",
	"/api/cache/entry-states": "V",
	"/api/cache/events":       "V",
	"/api/cache/health":       "V",
	"/api/cache/overview":     "V",
	"/api/cache/status":       "V",
	"/api/cache/timeseries":   "V",
	"/api/cloud/login":        "L",
	"/api/cloud/login/state":  "L",
	"/api/cloud/logout":       "L",
	// Cloud Intelligence actions (dashboard parity, 2026-09-14): every one
	// spawns the consent-gated `observer cloud …` CLI on THIS machine or reads
	// consent receipts — owner-loopback only, never remotely reachable.
	"/api/cloud/consent":        "L",
	"/api/cloud/consent/grant":  "L",
	"/api/cloud/consent/grants": "L",
	"/api/cloud/consent/revoke": "L",
	"/api/cloud/delete-account": "L",
	"/api/cloud/preview":        "L",
	"/api/cloud/sync":           "L",
	"/api/cloud/sync/state":     "L",
	"/api/cloud/session/":       "V",
	"/api/cloud/status":         "V",
	// Cloud Intelligence value-upgrade (2026-09-15): the standing Turn on /
	// Turn off actions are the same owner-loopback CLI-runner shape as the
	// other cloud actions above; the ledger is a pure store read like
	// /api/cloud/session/ and /api/cloud/status.
	"/api/cloud/enable":  "L",
	"/api/cloud/disable": "L",
	"/api/cloud/ledger":  "V",
	// Cloud Intelligence value-upgrade W3 (2026-09-15): the Sessions-page
	// toast/banner poll is a pure store read, same class as /api/cloud/status.
	"/api/cloud/events": "V",
	// Cloud Intelligence value-upgrade W5 (2026-09-15): the weekly project
	// digests `observer cloud sync` pulled back are a pure store read, same
	// class as /api/cloud/status.
	"/api/cloud/digests":            "V",
	"/api/codex/support":            "V",
	"/api/compaction/events":        "V",
	"/api/compression/by-model":     "V",
	"/api/compression/events":       "V",
	"/api/compression/retrieval":    "V",
	"/api/compression/rolling-cost": "V",
	"/api/compression/timeseries":   "V",
	"/api/config":                   "V",
	"/api/config/backup":            "L",
	"/api/config/keys":              "L", // generic batched dotted-key config write (dashboard-config-management plan §2.2)
	"/api/config/schema":            "L", // the owner-local settings schema that drives /keys
	"/api/config/pricing":           "L",
	"/api/config/pricing/defaults":  "V",
	"/api/config/profiles":          "L",
	"/api/config/profiles/":         "L",
	"/api/config/reload":            "L",
	"/api/config/section/":          "L",
	"/api/cost":                     "V",
	"/api/cowork/reconcile":         "V",
	"/api/demo":                     "V",
	"/api/demo/start":               "L",
	"/api/demo/stop":                "L",
	"/api/discover":                 "V",
	"/api/enrolment/last-payload":   "V",
	// Mints a credential on the ORG server (never touching this machine's
	// config or filesystem) — a real mutation at the Execute tier, the same
	// class as /api/sessions/tags/manage.
	"/api/enrolment/invite": "X",
	"/api/enrolment/status": "V",
	// Admin-controlled Plane B: the node's own governance posture. VIEW —
	// it is metadata about what this machine's organization hid, and a
	// paired remote owner sees the same managed dashboard the owner does.
	"/api/governance":              "V",
	"/api/enrolment/unenroll":      "L",
	"/api/experiments":             "L",
	"/api/experiments/report":      "V",
	"/api/experiments/stop":        "L",
	"/api/export.xlsx":             "V",
	"/api/file/state":              "V",
	"/api/guard/approvals":         "L",
	"/api/guard/approvals/":        "L",
	"/api/guard/budget":            "V",
	"/api/guard/conformance":       "V",
	"/api/guard/events":            "V",
	"/api/guard/evidence":          "L",
	"/api/guard/evidence/download": "V",
	"/api/guard/mcp":               "V",
	"/api/guard/mcp/approve":       "L",
	"/api/guard/policy":            "L",
	"/api/guard/policy/project":    "L",
	"/api/guard/policy/backup":     "L",
	"/api/guard/policy/lint":       "V",
	"/api/guard/prompt/allow/":     "L",
	"/api/guard/prompt/clear":      "L",
	"/api/guard/prompt/detectors":  "V",
	"/api/guard/prompt/events":     "V",
	"/api/guard/prompt/probe":      "L",
	"/api/guard/prompt/status":     "V",
	"/api/guard/rules":             "V",
	"/api/guard/simulate":          "V",
	"/api/guard/summary":           "V",
	"/api/health/doctor":           "V",
	"/api/health/failures":         "V",
	"/api/health/watcher":          "V",
	// Instance switcher — same class and the same reasoning as
	// /api/terminal/ssh below: GET discloses the operator's configured remote
	// hostnames, and POST .../connect spawns an `ssh -N -L` child to a
	// THIRD-PARTY machine whose forward then answers on this machine's
	// loopback. Letting a paired phone drive that is a pivot, not a view.
	"/api/instances":  "L",
	"/api/instances/": "L",
	"/api/launch/":    "V",
	"/api/live":       "V",
	// Lines-of-code authorship. The summary READ is View like every other
	// reporting surface; the editor-change INGEST is owner-Local, because
	// a remote viewer must never be able to write authorship counts into
	// someone else's node.
	"/api/loc/summary":            "V",
	"/api/loc/editor-change":      "L",
	"/api/mcp/value":              "V",
	"/api/models":                 "V",
	"/api/patterns":               "V",
	"/api/patterns/timeseries":    "V",
	"/api/privacy/scrub-test":     "V",
	"/api/process/enable-capture": "L",
	// Detection only: reads config, runs the read-only `schtasks /Query`
	// probe, reads the daemon's own published health record. Registers
	// nothing, spawns nothing — the elevation broker is a separate route.
	"/api/process/etw/status": "V",
	// The elevation broker: spawns a fixed server-derived
	// `powershell.exe … Start-Process schtasks.exe -Verb RunAs` in a
	// local-only setup PTY. A UAC prompt is a LOCAL physical act, so this
	// must never be reachable by a paired remote device — owner-local only.
	"/api/process/etw/register": "L",
	"/api/process/findings":     "V",
	"/api/process/network/":     "V",
	"/api/projects":             "V",
	// Agent-guidance inventory: metadata reads over already-persisted rows.
	"/api/projects/guidance":         "V",
	"/api/projects/guidance/summary": "V",
	// The guidance file VIEWER returns a project file's scrubbed body. View-
	// tier like /api/terminal/project/<token>/file, and gated the same way
	// in-handler: a remote-exposed caller is refused without
	// [remote].allow_terminal_view.
	"/api/projects/guidance/file":             "V",
	"/api/prune/run":                          "L",
	"/api/remote/add-device":                  "L",
	"/api/remote/allow-terminal":              "L",
	"/api/remote/allow-terminal-view":         "L",
	"/api/remote/allow-remote-takeover":       "L",
	"/api/remote/standing-revoke-on-takeover": "L",
	"/api/remote/approve-execute":             "L",
	"/api/remote/audit":                       "V",
	"/api/remote/config":                      "V",
	"/api/remote/disable":                     "L",
	"/api/remote/enable":                      "L",
	"/api/remote/rotate":                      "L",
	"/api/remote/selfcheck":                   "V",
	"/api/remote/sessions":                    "V",
	"/api/remote/sessions/":                   "L",
	"/api/remote/sessions/revoke-all":         "L",
	"/api/remote/standing-terminal":           "V", // status read (never the secret)
	"/api/remote/standing-terminal/mint":      "L", // mint/rotate the standing secret — owner-local only
	"/api/remote/standing-terminal/revoke":    "L", // revoke standing access — owner-local only
	"/api/remote/tailscale/status":            "V",
	"/api/remote/tailscale/serve":             "L", // runs `tailscale serve` (machine mutation) — owner-local only
	"/api/remote/tailscale/operator-grant":    "L", // spawns `sudo tailscale set --operator` in a local-only PTY — owner-local only
	"/api/remote/tailscale/login":             "L", // spawns `tailscale up` in a local-only PTY — owner-local only
	"/api/remote/tailscale/install":           "L", // spawns the Linux install.sh in a local-only PTY — owner-local only
	"/api/report/monthly":                     "V",
	"/api/routing/apply":                      "L",
	"/api/routing/apply/ledger":               "V",
	"/api/routing/apply/revert":               "L",
	"/api/routing/decisions":                  "V",
	"/api/routing/health":                     "V",
	"/api/routing/policy":                     "V",
	"/api/routing/policy/lint":                "V",
	"/api/routing/savings":                    "V",
	"/api/routing/shadow":                     "V",
	"/api/routing/simulate":                   "V",
	"/api/routing/status":                     "V",
	"/api/routing/tiers":                      "V",
	"/api/scan/run":                           "L",
	"/api/search":                             "V",
	"/api/session/":                           "V",
	"/api/sessions":                           "V",
	"/api/sessions/calendar":                  "V",
	// Session classification (plan §4). The vocabulary + per-tag rollup is a
	// pure read; MANAGING the vocabulary (rename/delete across every session) is
	// a whole-route Execute mutation — user-authored review metadata a paired
	// remote owner legitimately drives, never machine-reaching config.
	"/api/sessions/tags":        "V",
	"/api/sessions/tags/manage": "X",
	// Custom tag definitions: GET reads the glossary (View); POST upserts one
	// (Execute-escalated on the same route, like /api/session/<id>/tags).
	"/api/tags/definitions":               "V",
	"/api/setup/claude":                   "L",
	"/api/setup/codex":                    "L",
	"/api/setup/codex-hooks":              "V",
	"/api/setup/hooks":                    "L",
	"/api/setup/mcp":                      "L",
	"/api/status":                         "V",
	"/api/status/scoped":                  "V",
	"/api/statusline":                     "V",
	"/api/storage":                        "V",
	"/api/storage/backup":                 "L",
	"/api/storage/vacuum":                 "L",
	"/api/suggest":                        "V",
	"/api/suggest/write":                  "L",
	"/api/suggestions":                    "V",
	"/api/suggestions/state":              "L",
	"/api/tasks":                          "V", // Phase-2 task-tracking project/tool/window rollup — read-side aggregate over already-captured actions/token_usage rows, same posture as /api/cache/status
	"/api/terminal/":                      "V",
	"/api/terminal/install":               "L", // spawns the registry-constant install command in a local-only setup PTY — owner-local only
	"/api/terminal/launch":                "X",
	"/api/terminal/launch/preflight":      "L", // runs a $SHELL -lc login-shell PATH capture + reveals binary paths/home layout — owner-local only (reclassified V→L, 2026-07-23 review)
	"/api/terminal/launch/models":         "V", // reads token_usage model history + registry Known list only — same posture as /api/models (B5 model picker)
	"/api/terminal/sandbox":               "V", // B9 fail-soft sandbox probe — reads the daemon's cached bwrap probe result + [terminal.sandbox] config only, same posture as /api/terminal/launch/models
	"/api/terminal/ssh":                   "L", // SSH remote-system terminals — GET discloses the operator's internal hostnames (the sessions.git_branch privacy class) and POST opens an interactive shell on a THIRD-PARTY machine; both stay owner-local until remote-driven SSH gets its own threat model (ssh-remote-profiles plan §6.2 / D1)
	"/api/terminal/sandbox/config":        "L", // owner-local editor for [terminal.sandbox], including remote-clone / extra-rw-bind authority expansion
	"/api/terminal/limits":                "L",
	"/api/terminal/policy":                "L",
	"/api/terminal/project/":              "V",
	"/api/terminal/session/":              "V",
	"/api/terminal/runs":                  "V",
	"/api/arena/runs":                     "V", // agent arena: GET list; POST create auto-escalates to X + confirm token in-handler
	"/api/arena/runs/{id}":                "V",
	"/api/arena/runs/{id}/diff/{cid}":     "V",
	"/api/arena/runs/{id}/action/{cid}":   "V", // keep/discard POST auto-escalates to X + confirm token in-handler
	"/api/terminal/sessions":              "V",
	"/api/terminal/workspace-layout":      "V",
	"/api/terminal/workspace-layout/save": "L",
	"/api/timeseries/actions":             "V",
	"/api/timeseries/cost":                "V",
	"/api/timeseries/tokens-by-model":     "V",
	"/api/tools":                          "V",
	"/api/tools/breakdown":                "V",
	"/api/tools/launch":                   "L",
	"/api/tools/status":                   "V",
	"/api/update/apply":                   "L",
	// W5 (enterprise update management). The STATUS read is View: it
	// discloses this node's own version and update state to a viewer who can
	// already see /api/status. The extension-version REPORT is Local: it is a
	// loopback report from an editor sharing this machine, exactly like
	// /api/loc/editor-change above, and never something a remote caller writes.
	"/api/update/extension-version": "L",
	"/api/update/status":            "V",
	"/api/verbosity/aggregate":      "V",
	"/ws/launch/":                   "V",
	"/ws/terminal/status":           "V",
}

// TestFullRegistryClassification is the codex-finding-2 backstop (plan §9): the
// WHOLE built-in capMap must match the authoritative table exactly. A new
// mutation route that lands as plain View — or any classification drift — fails
// the build.
func TestFullRegistryClassification(t *testing.T) {
	s := newRemoteTestServer(t, Options{})
	_, capMap, _ := s.registerRoutes(nil)

	for pattern, cap := range capMap {
		want, ok := expectedClassification[pattern]
		if !ok {
			t.Errorf("route %q is registered but NOT in the §9.3 classification table — classify it (public/view/local/execute) and add it to expectedClassification", pattern)
			continue
		}
		if cap != capLetter(t, want) {
			t.Errorf("route %q classified %s, want %s (§9.3)", pattern, cap, capLetter(t, want))
		}
	}
	for pattern := range expectedClassification {
		if _, ok := capMap[pattern]; !ok {
			t.Errorf("expected route %q from the §9.3 table is not registered", pattern)
		}
	}
}

// mutationRoutes is the set of built-in routes whose handler writes config,
// writes an AI-client file, or drives daemon lifecycle. Every one MUST be Local
// or Execute — never plain View (which would auto-escalate an unsafe method to
// Execute and become reachable by a remote execute principal). This is the §2A
// invariant. (Routes whose unsafe verb is DELIBERATELY Execute via bare-View
// auto-escalation — /api/launch/ DELETE, /api/session/ sub-routes — are covered
// by TestSessionSubRouteCapabilities + the remote authz matrix, not here.)
var mutationRoutes = []string{
	"/api/admin/restart",
	"/api/backfill/run",
	"/api/config/backup",
	"/api/config/keys",
	"/api/config/pricing",
	"/api/config/profiles",
	"/api/config/profiles/",
	"/api/config/reload",
	"/api/config/section/",
	"/api/demo/start",
	"/api/demo/stop",
	"/api/enrolment/invite",
	"/api/enrolment/unenroll",
	"/api/experiments",
	"/api/experiments/stop",
	"/api/guard/approvals",
	"/api/guard/approvals/",
	"/api/guard/evidence",
	"/api/guard/mcp/approve",
	"/api/guard/policy",
	"/api/guard/policy/project",
	"/api/guard/policy/backup",
	"/api/guard/prompt/allow/",
	"/api/guard/prompt/clear",
	"/api/guard/prompt/probe",
	"/api/process/enable-capture",
	// Spawns a privileged PTY that asks Windows for elevation — the same
	// class as the tailscale setup POSTs below.
	"/api/process/etw/register",
	"/api/prune/run",
	"/api/remote/allow-terminal",
	"/api/remote/allow-terminal-view",
	"/api/remote/allow-remote-takeover",
	"/api/remote/approve-execute",
	"/api/remote/standing-revoke-on-takeover",
	"/api/remote/standing-terminal/mint",
	"/api/remote/standing-terminal/revoke",
	// The tailscale guided-setup POSTs all reach the machine (run `tailscale
	// serve`, or spawn a privileged sudo PTY), so every one MUST be Local — not
	// merely present in the editable classification table (the review flagged
	// the two-source gap). serve + operator-grant were already Local; login +
	// install are the new arrivals.
	"/api/remote/tailscale/serve",
	"/api/remote/tailscale/operator-grant",
	"/api/remote/tailscale/login",
	"/api/remote/tailscale/install",
	"/api/routing/apply",
	"/api/routing/apply/revert",
	"/api/scan/run",
	// Vocabulary management writes session_tags across EVERY session (rename /
	// delete) — a real mutation, so it must never sit at plain View.
	"/api/sessions/tags/manage",
	"/api/setup/claude",
	"/api/setup/codex",
	"/api/setup/hooks",
	"/api/setup/mcp",
	"/api/storage/backup",
	"/api/storage/vacuum",
	"/api/suggest/write",
	"/api/suggestions/state",
	"/api/tools/launch",
	"/api/terminal/install",
	"/api/terminal/launch",
	"/api/terminal/limits",
	"/api/terminal/policy",
	"/api/update/apply",
	// W5: the extension's self-report mutates daemon state (the posture it
	// republishes), so it belongs in the mutation set. The sibling
	// /api/update/status is a pure read and deliberately is not.
	"/api/update/extension-version",
}

// TestNoConfigMutationRouteIsPlainView pins the §2A / §9.2 invariant: no route
// in the declared mutation set is left as plain View. Build-breaking and
// fail-closed.
func TestNoConfigMutationRouteIsPlainView(t *testing.T) {
	s := newRemoteTestServer(t, Options{})
	_, capMap, _ := s.registerRoutes(nil)
	for _, pattern := range mutationRoutes {
		cap, ok := capMap[pattern]
		if !ok {
			t.Errorf("mutation route %q not registered", pattern)
			continue
		}
		if cap != CapabilityLocal && cap != CapabilityExecute {
			t.Errorf("mutation route %q is %s — must be Local or Execute, never plain View (auto-escalation would expose it to a remote execute principal)", pattern, cap)
		}
	}
}

// TestLocalRoutesRefusedOnRemoteListener is the core §A safety property: a View
// AND an Execute principal both get 403 on every Local route on the
// remotely-exposed listener, while a Local route stays reachable on the direct
// loopback listener (which never runs remoteAuthz).
func TestLocalRoutesRefusedOnRemoteListener(t *testing.T) {
	rc, enc := newReadyRemoteController(t)
	s := newRemoteTestServer(t, Options{Remote: rc})
	remoteH := s.remoteGuardedHandler(rc)
	loopH := s.Handler() // direct loopback path — no remoteAuthz

	cookie, csrf := pairSession(t, remoteH, enc)
	mc := rc.(*remoteController)

	_, capMap, _ := s.registerRoutes(nil)
	type probe struct{ method, path string }
	var locals []probe
	for pattern, cap := range capMap {
		if cap != CapabilityLocal {
			continue
		}
		method := http.MethodPost
		path := pattern
		if m, p, found := strings.Cut(pattern, " "); found {
			method, path = m, p
		}
		if strings.HasSuffix(path, "/") {
			path += "probe"
		}
		locals = append(locals, probe{method, path})
	}
	if len(locals) < 15 {
		t.Fatalf("suspiciously few Local routes discovered (%d)", len(locals))
	}

	call := func(h http.Handler, method, path string, withCap bool) int {
		req := httptest.NewRequest(method, path, strings.NewReader("{}"))
		req.Host = testRemoteHost
		req.Header.Set("Origin", "https://"+testRemoteHost)
		req.AddCookie(cookie)
		req.Header.Set(remoteCSRFHeader, csrf)
		if withCap {
			tok, err := mc.MintExecute(cookie.Value, method+" "+path)
			if err != nil {
				t.Fatalf("MintExecute: %v", err)
			}
			req.Header.Set(remoteExecuteHeader, tok)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// Every Local route is refused on the remote listener for BOTH a view and an
	// execute principal. (We only probe authz — the handlers never execute, so
	// no real config-write/restart side effect fires.)
	for _, p := range locals {
		if code := call(remoteH, p.method, p.path, false); code != http.StatusForbidden {
			t.Errorf("view principal on Local route %s %s = %d, want 403", p.method, p.path, code)
		}
		if code := call(remoteH, p.method, p.path, true); code != http.StatusForbidden {
			t.Errorf("execute principal on Local route %s %s = %d, want 403 (Local is orthogonal to the ladder)", p.method, p.path, code)
		}
	}

	// Direct loopback listener: a Local route is NOT gated by capability there
	// (browserGuard only — Local is metadata). Probe ONE benign Local write
	// (/api/suggestions/state, writes only node-local advisor state to the test
	// DB) and assert it is not refused by an authz 401/403: it reaches its
	// handler. Executing restart/vacuum/etc. on loopback would fire real side
	// effects, so we deliberately probe only this safe route.
	{
		body := `{"dedup_key":"local-class-test","status":"dismissed"}`
		req := httptest.NewRequest(http.MethodPost, "/api/suggestions/state", strings.NewReader(body))
		req.Host = "127.0.0.1:8080"
		rec := httptest.NewRecorder()
		loopH.ServeHTTP(rec, req)
		if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
			t.Errorf("loopback listener refused a Local route (%d) — Local routes must stay open on the owner-trusted listener", rec.Code)
		}
	}
}

// TestLocalRouteNeverConsumesExecuteCapability pins the funnel-parity guarantee
// (plan §A): a Local-route refusal must NOT consume a single-use execute
// capability (the refusal happens before the principal is resolved).
func TestLocalRouteNeverConsumesExecuteCapability(t *testing.T) {
	rc, enc := newReadyRemoteController(t)
	s := newRemoteTestServer(t, Options{Remote: rc})
	h := s.remoteGuardedHandler(rc)
	cookie, csrf := pairSession(t, h, enc)
	mc := rc.(*remoteController)

	action := http.MethodPost + " /api/scan/run"
	tok, err := mc.MintExecute(cookie.Value, action)
	if err != nil {
		t.Fatalf("MintExecute: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/scan/run", strings.NewReader("{}"))
	req.Host = testRemoteHost
	req.Header.Set("Origin", "https://"+testRemoteHost)
	req.AddCookie(cookie)
	req.Header.Set(remoteCSRFHeader, csrf)
	req.Header.Set(remoteExecuteHeader, tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("Local route with an execute capability = %d, want 403", rec.Code)
	}
	// Capabilities are keyed by the session HASH (matching Principal's Consume),
	// so verify survival with the same currency MintExecute used.
	if !mc.caps.Consume(tok, remoteauth.HashSessionID(cookie.Value), action) {
		t.Error("execute capability was consumed by a refused Local-route request — it must survive (funnel-parity)")
	}
}

// TestSessionSubRouteCapabilities enumerates the /api/session/ suffix table
// (plan §9.1): every mutating sub-route resolves to an explicit Execute tier,
// and none is Local (a Local sub-route would need its own pattern).
func TestSessionSubRouteCapabilities(t *testing.T) {
	if len(sessionSubRouteCapabilities) == 0 {
		t.Fatal("sessionSubRouteCapabilities is empty — the /api/session/ mutating sub-routes must be enumerated")
	}
	// Explicit membership pin: adding OR removing a mutating session sub-route
	// is a classification decision, so it must be made here too. /tags joined
	// the set with session classification (plan §4).
	wantSuffixes := map[string]struct{}{
		"/handoff": {},
		"/launch":  {},
		"/resume":  {},
		"/tags":    {},
	}
	for suffix := range wantSuffixes {
		if _, ok := sessionSubRouteCapabilities[suffix]; !ok {
			t.Errorf("expected mutating session sub-route %q is missing from sessionSubRouteCapabilities", suffix)
		}
	}
	for suffix := range sessionSubRouteCapabilities {
		if _, ok := wantSuffixes[suffix]; !ok {
			t.Errorf("session sub-route %q is registered but not in the pinned set — classify it here", suffix)
		}
	}
	for suffix, cap := range sessionSubRouteCapabilities {
		if !strings.HasPrefix(suffix, "/") {
			t.Errorf("sub-route suffix %q must start with '/'", suffix)
		}
		if cap != CapabilityExecute {
			t.Errorf("/api/session/…%s is %s — mutating session sub-routes are Execute (a Local sub-route needs a dedicated pattern)", suffix, cap)
		}
	}
}

// TestConfigAndSSHRoutesAreLocal is the dashboard-config-management plan's
// §4.4 assertion (P0-10): every /api/config/* pattern and every
// /api/terminal/ssh* pattern is CapabilityLocal, so a future refactor cannot
// quietly demote a config mutation to View. The two enumerated read-only
// exceptions are the only /api/config/* routes a paired remote viewer may
// use: the config READ itself (§2A, redacted) and the baked-in pricing
// defaults (no install state).
func TestConfigAndSSHRoutesAreLocal(t *testing.T) {
	s := newRemoteTestServer(t, Options{})
	_, capMap, _ := s.registerRoutes(nil)
	viewAllowed := map[string]bool{
		"/api/config":                  true,
		"/api/config/pricing/defaults": true,
	}
	var seenKeys, seenSchema, seenSSH bool
	for pattern, cap := range capMap {
		switch {
		case strings.HasPrefix(pattern, "/api/config"):
			if viewAllowed[pattern] {
				continue
			}
			if cap != CapabilityLocal {
				t.Errorf("%s is %s — every /api/config/* route must be Local", pattern, cap)
			}
			seenKeys = seenKeys || pattern == "/api/config/keys"
			seenSchema = seenSchema || pattern == "/api/config/schema"
		case strings.HasPrefix(pattern, "/api/terminal/ssh"):
			if cap != CapabilityLocal {
				t.Errorf("%s is %s — every /api/terminal/ssh* route must be Local", pattern, cap)
			}
			seenSSH = true
		}
	}
	if !seenKeys || !seenSchema || !seenSSH {
		t.Errorf("expected /api/config/keys, /api/config/schema and /api/terminal/ssh to be registered (keys=%v schema=%v ssh=%v)", seenKeys, seenSchema, seenSSH)
	}
}
