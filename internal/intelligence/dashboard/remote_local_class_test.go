//go:build !sbo_omit_remote

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
	// AI tool settings (agentconfig.go): the reads open the developer's own
	// vendor files, so only the catalogue coverage is View.
	"/api/agent-config/coverage":              "V",
	"/api/agent-config/tools":                 "L",
	"/api/agent-config/tool":                  "L",
	"/api/agent-config/file":                  "L",
	"/api/agent-config/common":                "L",
	"/api/agent-config/instructions":          "L",
	"/api/agent-config/instructions/new-path": "L",
	"/api/agent-config/history":               "L",
	"/api/agent-config/org":                   "L",
	"/api/agent-config/org/apply":             "L",
	"/api/agent-config/preview":               "L",
	"/api/agent-config/save":                  "L",
	"/api/agent-config/common/preview":        "L",
	"/api/agent-config/common/save":           "L",
	"/api/analysis/cache-savings-trend":       "V",
	"/api/analysis/cost-by-dow-hour":          "V",
	"/api/analysis/cost-by-hour":              "V",
	"/api/analysis/headline":                  "V",
	"/api/analysis/movers":                    "V",
	"/api/analysis/routing-suggestions":       "V",
	"/api/analysis/top-sessions":              "V",
	"/api/analysis/trend":                     "V",
	// Admin-authored banner copy, identical for every viewer of this
	// dashboard — no install state, nothing sensitive.
	"/api/announcements": "V",
	// The org's verified developer cost-display choice (dollars or token
	// usage); identical for every viewer, nothing about this install.
	"/api/cost-display":       "V",
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
	// Cloud Intelligence parity (org plane, design 3.7): the status read is a
	// view (it mints the confirm token like /api/enrolment/manage); accept and
	// withdraw write this machine's config and consent record, owner-local.
	"/api/intel/status":   "V",
	"/api/intel/accept":   "L",
	"/api/intel/withdraw": "L",
	// Parity phase 3 (design 3.2): the per-session state is a read; enrich
	// queues and sends one submission, owner-local. The preview (evidence
	// bytes) and the ledger (what was sent) are owner-local like their
	// personal-plane twin /api/cloud/preview (review M3-13).
	"/api/intel/session/": "V",
	"/api/intel/preview":  "L",
	"/api/intel/enrich":   "L",
	"/api/intel/ledger":   "L",
	// T-490: a signed, audited pull from the org on the developer's behalf.
	"/api/intel/digests": "L",
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
	"/api/cloud/digests":              "V",
	"/api/codex/support":              "V",
	"/api/compaction/events":          "V",
	"/api/compression/by-model":       "V",
	"/api/compression/events":         "V",
	"/api/compression/retrieval":      "V",
	"/api/compression/rolling-cost":   "V",
	"/api/compression/timeseries":     "V",
	"/api/config":                     "V",
	"/api/config/backup":              "L",
	"/api/config/keys":                "L", // generic batched dotted-key config write (dashboard-config-management plan §2.2)
	"/api/config/schema":              "L", // the owner-local settings schema that drives /keys
	"/api/config/pricing":             "L",
	"/api/config/pricing/defaults":    "V",
	"/api/config/profiles":            "L",
	"/api/config/profiles/":           "L",
	"/api/config/profile-assignments": "L", // per-tool profile assignment (T-369)
	"/api/config/project-profiles":    "L", // per-project profile assignment (T-421 item 1): writes a repo file
	"/api/config/reload":              "L",
	"/api/config/section/":            "L",
	"/api/cost":                       "V",
	"/api/plans":                      "L",
	"/api/plans/accounts":             "L",
	"/api/plans/accounts/":            "L",
	"/api/plans/optin":                "L",
	"/api/plans/probe":                "L",
	"/api/plans/statusline":           "L",
	"/api/cowork/reconcile":           "V",
	"/api/demo":                       "V",
	"/api/demo/start":                 "L",
	"/api/demo/stop":                  "L",
	"/api/discover":                   "V",
	"/api/enrolment/last-payload":     "V",
	// Mints a credential on the ORG server (never touching this machine's
	// config or filesystem) — a real mutation at the Execute tier, the same
	// class as /api/sessions/tags/manage.
	"/api/enrolment/invite": "X",
	"/api/enrolment/status": "V",
	// Admin-controlled Plane B: the node's own governance posture. VIEW —
	// it is metadata about what this machine's organization hid, and a
	// paired remote owner sees the same managed dashboard the owner does.
	"/api/governance": "V",
	// Modular packaging (MP-CAT, MP-DASH): the read-only component catalog
	// and the node's component state are VIEW; every Settings > Components
	// write (selection, teardown of other tools' config, purge of local
	// rows) is LOCAL behind the confirm token.
	"/api/components":               "V",
	"/api/components/sbom":          "V",
	"/api/components/state":         "V",
	"/api/components/preview":       "L",
	"/api/components/apply":         "L",
	"/api/components/teardown":      "L",
	"/api/components/purge/preview": "L",
	"/api/components/purge/execute": "L",
	"/api/enrolment/unenroll":       "L",
	// Settings > Enrolment management (backlog item 6): enrol, consent,
	// status, grant report, push now and leave. All LOCAL: they hold or mint
	// this machine's org credential, write config.toml and record consent,
	// which only the person at this machine may do (the CLI's own rule).
	"/api/enrolment/manage":         "L",
	"/api/enrolment/grant":          "L",
	"/api/enrolment/probe":          "L",
	"/api/enrolment/enrol":          "L",
	"/api/enrolment/grant-decision": "L",
	"/api/enrolment/idp/start":      "L",
	"/api/enrolment/idp/poll":       "L",
	"/api/enrolment/push-now":       "L",
	"/api/enrolment/share-history":  "L",
	"/api/enrolment/resync":         "L",
	"/api/enrolment/leave":          "L",
	"/api/experiments":              "L",
	"/api/experiments/report":       "V",
	"/api/experiments/stop":         "L",
	"/api/export.xlsx":              "V",
	"/api/file/state":               "V",
	"/api/guard/approvals":          "L",
	"/api/guard/approvals/":         "L",
	"/api/guard/budget":             "V",
	// The org warn ladder's status (budget-status.json): the same numbers
	// /api/guard/budget's org_budget block serves, so the same View class.
	"/api/budget/status": "V",
	// T-206: the same payload as a server-sent event stream.
	"/api/budget/status/stream":    "V",
	"/api/guard/conformance":       "V",
	"/api/guard/events":            "V",
	"/api/guard/hook-coverage":     "V",
	"/api/guard/hook-doctor":       "L",
	"/api/guard/hook-probe":        "L",
	"/api/guard/evidence":          "L",
	"/api/guard/evidence/download": "V",
	// Guard tools (T-154): the dry run is a read (fresh engines, nothing
	// persists); the job routes run `guard rescan|compile|mcp scan|report`.
	"/api/guard/test":                     "V",
	"/api/guard/jobs/policy":              "L",
	"/api/guard/jobs/mcp":                 "L",
	"/api/guard/mcp":                      "V",
	"/api/guard/mcp/approve":              "L",
	"/api/guard/mcp/reputation":           "L",
	"/api/guard/policy":                   "L",
	"/api/guard/policy/project":           "L",
	"/api/guard/policy/backup":            "L",
	"/api/guard/policy/lint":              "V",
	"/api/guard/prompt/allow/":            "L",
	"/api/guard/prompt/clear":             "L",
	"/api/guard/prompt/detectors":         "V",
	"/api/guard/prompt/events":            "V",
	"/api/guard/prompt/probe":             "L",
	"/api/guard/prompt/status":            "V",
	"/api/guard/rules":                    "V",
	"/api/guard/simulate":                 "V",
	"/api/requests":                       "L",
	"/api/requests/":                      "L",
	"/api/messages":                       "L",
	"/api/messages/":                      "L",
	"/api/security/status":                "V",
	"/api/security/org-notice":            "V",
	"/api/security/findings":              "V",
	"/api/security/scanners":              "V",
	"/api/security/scanners/db":           "L",
	"/api/security/import-sarif":          "L",
	"/api/security/code/install":          "L",
	"/api/security/iac/install":           "L",
	"/api/security/provenance":            "L",
	"/api/security/trust":                 "L",
	"/api/security/exceptions":            "L",
	"/api/security/exceptions/revoke":     "L",
	"/api/security/baseline":              "L",
	"/api/security/editor":                "L",
	"/api/security/scan-history":          "L",
	"/api/security/findings/{id}/explain": "L",
	"/api/security/githooks":              "L",
	"/api/security/scanners/custom":       "L",
	"/api/security/scanners/custom/":      "L",
	"/api/security/deps":                  "L",
	"/api/guard/summary":                  "V",
	"/api/health/doctor":                  "V",
	"/api/health/failures":                "V",
	"/api/health/watcher":                 "V",
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
	"/api/mcp-access/status":      "V", // Agent Access P10: node MCP relay status read (no network, no write), like /api/guard/mcp
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
	// Projects page (docs/projects-page.md): per-project detail, commit
	// ledger, prompt chains and spend views are reads over node-local
	// tables; the grade route runs the local heuristic (or the configured
	// judge) over already-persisted rows and stores the result - no
	// device-local physical act, so view-tier like the rest.
	"/api/project/{id}":                           "V",
	"/api/project/{id}/commits":                   "V",
	"/api/project/{id}/skills":                    "V",
	"/api/project/{id}/prompts":                   "V",
	"/api/project/{id}/cost":                      "V",
	"/api/project/{id}/prompts/{action_id}/grade": "V",
	"/api/project/{id}/commit-scan":               "L",
	// Delivery (D-689): the tab and the mirror list are reads; every write
	// reaches the network, the keychain or the disk, and the link list names
	// the connected account, so those are owner-local.
	"/api/project/{id}/delivery":          "V",
	"/api/project/{id}/delivery/check":    "L",
	"/api/project/{id}/delivery/settings": "L",
	"/api/delivery/links":                 "L",
	"/api/delivery/links/{id}":            "L",
	"/api/delivery/links/{id}/test":       "L",
	"/api/delivery/mirrors":               "V",
	"/api/delivery/mirrors/{id}":          "L",
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
	"/api/reprice/apply":                      "L",
	"/api/reprice/plan":                       "L",
	"/api/reprice/revert":                     "L",
	"/api/reprice/status":                     "L",
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
	"/api/tags/definitions":          "V",
	"/api/setup/claude":              "L",
	"/api/setup/codex":               "L",
	"/api/setup/codex-hooks":         "V",
	"/api/setup/hooks":               "L",
	"/api/setup/mcp":                 "L",
	"/api/setup/telemetry":           "L",
	"/api/setup/windows-homes":       "L",
	"/api/setup/windows-homes/apply": "L",
	"/api/shell-wrap/apply":          "L",
	"/api/shell-wrap/disable":        "L",
	"/api/shell-wrap/status":         "L",
	"/api/status":                    "V",
	"/api/status/scoped":             "V",
	"/api/statusline":                "V",
	"/api/storage":                   "V",
	"/api/storage/backup":            "L",
	"/api/storage/vacuum":            "L",
	"/api/suggest":                   "V",
	"/api/suggest/write":             "L",
	"/api/suggestions":               "V",
	"/api/suggestions/state":         "L",
	// The notification bell (D-323): the owner's own inbox and its
	// read / dismiss state write.
	"/api/notifications":       "L",
	"/api/notifications/state": "L",
	// T-922: the first-run capture view names this machine's session
	// folders and project roots, and its seen flag is a node write.
	"/api/firstrun":                       "L",
	"/api/firstrun/seen":                  "L",
	"/api/tasks":                          "V", // Phase-2 task-tracking project/tool/window rollup — read-side aggregate over already-captured actions/token_usage rows, same posture as /api/cache/status
	"/api/terminal/":                      "V",
	"/api/terminal/install":               "L", // spawns the registry-constant install command in a local-only setup PTY — owner-local only
	"/api/terminal/uninstall":             "L", // spawns the uninstall derived from the RECORDED dashboard install in a local-only setup PTY — owner-local only
	"/api/terminal/installs":              "L", // lists this machine's dashboard-install records (install commands, npm --prefix paths) — owner-local only
	"/api/terminal/installs/forget":       "L", // hides a dashboard-install record — owner-local only
	"/api/terminal/launch":                "X",
	"/api/terminal/launch/preflight":      "L", // runs a $SHELL -lc login-shell PATH capture + reveals binary paths/home layout — owner-local only (reclassified V→L, 2026-07-23 review)
	"/api/terminal/launch/models":         "V", // reads token_usage model history + registry Known list only — same posture as /api/models (B5 model picker)
	"/api/terminal/project-policy":        "L", // lane sec-p2b: takes a local directory path and says whether the org's project rules apply there; owner-local like preflight
	"/api/terminal/sandbox":               "V", // B9 fail-soft sandbox probe — reads the daemon's cached bwrap probe result + [terminal.sandbox] config only, same posture as /api/terminal/launch/models
	"/api/terminal/ssh":                   "L", // SSH remote-system terminals — GET discloses the operator's internal hostnames (the sessions.git_branch privacy class) and POST opens an interactive shell on a THIRD-PARTY machine; both stay owner-local until remote-driven SSH gets its own threat model (ssh-remote-profiles plan §6.2 / D1)
	"/api/terminal/sandbox/config":        "L", // owner-local editor for [terminal.sandbox], including remote-clone / extra-rw-bind authority expansion
	"/api/terminal/ssh/profiles":          "L", // T-488 owner-local editor for the [[terminal.ssh.profiles]] allow-list (full key PATHS, never contents)
	"/api/terminal/ssh/profiles/test":     "L", // T-488 draft test-connect: runs a bounded ssh probe to another machine
	"/api/terminal/limits":                "L",
	"/api/terminal/policy":                "L",
	"/api/terminal/project/":              "V",
	"/api/terminal/session/":              "V",
	"/api/terminal/runs":                  "V",
	"/api/arena/runs":                     "V", // agent arena: GET list; POST create auto-escalates to X + confirm token in-handler
	"/api/arena/runs/{id}":                "V",
	"/api/arena/models":                   "V", // read-only judge/candidate model pickers (GET only)
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
	// Lane LEFT-SBX: the install version picker makes the daemon read a
	// vendor registry for the picked tool; owner-local.
	"/api/terminal/sandbox/install-versions": "L",
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
	// Command jobs (command_jobs.go, backlog item 6 follow-up): each POST runs
	// an `observer` CLI command that writes state or an AI client's config, so
	// all are Local. The poll / list is Local too (review M3-04): a job's output
	// is local diagnostics of a Local-only action.
	"/api/jobs":                   "L",
	"/api/jobs/":                  "L",
	"/api/jobs/score":             "L",
	"/api/jobs/summarize":         "L",
	"/api/jobs/patterns":          "L",
	"/api/jobs/calibration":       "L",
	"/api/jobs/pricing-sync":      "L",
	"/api/jobs/mcp-wrap":          "L",
	"/api/jobs/mcp-unwrap":        "L",
	"/api/jobs/mcp-relay-enable":  "L",
	"/api/jobs/mcp-relay-disable": "L",
	"/api/jobs/mcp-doctor":        "L",
	// T-421 item 2: the forced integrity check (a whole-file read of the
	// database on demand) and its cancel are owner-local like every job.
	"/api/jobs/doctor-integrity":        "L",
	"/api/jobs/doctor-integrity/cancel": "L",
	// T-493: deleting a reclaim leftover (after a quick_check of the
	// database in place) is a local destructive write, owner-local.
	"/api/jobs/reclaim-cleanup":        "L",
	"/api/jobs/reclaim-cleanup/cancel": "L",
	// T-421 item 3: the per-tool doctor quotes local paths and probes the
	// machine, so it is owner-local like the mcp-doctor job.
	"/api/health/doctor/tool": "L",
	// The update ledger can name local paths; adopt-defaults writes config;
	// a benchmark run spends and a delete removes rows.
	"/api/update/history":        "L",
	"/api/config/adopt-defaults": "L",
	"/api/benchmarks/run":        "L",
	"/api/benchmarks/delete":     "L",
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
			t.Errorf("route %q is registered but NOT in the §9.3 classification table - classify it (public/view/local/execute) and add it to expectedClassification", pattern)
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
	// The AI tool settings editor writes the developer's vendor config files.
	"/api/agent-config/save",
	"/api/agent-config/common/save",
	"/api/admin/restart",
	"/api/backfill/run",
	"/api/config/backup",
	"/api/config/keys",
	"/api/config/pricing",
	"/api/config/profiles",
	"/api/config/profiles/",
	"/api/config/profile-assignments",
	"/api/config/project-profiles",
	"/api/config/reload",
	"/api/config/section/",
	"/api/demo/start",
	"/api/demo/stop",
	"/api/enrolment/invite",
	"/api/enrolment/unenroll",
	"/api/enrolment/enrol",
	"/api/enrolment/grant-decision",
	"/api/enrolment/idp/start",
	"/api/enrolment/idp/poll",
	"/api/enrolment/push-now",
	"/api/enrolment/share-history",
	"/api/enrolment/resync",
	"/api/enrolment/leave",
	"/api/intel/accept",
	"/api/intel/withdraw",
	"/api/intel/enrich",
	"/api/experiments",
	"/api/experiments/stop",
	"/api/guard/approvals",
	"/api/guard/approvals/",
	"/api/guard/evidence",
	"/api/guard/jobs/policy",
	"/api/guard/jobs/mcp",
	"/api/guard/mcp/approve",
	// T-496: a reputation lookup makes one outbound registry request.
	"/api/guard/mcp/reputation",
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
	// An apply / revert rewrites stored spend rows.
	"/api/reprice/apply",
	"/api/reprice/revert",
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
	// T-537: points a tool's own OTLP exporter at the node.
	"/api/setup/telemetry",
	// T-421 item 4: writes the operator's Windows-side AI-tool configs.
	"/api/setup/windows-homes/apply",
	// Command wrapping writes shims + marked blocks into the operator's
	// shell start-up files: machine-reaching, never a remote viewer's call.
	"/api/shell-wrap/apply",
	"/api/shell-wrap/disable",
	"/api/storage/backup",
	"/api/storage/vacuum",
	"/api/suggest/write",
	"/api/suggestions/state",
	"/api/notifications/state",
	"/api/firstrun/seen",
	// T-854: a reply / Ask my admin, read and acknowledge receipts, retry
	// and discard all reach the org or change what will.
	"/api/messages",
	"/api/messages/",
	"/api/tools/launch",
	"/api/terminal/install",
	"/api/terminal/uninstall",
	"/api/terminal/installs/forget",
	"/api/terminal/launch",
	"/api/terminal/limits",
	"/api/terminal/policy",
	// T-488: writes the SSH remote-systems allow-list / probes a draft host.
	"/api/terminal/ssh/profiles",
	"/api/terminal/ssh/profiles/test",
	"/api/update/apply",
	// W5: the extension's self-report mutates daemon state (the posture it
	// republishes), so it belongs in the mutation set. The sibling
	// /api/update/status is a pure read and deliberately is not.
	"/api/update/extension-version",
	// Command jobs: each runs a state-writing `observer` CLI command (doctor
	// runs a machine probe, which is the same owner-local class).
	"/api/jobs/score",
	"/api/jobs/summarize",
	"/api/jobs/patterns",
	"/api/jobs/calibration",
	"/api/jobs/pricing-sync",
	"/api/jobs/mcp-wrap",
	"/api/jobs/mcp-unwrap",
	"/api/jobs/mcp-relay-enable",
	"/api/jobs/mcp-relay-disable",
	"/api/jobs/mcp-doctor",
	"/api/jobs/doctor-integrity",
	"/api/jobs/doctor-integrity/cancel",
	"/api/jobs/reclaim-cleanup",
	"/api/jobs/reclaim-cleanup/cancel",
	"/api/config/adopt-defaults",
	// Settings > Components: writes [components], removes Observer's entries
	// from other tools' config, persists and executes a local purge plan.
	"/api/components/apply",
	"/api/components/teardown",
	"/api/components/purge/preview",
	"/api/components/purge/execute",
	"/api/benchmarks/run",
	"/api/benchmarks/delete",
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
			t.Errorf("mutation route %q is %s - must be Local or Execute, never plain View (auto-escalation would expose it to a remote execute principal)", pattern, cap)
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
			t.Errorf("loopback listener refused a Local route (%d) - Local routes must stay open on the owner-trusted listener", rec.Code)
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
		t.Error("execute capability was consumed by a refused Local-route request - it must survive (funnel-parity)")
	}
}

// TestSessionSubRouteCapabilities enumerates the /api/session/ suffix table
// (plan §9.1): every mutating sub-route resolves to an explicit Execute tier,
// and none is Local (a Local sub-route would need its own pattern).
func TestSessionSubRouteCapabilities(t *testing.T) {
	if len(sessionSubRouteCapabilities) == 0 {
		t.Fatal("sessionSubRouteCapabilities is empty - the /api/session/ mutating sub-routes must be enumerated")
	}
	// Explicit membership pin: adding OR removing a mutating session sub-route
	// is a classification decision, so it must be made here too. /tags joined
	// the set with session classification (plan §4).
	wantSuffixes := map[string]struct{}{
		"/handoff": {},
		"/launch":  {},
		"/resume":  {},
		"/tags":    {},
		"/quality": {},
	}
	for suffix := range wantSuffixes {
		if _, ok := sessionSubRouteCapabilities[suffix]; !ok {
			t.Errorf("expected mutating session sub-route %q is missing from sessionSubRouteCapabilities", suffix)
		}
	}
	for suffix := range sessionSubRouteCapabilities {
		if _, ok := wantSuffixes[suffix]; !ok {
			t.Errorf("session sub-route %q is registered but not in the pinned set - classify it here", suffix)
		}
	}
	for suffix, cap := range sessionSubRouteCapabilities {
		if !strings.HasPrefix(suffix, "/") {
			t.Errorf("sub-route suffix %q must start with '/'", suffix)
		}
		if cap != CapabilityExecute {
			t.Errorf("/api/session/…%s is %s - mutating session sub-routes are Execute (a Local sub-route needs a dedicated pattern)", suffix, cap)
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
				t.Errorf("%s is %s - every /api/config/* route must be Local", pattern, cap)
			}
			seenKeys = seenKeys || pattern == "/api/config/keys"
			seenSchema = seenSchema || pattern == "/api/config/schema"
		case strings.HasPrefix(pattern, "/api/terminal/ssh"):
			if cap != CapabilityLocal {
				t.Errorf("%s is %s - every /api/terminal/ssh* route must be Local", pattern, cap)
			}
			seenSSH = true
		}
	}
	if !seenKeys || !seenSchema || !seenSSH {
		t.Errorf("expected /api/config/keys, /api/config/schema and /api/terminal/ssh to be registered (keys=%v schema=%v ssh=%v)", seenKeys, seenSchema, seenSSH)
	}
}
