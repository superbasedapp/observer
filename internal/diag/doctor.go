package diag

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/codextrust"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/installshape"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/mcpregister"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
	"github.com/marmutapp/superbased-observer/internal/remedy"
	"github.com/marmutapp/superbased-observer/internal/supervisor"
)

// Status is the outcome of a single check. Three levels — anything other
// than StatusOK is reported on stderr; StatusFail flips the exit code.
type Status int

const (
	StatusOK Status = iota
	StatusWarn
	StatusFail
)

// String renders a status as a one-token symbol for tabular output.
func (s Status) String() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusWarn:
		return "warn"
	case StatusFail:
		return "fail"
	}
	return "?"
}

// Check is one row of a Report.
type Check struct {
	Name    string   // short id, e.g. "db.integrity"
	Status  Status   // ok | warn | fail
	Message string   // single-line summary
	Details []string // optional bullet points (printed indented)

	// Remediations are the finding's structured fixes (T-421 item 3): a
	// closed action id plus a parameter, rendered by internal/remedy as the
	// command the Message / Details already quote for the CLI and as a
	// button linking to the dashboard control. Empty on a healthy check.
	Remediations []remedy.Remediation `json:",omitempty"`

	// pinned keeps the check through Report.Filter whatever the filter
	// word: a line that explains why a scoped doctor left something out
	// (the deferred whole-DB integrity pass) must reach the scoped output.
	// Unexported, so it never changes the JSON shape.
	pinned bool
}

// Report is the result of running all checks.
type Report struct {
	Checks []Check
}

// Failed reports whether any check has Status == StatusFail.
func (r Report) Failed() bool {
	for _, c := range r.Checks {
		if c.Status == StatusFail {
			return true
		}
	}
	return false
}

// Counts returns (ok, warn, fail) tallies across the report.
func (r Report) Counts() (int, int, int) {
	var ok, warn, fail int
	for _, c := range r.Checks {
		switch c.Status {
		case StatusOK:
			ok++
		case StatusWarn:
			warn++
		case StatusFail:
			fail++
		}
	}
	return ok, warn, fail
}

// DoctorOptions parameterizes Doctor.
type DoctorOptions struct {
	// Config is the loaded observer config. Required.
	Config config.Config
	// DB is an opened observer DB (use internal/db.Open). Required.
	DB *sql.DB
	// HomeDir overrides $HOME (for tests).
	HomeDir string
	// Getenv reads the variables that relocate a tool's config home
	// (CODEX_HOME today, through the agentconfig rule on codex/user-config;
	// surface-gap Wave 4 CX-4). nil is the one pinned-home rule
	// (crossmount.HomeEnv, R-188 F1): os.Getenv only when HomeDir is not
	// pinned and the process home is not isolated, and no variable
	// otherwise, so a sandboxed or isolated run reads only its own home.
	Getenv func(string) string
	// BinaryPath is the absolute path of the running observer binary.
	// Required for hook + MCP registration checks. It is the REGISTRATION
	// command (the npm / pip launcher for a package-manager install, U1),
	// what hook and MCP entries are expected to name.
	BinaryPath string
	// RealBinaryPath is the running binary itself; an MCP entry naming it
	// runs this same install, so init refreshes it without --force (U2).
	RealBinaryPath string
	// CLIVersion is this binary's release version; the daemon.version
	// check compares the running daemon's with it (U3). Empty or "dev"
	// skips the comparison.
	CLIVersion string
	// Scope is the doctor's single argument (`observer doctor <scope>`),
	// "" for an unscoped run. A scope whose filter would not keep the
	// db.integrity check (a per-tool doctor such as `observer doctor
	// cline`) DEFERS the whole-database PRAGMA quick_check instead of
	// paying for it and then filtering its line away; see
	// checkDBIntegrityGated.
	Scope string
	// ForceIntegrity runs the whole-database quick_check regardless of
	// Scope and of [observer.db].integrity_check_max_gb (`observer doctor
	// --integrity`).
	ForceIntegrity bool
	// RouteSelection is the node's component selection for managed routes,
	// the one route maintenance acts on (cmd/observer routeSelection). The
	// route rows name a tool it does not select as "not selected by policy"
	// and, with the route writer component off, every tool as "routing
	// switched off by policy", never as route drift (T-915, D-770, D-771).
	// The zero value selects routing and every tool.
	RouteSelection proxyroute.Selection
	// ExtraChecks are pre-built checks the caller assembles OUTSIDE this
	// package and appends to the report — the seam for checks that need
	// dependencies diag must not import (e.g. the obs-plane admission check,
	// built in cmd/observer's obs_wire.go so diag never imports internal/obs).
	// They are added after the built-in checks, so `observer doctor <tool>`
	// substring-filtering (Filter) still scopes to them by Name.
	ExtraChecks []Check
}

// Run executes every check and returns the aggregated report. It never
// returns an error — every failure is captured as a StatusFail check.
func Run(ctx context.Context, opts DoctorOptions) Report {
	// homeOverride is the caller's RAW HomeDir, kept before the real-$HOME
	// default below: non-empty means "this doctor run is sandboxed", which
	// switches OFF cross-OS auto-detection in the checks that would otherwise
	// read a foreign-OS home (see crossmount.AutoDetectSuppressed, incident
	// 2026-07-31). "" on every production run.
	homeOverride := opts.HomeDir
	if opts.HomeDir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			opts.HomeDir = home
		}
	}
	opts.Getenv = crossmount.HomeEnv(homeOverride, opts.Getenv)
	r := Report{}
	r.add(checkSchema(ctx, opts.DB))
	r.add(checkDBIntegrityGated(ctx, opts))
	r.add(checkDBSize(opts.Config, opts.HomeDir))
	r.add(checkAdapters(opts.Config))
	r.add(checkAntigravityFamily(opts.HomeDir, opts.Config))
	r.add(checkHookChecksums(opts.HomeDir))
	r.add(checkHookCommandsBinary(opts.HomeDir, opts.BinaryPath, opts.RealBinaryPath))
	// A stale observer left by an update (lane LEFT-SHARED,
	// binaryfreshness.go): plugin shims and the observer on PATH.
	running := HookBinaryIdentity{Command: opts.BinaryPath, Real: opts.RealBinaryPath}
	r.add(checkPluginShimBinaries(opts.HomeDir, opts.Getenv, running, opts.CLIVersion, BinaryVersionOf))
	r.add(checkPathObserver(pathObserver, running, opts.CLIVersion, BinaryVersionOf))
	r.add(checkMCPRegistrations(opts.HomeDir, opts.BinaryPath, opts.RealBinaryPath, opts.Getenv, opts.Config.Observer.MCP.StableCommand))
	r.add(checkClaudeCodePlugin(opts.HomeDir, homeOverride))
	r.add(checkCursorHooks(opts.HomeDir, homeOverride))
	r.add(checkCursorClaudeReplay(opts.HomeDir))
	switchRoots := hookSwitchProjectRoots(ctx, opts.DB)
	r.add(checkHooksDisabled(opts.HomeDir, homeOverride, switchRoots, opts.Getenv))
	r.add(checkConfigLayers(ctx, opts.HomeDir, homeOverride, switchRoots, opts.Getenv))
	r.add(checkHookLiveness(ctx, opts.DB, opts.HomeDir, homeOverride, switchRoots, time.Now(), opts.Getenv))
	for _, c := range checkWindowsHookShells(homeOverride, opts.BinaryPath, opts.Getenv) {
		r.add(c)
	}
	for _, c := range checkCopilotCLIPowerShellOnHost(homeOverride, opts.BinaryPath, opts.Getenv) {
		r.add(c)
	}
	for _, c := range checkWindowsHookRunners(ctx, homeOverride, opts.BinaryPath, opts.Getenv) {
		r.add(c)
	}
	for _, c := range checkCrossOSLiveGated(homeOverride, opts.BinaryPath) {
		r.add(c)
	}
	if c, ok := checkRemoteHosts(opts.HomeDir, homeOverride != ""); ok {
		r.add(c)
	}
	if c, ok := checkCodexInWSL(opts.HomeDir, homeOverride != ""); ok {
		r.add(c)
	}
	if c, ok := checkWindowsSideRelocation(homeOverride, opts.BinaryPath); ok {
		r.add(c)
	}
	// Gates reached through another tool's hook registration (W-2b).
	for _, c := range checkReplayedVia(ctx, opts.HomeDir, opts.BinaryPath, opts.DB, time.Now()) {
		r.add(c)
	}
	r.add(checkCursorUsage(ctx, opts.DB, cursorFinishHooksWiring(cursorHooksFiles(opts.HomeDir, homeOverride))))
	r.add(checkPidBridge(ctx, opts.DB))
	r.add(checkConcurrentDaemons(opts.Config))
	r.add(checkDaemonVersion(opts.Config, opts.CLIVersion))
	r.add(checkCodexHookTrust(opts.HomeDir))
	for _, c := range checkForeignCodexHookTrust(homeOverride) {
		r.add(c)
	}
	r.add(checkRoutePort(opts.HomeDir, opts.Config))
	r.add(checkProxyClientAuth(opts.HomeDir, opts.Config))
	r.add(checkRouteHost(opts.HomeDir, opts.RouteSelection))
	for _, c := range checkRecordedRoutes(opts.HomeDir) {
		r.add(c)
	}
	r.add(checkSupervisor(opts.HomeDir, supervisor.OSProbe()))
	r.add(checkCodexProviderRoute(opts.HomeDir, opts.Getenv, codexSystemRequirementsPath()))
	r.add(checkLiveGatedWriters())
	for _, c := range checkSurfaceCoverage(opts.HomeDir, homeOverride != "", opts.Getenv) {
		r.add(c)
	}
	r.add(checkRouteObserved(ctx, opts.DB, time.Now(), nil))
	if c, ok := checkWindowsProxyRoutes(ctx, opts.Config); ok {
		r.add(c)
	}
	for _, c := range checkRelay(homeOverride, time.Now()) {
		r.add(c)
	}
	r.add(checkOrgEnrolment(ctx, opts.DB, opts.Config))
	r.add(checkGovernance(ctx, opts.DB, opts.Config, homeOverride))
	r.add(checkProcessObservability(ctx, opts.DB, opts.Config))
	r.add(checkHandoffReaders(ctx, opts.DB))
	r.add(checkClaudeCodeTeams(opts.Config))
	r.add(checkClaudeCodeManagedPolicy(opts.HomeDir, opts.Getenv))
	r.add(checkVendorPolicyCaches(opts.HomeDir, opts.Getenv))
	r.add(checkCodexTeams(opts.Config))
	r.add(checkCopilotTeams(opts.Config))
	r.add(checkCortexTeams(opts.Config))
	r.add(checkIBMBobTeams(opts.Config))
	r.add(checkPromptGuardWiring(opts.Config))
	r.add(checkGuardOrgLock(opts.Config))
	r.add(checkCommitCapture(opts.Config))
	r.add(checkCodeIntel(opts.Config))
	if c, ok := checkCrossmountRow(); ok {
		r.add(c)
	}
	for _, c := range opts.ExtraChecks {
		r.add(c)
	}
	return r
}

// Filter returns a copy of the report keeping only checks whose Name
// contains tool (case-insensitive). An empty tool returns the report
// unchanged. Used by `observer doctor <tool>` to scope the output to one
// integration (e.g. `observer doctor opencode`).
func (r Report) Filter(tool string) Report {
	tool = strings.ToLower(strings.TrimSpace(tool))
	if tool == "" {
		return r
	}
	out := Report{}
	for _, c := range r.Checks {
		if c.pinned || strings.Contains(strings.ToLower(c.Name), tool) {
			out.Checks = append(out.Checks, c)
		}
	}
	return out
}

// Matched reports how many checks in r matched a filter on their own name,
// i.e. excluding pinned explanatory lines. A caller uses it to tell "this
// filter word matched nothing" apart from "only a pinned note survived".
func (r Report) Matched() int {
	n := 0
	for _, c := range r.Checks {
		if !c.pinned {
			n++
		}
	}
	return n
}

// checkOrgEnrolment surfaces the Teams (org) side of the agent in
// doctor: enrolment state, share mode (the per-node v1.8.0 opt-in),
// any scope filters, the last push status, and a clock-skew estimate
// against the org server. None of these failure modes hurt anything
// silently — they just mean the operator's expectations don't match
// what the agent will do — but they are exactly the questions the
// 2026-06-02 teams test couldn't answer without reading source.
func checkOrgEnrolment(ctx context.Context, database *sql.DB, cfg config.Config) Check {
	if !cfg.OrgClient.Enabled {
		// Tracker #41: "disabled" is only innocuous on a machine that never
		// enrolled. An enrolment row with the rail off means the node LOOKS
		// enrolled to its operator (and to the org that minted the token)
		// while pushing nothing and polling no policy — silently ungoverned.
		var enrolled int
		if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM org_enrolment`).Scan(&enrolled); err == nil && enrolled > 0 {
			return Check{
				Name: "org enrolment", Status: StatusWarn,
				Message:      "enrolled but [org_client] enabled = false - the org rail is NOT running (no push, no policy poll); set enabled = true in config.toml or run " + remedy.Quote(remedy.Of(remedy.OrgUnenroll, "")),
				Remediations: []remedy.Remediation{remedy.Of(remedy.OrgClientEnable, ""), remedy.Of(remedy.OrgUnenroll, "")},
			}
		}
		return Check{Name: "org enrolment", Status: StatusOK, Message: "[org_client] disabled (solo-local mode)"}
	}
	// Schema-meta-driven enrolment / cursor / last-push readout. We
	// avoid pulling internal/store here to keep diag standalone.
	var enrolled int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM org_enrolment`).Scan(&enrolled); err != nil {
		return Check{
			Name: "org enrolment", Status: StatusFail, Message: "could not read org_enrolment table",
			Details: []string{err.Error()},
		}
	}
	if enrolled == 0 {
		return Check{
			Name: "org enrolment", Status: StatusWarn,
			Message:      "[org_client] enabled but not enrolled - run " + remedy.Quote(remedy.Of(remedy.OrgEnroll, "")) + " to enrol",
			Remediations: []remedy.Remediation{remedy.Of(remedy.OrgEnroll, "")},
		}
	}
	var orgID, orgName, orgURL, userEmail string
	if err := database.QueryRowContext(ctx,
		`SELECT org_id, org_name, org_server_url, user_email FROM org_enrolment LIMIT 1`).
		Scan(&orgID, &orgName, &orgURL, &userEmail); err != nil {
		return Check{
			Name: "org enrolment", Status: StatusFail, Message: "could not read enrolment row",
			Details: []string{err.Error()},
		}
	}

	details := []string{
		fmt.Sprintf("org:           %s (%s)", orgName, orgID),
		fmt.Sprintf("user:          %s", userEmail),
		fmt.Sprintf("server:        %s", orgURL),
	}
	// Share mode (v1.8.0): mention loudly when full_content is on, so a
	// node operator that intended to ship metadata-only sees their
	// config drift immediately.
	shareMsg := "metadata-only (default; raws withheld)"
	shareStatus := StatusOK
	if cfg.OrgClient.Share.FullContent {
		shareMsg = "FULL CONTENT (raw command bodies + assistant prose + raw paths SHIPPED)"
		shareStatus = StatusWarn
	}
	details = append(details, "share mode:    "+shareMsg)
	// Tracker #41 second half — REVISED after a code review (BLOCK-1)
	// rejected the prior version of this check, which treated a blank
	// [org_client].org_server_url as "NOT enrolled" full stop. That was
	// wrong for a real, live shape: this function only reaches here when
	// an org_enrolment row already exists (see the `enrolled == 0` early
	// return above), and cmd/observer/start.go's construction gate
	// (orgClientShouldStart) starts the WHOLE org client — push, guard-
	// policy poll, announcement/routing-policy fetch, grant renewal —
	// whenever EITHER the config carries a URL OR a persisted row exists.
	// A row existing here means the node IS active: the push loop dials
	// the ROW's own server URL (orgURL below), which
	// internal/orgclient.Client.PushOnce reads from the store, never from
	// this config field. `ensureOrgClientBlock` (cmd/observer/org.go) is
	// header-idempotent — an existing [org_client] table header means
	// org_server_url is never (re)written — so a node enrolled before that
	// field existed, or re-enrolled without a full `observer unenroll`
	// first, can carry a blank org_server_url indefinitely while staying
	// genuinely, fully enrolled.
	//
	// What a blank org_server_url DOES still affect: it is NOT the guard
	// policy-bundle poll's dial target — that poll (like every other org
	// loop) reads enr.OrgServerURL from the PERSISTED row via
	// internal/orgclient's FetchPolicyBundle (LoadEnrolment →
	// genClient(enr.OrgServerURL)), never from this config field. A code
	// review corrected an earlier version of this check that claimed
	// otherwise. The one real, cosmetic effect: cmd/observer/start.go
	// passes this config field into newPolicyBundleRunner purely as R-205
	// audit metadata (policybundle.go's orgURL field), used only to build
	// the Target string on a bundle-REJECTED guard finding
	// (orgURL+"/api/v1/policy-bundle"). With this field blank, that one
	// Target string loses its server-URL prefix (becomes just
	// "/api/v1/policy-bundle") — the finding itself, the R-205 rule, and
	// every loop's actual behavior are all unaffected. That is cosmetic,
	// not a degradation, so it does not raise this check's status.
	orgServerURLUnset := strings.TrimSpace(cfg.OrgClient.OrgServerURL) == ""
	if orgServerURLUnset {
		details = append(details, fmt.Sprintf(
			"config gap:    [org_client].org_server_url is unset - the node stays fully ACTIVE (push/announcement/routing-policy/guard-policy-poll all dial the persisted enrolment's server, %q, directly); the only effect is cosmetic - an R-205 bundle-rejection finding's Target string loses its server-URL prefix. Add org_server_url = %q to config.toml to restore that prefix", orgURL, orgURL,
		))
	}
	if len(cfg.OrgClient.Share.TargetActionAllowlist) > 0 {
		details = append(details, fmt.Sprintf("target allow:  %v", cfg.OrgClient.Share.TargetActionAllowlist))
	}
	if len(cfg.OrgClient.Scope.ProjectRootAllowlist) > 0 {
		details = append(details, fmt.Sprintf("scope allow:   %v", cfg.OrgClient.Scope.ProjectRootAllowlist))
	}
	if len(cfg.OrgClient.Scope.ProjectRootDenylist) > 0 {
		details = append(details, fmt.Sprintf("scope deny:    %v", cfg.OrgClient.Scope.ProjectRootDenylist))
	}
	// Last push: only flag a non-OK status (the cron-style push loop
	// can transiently fail on a captive-portal lunch break without
	// indicating a real problem).
	var lastStatus, lastPushedAt, lastErr string
	var lastRows int64
	err := database.QueryRowContext(ctx,
		`SELECT pushed_at, row_count, status, COALESCE(error,'') FROM org_push_log
		   ORDER BY id DESC LIMIT 1`).
		Scan(&lastPushedAt, &lastRows, &lastStatus, &lastErr)
	switch {
	case err == sql.ErrNoRows:
		details = append(details, "last push:     (none yet)")
	case err != nil:
		details = append(details, "last push:     could not read org_push_log: "+err.Error())
		shareStatus = worseStatus(shareStatus, StatusWarn)
	default:
		summary := fmt.Sprintf("last push:     %s - %s, %d rows", lastPushedAt, lastStatus, lastRows)
		if lastErr != "" {
			summary += fmt.Sprintf(" (err: %s)", lastErr)
		}
		details = append(details, summary)
		if lastStatus != "ok" {
			shareStatus = worseStatus(shareStatus, StatusWarn)
		}
	}
	// Snapshot rows too large for any push: the daemon's report
	// (store.OrgPushOversizedKey; family names and sizes only, never row
	// content). Read here with this file's own SQL, like org_push_log above.
	var rems []remedy.Remediation
	for _, line := range oversizedPushLines(ctx, database) {
		details = append(details, "oversized:     "+line)
		shareStatus = worseStatus(shareStatus, StatusWarn)
		if len(rems) == 0 {
			rems = append(rems, remedy.Of(remedy.OpenSettings, "org"))
		}
	}
	if line, unavailable := machineProofLine(ctx, database); line != "" {
		details = append(details, "machine proof: "+line)
		if unavailable {
			shareStatus = worseStatus(shareStatus, StatusWarn)
		}
	}
	msg := "enrolled - " + shareMsg
	if orgServerURLUnset {
		msg = fmt.Sprintf(
			"enrolled - ACTIVE, dialing the persisted server %s (org_server_url is unset in config; see the config gap detail for the one cosmetic thing that affects) - %s",
			orgURL, shareMsg,
		)
	}
	return Check{
		Name:         "org enrolment",
		Status:       shareStatus,
		Message:      msg,
		Details:      details,
		Remediations: rems,
	}
}

// orgPushOversizedKey mirrors store.OrgPushOversizedKey (this file keeps its
// own SQL); TestOrgEnrolmentReportsOversizedPushRows pins the shape.
const orgPushOversizedKey = "org_push_oversized_rows"

// oversizedPushLines renders the daemon's oversized snapshot row report, one
// line per family. A missing or unreadable report yields nothing.
func oversizedPushLines(ctx context.Context, database *sql.DB) []string {
	var raw string
	if err := database.QueryRowContext(ctx, `SELECT value FROM schema_meta WHERE key = ?`, orgPushOversizedKey).Scan(&raw); err != nil || raw == "" {
		return nil
	}
	var rows []struct {
		Family       string `json:"family"`
		Rows         int64  `json:"rows"`
		LargestBytes int64  `json:"largest_bytes"`
		BudgetBytes  int64  `json:"budget_bytes"`
		LastSeen     string `json:"last_seen"`
	}
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		return nil
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, fmt.Sprintf("%s: %d row(s) larger than the %d-byte snapshot budget (largest %d bytes, last %s); raise [org_client] max_push_bytes (Settings > Org sharing) to ship them",
			r.Family, r.Rows, r.BudgetBytes, r.LargestBytes, r.LastSeen))
	}
	return out
}

// orgMachineProofKey mirrors store.OrgMachineProofKey (this file keeps its
// own SQL); TestOrgMachineProofReport pins the shape.
const orgMachineProofKey = "org_machine_proof"

// machineProofLine renders the daemon's machine-proof report (WINNODE item 4):
// the daemon records it only for a managed enrolment, at its first request
// that names the machine. unavailable is true when the daemon signs nothing.
// A missing or unreadable report yields "".
func machineProofLine(ctx context.Context, database *sql.DB) (line string, unavailable bool) {
	var tenancy, raw string
	if err := database.QueryRowContext(ctx, `SELECT COALESCE(tenancy,'') FROM org_enrolment LIMIT 1`).Scan(&tenancy); err != nil || tenancy != "managed" {
		return "", false // only a managed enrolment signs with a machine key
	}
	if err := database.QueryRowContext(ctx, `SELECT value FROM schema_meta WHERE key = ?`, orgMachineProofKey).Scan(&raw); err != nil || raw == "" {
		return "", false
	}
	var r struct {
		Available bool   `json:"available"`
		Reason    string `json:"reason"`
		At        string `json:"at"`
	}
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return "", false
	}
	if r.Available {
		return "available (daemon, since " + r.At + ")", false
	}
	return "machine proof unavailable: " + r.Reason + " (daemon, since " + r.At + "); machine-scoped grants and the machine's budget binding are withheld until the daemon runs in the developer's sign-in", true
}

func worseStatus(a, b Status) Status {
	rank := map[Status]int{StatusOK: 0, StatusWarn: 1, StatusFail: 2}
	if rank[a] > rank[b] {
		return a
	}
	return b
}

// checkConcurrentDaemons reads observer-*.lock files in the DB directory
// and reports how many distinct observer daemons are alive on this DB.
// More than one is a real correctness hazard — two writers race on the
// parse_cursors table and silently desync ingest state. Stale lockfiles
// (PIDs whose processes have exited) are filtered out.
func checkConcurrentDaemons(cfg config.Config) Check {
	dbDir := filepath.Dir(cfg.Observer.DBPath)
	locks, err := LiveLocks(dbDir)
	if err != nil {
		return Check{
			Name: "daemon.unique", Status: StatusWarn,
			Message: fmt.Sprintf("scan locks: %s", err),
		}
	}
	switch len(locks) {
	case 0:
		return Check{
			Name: "daemon.unique", Status: StatusOK,
			Message: "no observer daemon running on this DB",
		}
	case 1:
		l := locks[0]
		return Check{
			Name: "daemon.unique", Status: StatusOK,
			Message: fmt.Sprintf("1 daemon (pid=%d) on this DB", l.PID),
		}
	}
	details := make([]string, 0, len(locks))
	for _, l := range locks {
		details = append(details,
			fmt.Sprintf("pid=%d started=%s binary=%s",
				l.PID, l.StartedAt.Format(time.RFC3339), l.BinaryPath))
	}
	return Check{
		Name: "daemon.unique", Status: StatusWarn,
		Message: fmt.Sprintf("%d observer daemons running on the same DB - concurrent writers can desync cursor state",
			len(locks)),
		Details: details,
	}
}

// checkPidBridge reports how many {pid → session_id} entries the proxy
// has on hand. Zero is not a failure (the bridge is opt-in via the
// SessionStart hook), but a warn nudge so users remember to re-run
// `observer init` after upgrading.
func checkPidBridge(ctx context.Context, database *sql.DB) Check {
	var count int
	err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM session_pid_bridge`).Scan(&count)
	if err != nil {
		return Check{Name: "pidbridge.size", Status: StatusFail, Message: "read session_pid_bridge: " + err.Error()}
	}
	if count == 0 {
		return Check{
			Name: "pidbridge.size", Status: StatusWarn,
			Message:      "no pid→session entries - host tool hasn't fired SessionStart yet (re-run " + remedy.Quote(initAll) + " after upgrading)",
			Remediations: []remedy.Remediation{initAll},
		}
	}
	return Check{Name: "pidbridge.size", Status: StatusOK, Message: fmt.Sprintf("%d pid→session entries", count)}
}

func (r *Report) add(c Check) { r.Checks = append(r.Checks, c) }

// checkSchema verifies a non-zero schema version is recorded and that no
// migration is still pending. Pending comes from db.PlanMigrations, the
// runner's own read-only plan (T-979), so a step numbered below the recorded
// version that has not run is reported too; the version alone cannot show it.
// It is a warning, not a failure: the usual cause is a CLI that deferred its
// migrations to a running daemon of an older build.
func checkSchema(ctx context.Context, database *sql.DB) Check {
	v, err := db.Version(ctx, database)
	if err != nil {
		return Check{Name: "db.schema", Status: StatusFail, Message: "schema_meta unreadable: " + err.Error()}
	}
	if v == 0 {
		return Check{Name: "db.schema", Status: StatusFail, Message: "no migrations applied (version 0)"}
	}
	plan, err := db.PlanMigrations(ctx, database)
	if err != nil {
		return Check{
			Name: "db.schema", Status: StatusWarn,
			Message: fmt.Sprintf("schema version %d applied; the migration plan could not be read: %v", v, err),
		}
	}
	if pending := plan.RunVersions(); len(pending) > 0 {
		parts := make([]string, len(pending))
		for i, p := range pending {
			parts[i] = fmt.Sprint(p)
		}
		return Check{
			Name: "db.schema", Status: StatusWarn,
			Message: fmt.Sprintf("schema version %d applied; %d migration(s) pending (%s): restart the daemon so it applies them",
				v, len(pending), strings.Join(parts, ", ")),
		}
	}
	return Check{Name: "db.schema", Status: StatusOK, Message: fmt.Sprintf("schema version %d applied", v)}
}

// dbIntegrityCheckName is the db.integrity check's Name (the Filter key).
const dbIntegrityCheckName = "db.integrity"

// integrityDecision is one row of the ordered db.integrity gate: the first
// row whose match holds decides whether doctor pays for the whole-database
// PRAGMA quick_check. Adding a case is adding a row.
type integrityDecision struct {
	match func(integrityInput) bool
	// skip is nil for "run the probe"; otherwise it builds the honest
	// skipped line.
	skip func(integrityInput) Check
	// needsSize makes the gate stat the database file before match (only
	// the size row does, so a scoped or forced run never stats it).
	needsSize bool
}

// integrityInput is what the gate decides on.
type integrityInput struct {
	scope     string
	force     bool
	maxGB     int
	overCap   bool
	sizeBytes int64
}

// scopeExcludesIntegrity reports whether a scoped doctor's filter would drop
// the db.integrity line (Report.Filter's substring rule).
func scopeExcludesIntegrity(in integrityInput) bool {
	return in.scope != "" && !strings.Contains(dbIntegrityCheckName, in.scope)
}

// integrityOnDemand is the one pointer every skip line gives; its command is
// remedy's DoctorDBIntegrity (the dashboard's forced integrity check).
var integrityOnDemand = "run " + remedy.Quote(integrityRemedy) + " (or `observer doctor --integrity`) to run it on demand"

// integrityRemedy is the structured fix a skipped integrity line carries.
var integrityRemedy = remedy.Of(remedy.DoctorDBIntegrity, "")

// initAll is the plain `observer init` remediation (Connected tools).
var initAll = remedy.Of(remedy.Init, "")

var integrityDecisions = []integrityDecision{
	{
		// `observer doctor --integrity`: always run.
		match: func(in integrityInput) bool { return in.force },
	},
	{
		// A per-tool doctor (the scope does not select db.integrity):
		// defer. quick_check reads every page of the database, so its cost
		// has nothing to do with the one tool being asked about (live
		// finding D8: `observer doctor cline` took 751 s on a 27 GB DB for
		// two lines of output). Pinned so the scoped output says so.
		match: scopeExcludesIntegrity,
		skip: func(in integrityInput) Check {
			return Check{
				Name:         dbIntegrityCheckName,
				Status:       StatusOK,
				Message:      fmt.Sprintf("skipped: `observer doctor %s` is scoped to one tool and the whole-database PRAGMA quick_check is not; %s", in.scope, integrityOnDemand),
				Remediations: []remedy.Remediation{integrityRemedy},
				pinned:       true,
			}
		},
	},
	{
		// An explicit `observer doctor db` is the on-demand probe the
		// daemon's startup skip line points at: run it whatever the size.
		match: func(in integrityInput) bool { return in.scope != "" },
	},
	{
		// Unscoped doctor over [observer.db].integrity_check_max_gb:
		// honour the same gate the daemon's startup pass does.
		match:     func(in integrityInput) bool { return in.overCap },
		needsSize: true,
		skip: func(in integrityInput) Check {
			return Check{
				Name:   dbIntegrityCheckName,
				Status: StatusOK,
				Message: fmt.Sprintf("skipped: database is %.1f GB, over [observer.db].integrity_check_max_gb = %d (the same gate as the daemon's startup check); %s",
					float64(in.sizeBytes)/(1<<30), in.maxGB, integrityOnDemand),
				Remediations: []remedy.Remediation{integrityRemedy},
			}
		},
	},
}

// checkDBIntegrityGated decides, through integrityDecisions, whether this
// doctor run pays for the whole-database PRAGMA quick_check. The size gate
// is db.IntegrityCheckShouldSkip, the one owner the daemon's automatic
// startup pass also asks. A skipped line carries the most recently recorded
// probe verdict (db.LastIntegrityVerdict) when one exists, so skipping never
// hides a known result.
func checkDBIntegrityGated(ctx context.Context, opts DoctorOptions) Check {
	in := integrityInput{
		scope: strings.ToLower(strings.TrimSpace(opts.Scope)),
		force: opts.ForceIntegrity,
		maxGB: opts.Config.Observer.DB.IntegrityCheckMaxGB,
	}
	sized := false
	for _, row := range integrityDecisions {
		if row.needsSize && !sized {
			in.overCap, in.sizeBytes = db.IntegrityCheckShouldSkip(expandHomePath(opts.Config.Observer.DBPath, opts.HomeDir), in.maxGB)
			sized = true
		}
		if !row.match(in) {
			continue
		}
		if row.skip == nil {
			c := checkDBIntegrity(ctx, opts.DB)
			// A forced probe under a per-tool scope must still print.
			c.pinned = scopeExcludesIntegrity(in)
			return c
		}
		c := row.skip(in)
		if opts.DB != nil {
			if v, ok, err := db.LastIntegrityVerdict(ctx, opts.DB); err == nil && ok {
				c.Details = append(c.Details, fmt.Sprintf("last recorded quick_check: %s at %s", v.Status, v.CheckedAt.UTC().Format(time.RFC3339)))
			}
		}
		return c
	}
	return checkDBIntegrity(ctx, opts.DB)
}

// expandHomePath resolves a leading "~/" against homeDir (checkDBSize's rule).
func expandHomePath(path, homeDir string) string {
	if strings.HasPrefix(path, "~/") && homeDir != "" {
		return filepath.Join(homeDir, path[2:])
	}
	return path
}

// checkDBIntegrity runs PRAGMA quick_check.
func checkDBIntegrity(ctx context.Context, database *sql.DB) Check {
	var result string
	if err := database.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&result); err != nil {
		return Check{Name: "db.integrity", Status: StatusFail, Message: "quick_check error: " + err.Error()}
	}
	if result != "ok" {
		return Check{Name: "db.integrity", Status: StatusFail, Message: "quick_check failed: " + result}
	}
	return Check{Name: "db.integrity", Status: StatusOK, Message: "PRAGMA quick_check ok"}
}

// checkDBSize warns when the DB exceeds 80% of max_db_size_mb and fails when
// it exceeds 100%. A zero/negative cap disables the check.
func checkDBSize(cfg config.Config, homeDir string) Check {
	cap := cfg.Observer.Retention.MaxDBSizeMB
	if cap <= 0 {
		return Check{Name: "db.size", Status: StatusOK, Message: "max_db_size_mb disabled"}
	}
	path := cfg.Observer.DBPath
	if strings.HasPrefix(path, "~/") && homeDir != "" {
		path = filepath.Join(homeDir, path[2:])
	}
	fi, err := os.Stat(path)
	if err != nil {
		return Check{Name: "db.size", Status: StatusWarn, Message: "stat db: " + err.Error()}
	}
	mb := fi.Size() / (1024 * 1024)
	switch {
	case mb >= int64(cap):
		return Check{Name: "db.size", Status: StatusFail, Message: fmt.Sprintf("%dMB exceeds max_db_size_mb=%d (run pruning)", mb, cap)}
	case mb >= int64(cap)*8/10:
		return Check{Name: "db.size", Status: StatusWarn, Message: fmt.Sprintf("%dMB approaching max_db_size_mb=%d", mb, cap)}
	}
	return Check{Name: "db.size", Status: StatusOK, Message: fmt.Sprintf("%dMB / %dMB", mb, cap)}
}

// checkAntigravityFamily reports the state of the desktop + CLI
// Antigravity conversation directories on this host. Both layouts
// can coexist; the check emits a StatusWarn when CLI conversations
// exist but `[observer.antigravity] network_recovery` is off, since
// CLI .pb files practically require the gRPC fallback to surface in
// the dashboard (the agy CLI does not bootstrap an oscrypt secret
// equivalent to the desktop install).
func checkAntigravityFamily(homeDir string, cfg config.Config) Check {
	desktop := filepath.Join(homeDir, ".gemini", "antigravity", "conversations")
	cli := filepath.Join(homeDir, ".gemini", "antigravity-cli", "conversations")
	desktopPbs := countDirEntries(desktop, ".pb")
	cliPbs := countDirEntries(cli, ".pb")

	var details []string
	if dirExists(desktop) {
		details = append(details, fmt.Sprintf("desktop: %s (%d .pb files)", desktop, desktopPbs))
	} else {
		details = append(details, "desktop: not present")
	}
	if dirExists(cli) {
		details = append(details, fmt.Sprintf("cli: %s (%d .pb files)", cli, cliPbs))
	} else {
		details = append(details, "cli: not present")
	}

	net := strings.ToLower(strings.TrimSpace(cfg.Observer.Antigravity.NetworkRecovery))
	details = append(details, "network_recovery: "+netDescription(net))

	if cliPbs > 0 && net != "local" {
		return Check{
			Name:         "antigravity.family",
			Status:       StatusWarn,
			Message:      fmt.Sprintf("%d Antigravity-CLI .pb file(s) present but [observer.antigravity] network_recovery is %q - set it to \"local\" (Settings > Antigravity) so the gRPC fallback can recover CLI conversations", cliPbs, net),
			Details:      details,
			Remediations: []remedy.Remediation{remedy.Of(remedy.OpenSettings, "antigravity")},
		}
	}
	if desktopPbs+cliPbs == 0 {
		return Check{
			Name:    "antigravity.family",
			Status:  StatusOK,
			Message: "no Antigravity .pb files on disk yet",
			Details: details,
		}
	}
	return Check{
		Name:    "antigravity.family",
		Status:  StatusOK,
		Message: fmt.Sprintf("%d desktop + %d CLI .pb file(s) discovered", desktopPbs, cliPbs),
		Details: details,
	}
}

func netDescription(s string) string {
	if s == "" {
		return "(unset; default = off)"
	}
	return s
}

// countDirEntries counts files whose name ends in ext in dir.
// Best-effort: returns 0 for any I/O error.
func countDirEntries(dir, ext string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(strings.ToLower(e.Name()), strings.ToLower(ext)) {
			n++
		}
	}
	return n
}

// checkHookChecksums reads ~/.observer/hook_checksums.json and verifies
// each recorded config file still hashes to the expected value. Drift is
// reported as StatusWarn so the user can decide whether to re-run init.
func checkHookChecksums(homeDir string) Check {
	csPath := filepath.Join(homeDir, ".observer", "hook_checksums.json")
	raw, err := os.ReadFile(csPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Check{Name: "hooks.checksums", Status: StatusWarn, Message: "no hook_checksums.json yet - run " + remedy.Quote(initAll) + " first", Remediations: []remedy.Remediation{initAll}}
		}
		return Check{Name: "hooks.checksums", Status: StatusFail, Message: "read checksums: " + err.Error()}
	}
	var entries map[string]struct {
		SHA256      string `json:"sha256"`
		DigestScope string `json:"digest_scope"`
		HooksSHA256 string `json:"hooks_sha256"`
		Registered  string `json:"registered"`
		BinaryPath  string `json:"binary_path"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return Check{Name: "hooks.checksums", Status: StatusFail, Message: "parse checksums: " + err.Error()}
	}
	if len(entries) == 0 {
		return Check{Name: "hooks.checksums", Status: StatusWarn, Message: "no hooks registered"}
	}

	var (
		drift   []string
		missing []string
		matched int
	)
	for path, want := range entries {
		body, err := os.ReadFile(path)
		if err != nil {
			missing = append(missing, path+": "+err.Error())
			continue
		}
		if !hookEntryMatches(path, body, want.SHA256, want.DigestScope, want.HooksSHA256) {
			drift = append(drift, path)
			continue
		}
		matched++
	}

	switch {
	case len(missing) > 0:
		return Check{
			Name: "hooks.checksums", Status: StatusFail,
			Message: fmt.Sprintf("%d config file(s) missing", len(missing)),
			Details: missing,
		}
	case len(drift) > 0:
		return Check{
			Name: "hooks.checksums", Status: StatusWarn,
			Message:      fmt.Sprintf("%d config file(s) modified externally - re-run %s to refresh", len(drift), remedy.Quote(initAll)),
			Details:      drift,
			Remediations: []remedy.Remediation{initAll},
		}
	}
	return Check{Name: "hooks.checksums", Status: StatusOK, Message: fmt.Sprintf("%d config(s) match recorded checksums", matched)}
}

// checkCodexHookTrust reports whether every Codex hook event Observer
// registers will actually run. Codex (0.129.0+, still required on 0.160)
// dispatches a hooks.json entry only after the user trusts it inside
// Codex (`/hooks`); the approval lives in ~/.codex/config.toml
// [hooks.state] as a trusted_hash over the entry's body, so an entry
// whose command changed after it was trusted is untrusted again, and an
// entry the user switched off carries `enabled = false`.
//
// The expected events come from the integration registry (the Registered
// Codex bindings, pinned to the writer's list), so an event a newer
// Observer adds is listed even before hooks.json carries it. The trust
// hash is recomputed by internal/codextrust. This check never writes Codex
// config; the hook writer records trust for Observer's own entries when it
// registers them (live check 2026-10-20), so an entry reported here as
// untrusted is one whose record is missing, changed or switched off.
//
// Outcomes: OK when Codex has no Observer hooks or every expected event
// is trusted; Warn otherwise, with the first detail line naming the
// events that will not run ("untrusted: ...", read by
// CaptureIntegritySignals) and one line per state.
func checkCodexHookTrust(homeDir string) Check {
	st := readCodexHookTrust(homeDir)
	switch {
	case st.noHooksFile:
		return Check{Name: "codex.hook_trust", Status: StatusOK, Message: "no codex hooks registered"}
	case st.err != "":
		return Check{Name: "codex.hook_trust", Status: StatusWarn, Message: st.err}
	case len(st.registered) == 0:
		return Check{Name: "codex.hook_trust", Status: StatusOK, Message: "no observer-owned codex hooks found"}
	}
	return codexHookTrustCheck(st.report, st.hooksPath)
}

// codexTrustState is the parsed Codex hook trust state: the
// observer-owned events in hooks.json and which of them Codex will run.
// Shared by checkCodexHookTrust and the per-binding HookTrustFor read
// (hook-parity Lane G), so the parse exists once; both are built on the
// one internal/codextrust classification (T-039), so an entry changed or
// switched off since it was trusted counts as not trusted in both.
type codexTrustState struct {
	hooksPath   string
	noHooksFile bool
	err         string
	// registered lists the observer-owned events hooks.json carries.
	registered []string
	// trusted marks the registered events Codex will dispatch.
	trusted map[string]bool
	report  codextrust.Report
}

func readCodexHookTrust(homeDir string) codexTrustState {
	hooksPath := filepath.Join(homeDir, ".codex", "hooks.json")
	configPath := filepath.Join(homeDir, ".codex", "config.toml")
	st := codexTrustState{hooksPath: hooksPath, trusted: map[string]bool{}}

	hooksRaw, err := os.ReadFile(hooksPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			st.noHooksFile = true
			return st
		}
		st.err = "read codex hooks.json: " + err.Error()
		return st
	}
	cfgRaw, err := os.ReadFile(configPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		st.err = "read codex config.toml: " + err.Error()
		return st
	}
	rep, err := codextrust.Classify(codextrust.Input{
		HooksPath:     hooksPath,
		HooksJSON:     hooksRaw,
		ConfigTOML:    cfgRaw,
		Expected:      codexExpectedHookEvents(),
		Owned:         isObserverCodexHook,
		NormalizePath: CodexTrustPathKey,
	})
	if err != nil {
		st.err = err.Error()
		return st
	}
	st.report = rep
	for _, e := range rep.Entries {
		if e.State == codextrust.StateMissing {
			continue
		}
		st.registered = append(st.registered, e.Event)
		if e.State == codextrust.StateTrusted {
			st.trusted[e.Event] = true
		}
	}
	sort.Strings(st.registered)
	return st
}

// CodexTrustPathKey is the codextrust NormalizePath every Codex trust read
// uses: the foreign-path translation (a Windows Codex's C:\... or \\?\C:\...
// key becomes /mnt/c/... on a WSL daemon), forward slashes, lower case (NTFS
// and DrvFs are case-insensitive). Applied to both sides of the comparison,
// so a native POSIX path still matches itself.
func CodexTrustPathKey(p string) string {
	return strings.ToLower(filepath.ToSlash(crossmount.TranslateForeignPath(p)))
}

// ForeignCodexHomes returns the cross-mount homes (a WSL daemon's view of
// the Windows user's home, the one the codex-windows hook bridge writes
// into) that carry a .codex directory. A Windows home counts only when it
// is the current Windows user's (the same ownership rule the bridge
// registrar applies). homeOverride is the caller's sandbox home ("" in
// production); a sandboxed caller sees none (crossmount.AutoDetectSuppressed).
func ForeignCodexHomes(homeOverride string) []crossmount.HomeRoot {
	if crossmount.AutoDetectSuppressed(homeOverride, "") {
		return nil
	}
	var out []crossmount.HomeRoot
	for _, h := range crossmount.AllHomes() {
		if h.Origin == "native" {
			continue
		}
		if fi, err := os.Stat(filepath.Join(h.Path, ".codex")); err != nil || !fi.IsDir() {
			continue
		}
		if h.OS == crossmount.OSWindows && !crossmount.HomeOwnedByCurrentWindowsUser(h.Path) {
			continue
		}
		out = append(out, h)
	}
	return out
}

// checkForeignCodexHookTrust is checkCodexHookTrust for every foreign home
// ForeignCodexHomes finds (live check 2026-10-20: on a WSL daemon the only
// check read the WSL ~/.codex, so the Windows Codex's untrusted Observer
// hooks, and with them a gate that never ran, went unreported). A home with
// no Observer hooks yields no check. The check is named
// "codex.hook_trust.<os>" so it sits beside the native one.
func checkForeignCodexHookTrust(homeOverride string) []Check {
	var out []Check
	for _, h := range ForeignCodexHomes(homeOverride) {
		name := "codex.hook_trust." + h.OS
		st := readCodexHookTrust(h.Path)
		switch {
		case st.noHooksFile:
			continue
		case st.err != "":
			out = append(out, Check{Name: name, Status: StatusWarn, Message: st.err})
			continue
		case len(st.registered) == 0:
			continue
		}
		out = append(out, codexHookTrustCheckNamed(name, st.report, st.hooksPath))
	}
	return out
}

// CodexToolGateEvents returns the Codex hooks.json events Observer registers
// as its tool gate (registry bindings with the tool-gate capability). While
// any of them is untrusted, Observer's Codex guard gate does not run at all.
func CodexToolGateEvents() []string {
	c, ok := integration.For(models.ToolCodex)
	if !ok {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, b := range c.Hook.Bindings {
		if b.Registered && b.Cap == integration.HookCapToolGate && !seen[b.NativeEvent] {
			seen[b.NativeEvent] = true
			out = append(out, b.NativeEvent)
		}
	}
	return out
}

// codexExpectedHookEvents is every Codex hooks.json event Observer
// registers, from the integration registry.
func codexExpectedHookEvents() []string {
	c, ok := integration.For(models.ToolCodex)
	if !ok {
		return nil
	}
	return c.Hook.RegisteredEvents()
}

// isObserverCodexHook reports an Observer Codex hook command in every shape
// the registrar writes (hook.IsObserverCodexHookCommand, the fail-closed
// hook bridge included).
func isObserverCodexHook(command string) bool {
	return hook.IsObserverCodexHookCommand(command)
}

// codexTrustStateLines is the per-state detail table, in display order.
var codexTrustStateLines = []struct {
	state codextrust.State
	label string
}{
	{codextrust.StateUntrusted, "never trusted"},
	{codextrust.StateModified, "changed since you trusted it (re-trust in /hooks)"},
	{codextrust.StateDisabled, "switched off in /hooks"},
	{codextrust.StateMissing, "not registered yet (run " + remedy.Quote(remedy.Of(remedy.InitTool, models.ToolCodex)) + ", or restart `observer start` to auto-register)"},
	{codextrust.StateTrusted, "trusted"},
}

func codexHookTrustCheck(rep codextrust.Report, hooksPath string) Check {
	return codexHookTrustCheckNamed("codex.hook_trust", rep, hooksPath)
}

// codexHookTrustCheckNamed builds the trust check under name. An untrusted
// tool-gate event (CodexToolGateEvents) is a FAIL, not a warning: Codex runs
// no unapproved hook, so Observer's Codex guard gate is off, not degraded
// (live check 2026-10-20, Codex 0.144.4 `codex exec` ran no hook at all).
func codexHookTrustCheckNamed(name string, rep codextrust.Report, hooksPath string) Check {
	blocked := rep.Events(codextrust.StateUntrusted, codextrust.StateModified, codextrust.StateDisabled)
	missing := rep.Events(codextrust.StateMissing)
	if len(blocked) == 0 && len(missing) == 0 {
		msg := fmt.Sprintf("all %d codex hook(s) are trust-approved", len(rep.Entries))
		if !rep.HashVerified {
			msg += " (recorded approvals; this Codex version's trust hash could not be reproduced)"
		}
		return Check{Name: name, Status: StatusOK, Message: msg}
	}
	gate := map[string]bool{}
	for _, e := range CodexToolGateEvents() {
		gate[e] = true
	}
	var gateOff []string
	for _, e := range blocked {
		if gate[e] {
			gateOff = append(gateOff, e)
		}
	}
	status := StatusWarn
	var details []string
	var msg string
	switch {
	case len(gateOff) > 0:
		status = StatusFail
		msg = fmt.Sprintf("Codex hooks not trusted, so Observer's Codex guard gate is OFF (%s does not run): run `observer init --codex` (it re-registers the hooks and records their trust), or approve each Observer entry in codex /hooks (%d need approval)",
			strings.Join(gateOff, ", "), len(blocked))
		details = append(details, "untrusted: "+strings.Join(blocked, ", "))
	case len(blocked) > 0:
		msg = fmt.Sprintf("%d codex hook(s) need trust approval, so Codex will not run them: run `observer init --codex`, or trust each Observer entry in codex /hooks", len(blocked))
		details = append(details, "untrusted: "+strings.Join(blocked, ", "))
	default:
		msg = fmt.Sprintf("%d codex hook event(s) Observer expects are not registered", len(missing))
		details = append(details, "not registered: "+strings.Join(missing, ", "))
	}
	for _, row := range codexTrustStateLines {
		if evs := rep.Events(row.state); len(evs) > 0 {
			details = append(details, row.label+": "+strings.Join(evs, ", "))
		}
	}
	if !rep.ConfigPresent {
		details = append(details, "config.toml does not exist (codex never opened since the hooks were registered?)")
	}
	if !rep.HashVerified {
		details = append(details, "note: no trust hash in this hooks.json reproduces, so a changed entry cannot be told apart from a trusted one")
	}
	if len(gateOff) > 0 {
		details = append(details, "gate off: guard rules do not apply to Codex tool calls until the tool-gate hook is trusted")
	}
	details = append(details,
		"hooks file: "+hooksPath,
		"why: codex runs a hook only once config.toml [hooks.state] records its trust; Observer records it for its own entries when it registers them, so an entry listed here lacks that record (registered by an older Observer, changed since, or a Codex version that hashes differently). An entry switched off in /hooks stays off until you turn it back on there",
	)
	var rems []remedy.Remediation
	if len(blocked) > 0 || len(missing) > 0 {
		rems = append(rems, remedy.Of(remedy.InitTool, models.ToolCodex))
	}
	if len(blocked) > 0 {
		rems = append(rems, remedy.Of(remedy.CodexTrust, ""))
	}
	return Check{Name: name, Status: status, Message: msg, Details: details, Remediations: rems}
}

// checkHookCommandsBinary looks at every recorded hook config and verifies
// the command it points to is the running observer binary. Mismatch
// usually means the binary was moved after `observer init`. binaryPath is
// the registration command and realBinary the running binary; the match is
// HookBinaryMatches, the one rule table the managed-integrity probe uses too
// (T-874).
func checkHookCommandsBinary(homeDir, binaryPath, realBinary string) Check {
	if binaryPath == "" {
		return Check{Name: "hooks.binary", Status: StatusWarn, Message: "binary path unknown"}
	}
	csPath := filepath.Join(homeDir, ".observer", "hook_checksums.json")
	raw, err := os.ReadFile(csPath)
	if err != nil {
		return Check{Name: "hooks.binary", Status: StatusOK, Message: "no checksums to verify"}
	}
	var entries map[string]struct {
		BinaryPath string `json:"binary_path"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return Check{Name: "hooks.binary", Status: StatusFail, Message: "parse checksums: " + err.Error()}
	}
	var drift []string
	for path, e := range entries {
		if e.BinaryPath != "" && !HookBinaryMatches(e.BinaryPath, HookBinaryIdentity{Command: binaryPath, Real: realBinary}) {
			drift = append(drift, fmt.Sprintf("%s: registered=%s running=%s", path, e.BinaryPath, binaryPath))
		}
	}
	sort.Strings(drift)
	if len(drift) > 0 {
		return Check{
			Name: "hooks.binary", Status: StatusWarn,
			Message:      fmt.Sprintf("%d hook(s) point at a different binary path - re-run %s", len(drift), remedy.Quote(initAll)),
			Details:      drift,
			Remediations: []remedy.Remediation{initAll},
		}
	}
	return Check{Name: "hooks.binary", Status: StatusOK, Message: "all hooks point at the running binary"}
}

// checkMCPRegistrations probes the three MCP config locations and reports
// which contain an observer entry pointing at the registration command
// (binaryPath, the launcher U1 registers for an npm / pip install). A
// mismatched entry's advice names the exact command that will fix it (U2):
// `observer init --skip-hooks --skip-proxy-route` when init would refresh it
// on its own (a stale entry whose binary is gone, or this same install by
// another path), with --force only when init would really refuse.
func checkMCPRegistrations(homeDir, binaryPath, realBinary string, getenv func(string) string, stableCommand bool) Check {
	c := checkMCPRegistrationsAt(homeDir, binaryPath, realBinary, getenv, stableCommand)
	c.Details = append(c.Details, stableMCPCommandNote(stableCommand))
	if !stableCommand {
		// The opt-in lives in Settings > Observer (its More settings).
		c.Remediations = append(c.Remediations, remedy.Of(remedy.OpenSettings, "observer"))
	}
	return c
}

// stableMCPCommandNote is the DEC-12 line for the managed-node bare MCP
// command (surface-gap FU-24): built, and switched off until its live check
// passes unless the operator opted in.
func stableMCPCommandNote(on bool) string {
	if on {
		return "stable MCP command ([observer.mcp] stable_command): ON by opt-in, so an org-managed Linux or macOS node registers the bare observer when PATH runs this install; not live-verified, waiting on " + installshape.PathNameLiveCheck
	}
	return "stable MCP command for managed nodes: built, waiting on " + installshape.PathNameLiveCheck + "; off by default (opt in with [observer.mcp] stable_command = true, in Settings > Observer)"
}

// checkMCPRegistrationsAt is checkMCPRegistrations before the DEC-12 note.
func checkMCPRegistrationsAt(homeDir, binaryPath, realBinary string, getenv func(string) string, stableCommand bool) Check {
	if binaryPath == "" {
		return Check{Name: "mcp.registrations", Status: StatusWarn, Message: "binary path unknown"}
	}
	cases := []struct {
		tool string
		path string
		read func(string) (mcpEntry, bool, error)
	}{
		{"claude-code", claudeGlobalConfigPath(homeDir, getenv), readJSONMCPEntry},
		{"cursor", filepath.Join(homeDir, ".cursor", "mcp.json"), readJSONMCPEntry},
		{"codex", filepath.Join(homeDir, ".codex", "config.toml"), readTOMLMCPEntry},
	}
	var registered, mismatched, absent []string
	needsForce := false
	for _, c := range cases {
		entry, ok, err := c.read(c.path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			absent = append(absent, c.tool+": "+err.Error())
			continue
		}
		switch {
		case !ok:
			absent = append(absent, c.tool)
		case entry.command == binaryPath:
			registered = append(registered, c.tool)
		case stableCommand && entry.command == "observer" && mcpregister.SameInstallCommand(entry.command, realBinary):
			// The stable bare form the opt-in registers (FU-24): PATH runs
			// this install, so it is registered, not a mismatch.
			registered = append(registered, c.tool)
		default:
			mismatched = append(mismatched, c.tool)
			if !mcpregister.InitRefreshes(entry.command, entry.args, binaryPath, realBinary) {
				needsForce = true
			}
		}
	}
	if len(mismatched) > 0 {
		fix := mcpRefreshRemedy
		why := "init refreshes them without --force (the old binary is gone, or it is this same install by another path)"
		if needsForce {
			fix = mcpForceRemedy
			why = "at least one names another program that still exists, so init only replaces it with --force"
		}
		return Check{
			Name: "mcp.registrations", Status: StatusWarn,
			Message:      fmt.Sprintf("MCP entries for %s point at a different command - run %s (%s)", strings.Join(mismatched, ", "), remedy.Quote(fix), why),
			Details:      append([]string{"registered: " + strings.Join(registered, ", ")}, "absent: "+strings.Join(absent, ", ")),
			Remediations: []remedy.Remediation{fix},
		}
	}
	if len(registered) == 0 {
		return Check{
			Name: "mcp.registrations", Status: StatusWarn,
			Message:      "no MCP registrations found - run " + remedy.Quote(initAll) + " to register",
			Details:      []string{"absent: " + strings.Join(absent, ", ")},
			Remediations: []remedy.Remediation{initAll},
		}
	}
	return Check{
		Name: "mcp.registrations", Status: StatusOK,
		Message: fmt.Sprintf("registered: %s", strings.Join(registered, ", ")),
	}
}

// mcpEntry is an observer MCP entry as doctor reads it.
type mcpEntry struct {
	command string
	args    []string
}

// mcpRefreshRemedy / mcpForceRemedy are the exact commands that rewrite only
// the MCP entries (hooks and routes untouched).
var (
	mcpRefreshRemedy = remedy.Of(remedy.Init, "--skip-hooks --skip-proxy-route")
	mcpForceRemedy   = remedy.Of(remedy.Init, "--skip-hooks --skip-proxy-route --force")
)

func readJSONMCPEntry(path string) (mcpEntry, bool, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return mcpEntry{}, false, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return mcpEntry{}, false, err
	}
	servers := map[string]struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}{}
	if raw, ok := top["mcpServers"]; ok {
		_ = json.Unmarshal(raw, &servers)
	}
	entry, ok := servers[mcpregister.ServerName]
	if !ok {
		return mcpEntry{}, false, nil
	}
	return mcpEntry{command: entry.Command, args: entry.Args}, true, nil
}

func readTOMLMCPEntry(path string) (mcpEntry, bool, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return mcpEntry{}, false, err
	}
	root := map[string]any{}
	if err := toml.Unmarshal(body, &root); err != nil {
		return mcpEntry{}, false, err
	}
	servers, _ := root["mcp_servers"].(map[string]any)
	entry, _ := servers[mcpregister.ServerName].(map[string]any)
	if entry == nil {
		return mcpEntry{}, false, nil
	}
	cmd, _ := entry["command"].(string)
	return mcpEntry{command: cmd, args: mcpregister.TOMLStringArgs(entry["args"])}, true, nil
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// checkDaemonVersion compares the running daemon's version (its lockfile)
// with this CLI's (U3, lane FIX-UPGRADE): after a package-manager upgrade the
// CLI is new while the daemon still runs the old binary, and the database
// stays on the old schema until the daemon restarts.
func checkDaemonVersion(cfg config.Config, cliVersion string) Check {
	const name = "daemon.version"
	locks, err := LiveLocks(filepath.Dir(cfg.Observer.DBPath))
	if err != nil || len(locks) == 0 {
		return Check{Name: name, Status: StatusOK, Message: "no observer daemon running on this DB"}
	}
	cli := strings.TrimPrefix(cliVersion, "v")
	if cli == "" || cli == "dev" {
		return Check{Name: name, Status: StatusOK, Message: "this CLI is a development build: version comparison skipped"}
	}
	self := os.Getpid()
	var stale []string
	for _, l := range locks {
		if l.PID == self {
			continue
		}
		d := strings.TrimPrefix(l.Version, "v")
		switch {
		case d == "":
			stale = append(stale, fmt.Sprintf("pid %d runs an older build (it predates version reporting)", l.PID))
		case d != cli:
			stale = append(stale, fmt.Sprintf("pid %d runs v%s", l.PID, d))
		}
	}
	if len(stale) == 0 {
		return Check{Name: name, Status: StatusOK, Message: "the running daemon is v" + cli + ", same as this CLI"}
	}
	return Check{
		Name: name, Status: StatusWarn,
		Message: fmt.Sprintf("the running daemon is not v%s (this CLI): %s - restart it to finish the upgrade (turn any proxy route off first, docs/daemon-restart-runbook.md)",
			cli, strings.Join(stale, "; ")),
		Remediations: []remedy.Remediation{remedy.Of(remedy.RestartDaemon, "")},
	}
}
