package diag

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/mcp"
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
	// BinaryPath is the absolute path of the running observer binary.
	// Required for hook + MCP registration checks.
	BinaryPath string
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
	r := Report{}
	r.add(checkSchema(ctx, opts.DB))
	r.add(checkDBIntegrity(ctx, opts.DB))
	r.add(checkDBSize(opts.Config, opts.HomeDir))
	r.add(checkAdapters(opts.Config))
	r.add(checkAntigravityFamily(opts.HomeDir, opts.Config))
	r.add(checkHookChecksums(opts.HomeDir))
	r.add(checkHookCommandsBinary(opts.HomeDir, opts.BinaryPath))
	r.add(checkMCPRegistrations(opts.HomeDir, opts.BinaryPath))
	r.add(checkClaudeCodePlugin(opts.HomeDir, homeOverride))
	r.add(checkPidBridge(ctx, opts.DB))
	r.add(checkConcurrentDaemons(opts.Config))
	r.add(checkCodexHookTrust(opts.HomeDir))
	r.add(checkProxyRoutingGap(ctx, opts.DB, opts.HomeDir))
	if c, ok := checkWindowsProxyRoutes(ctx, opts.Config); ok {
		r.add(c)
	}
	r.add(checkOrgEnrolment(ctx, opts.DB, opts.Config))
	r.add(checkGovernance(ctx, opts.DB, opts.Config, homeOverride))
	r.add(checkProcessObservability(ctx, opts.DB, opts.Config))
	r.add(checkHandoffReaders(ctx, opts.DB))
	r.add(checkClaudeCodeTeams(opts.Config))
	r.add(checkCodexTeams(opts.Config))
	r.add(checkCopilotTeams(opts.Config))
	r.add(checkPromptGuardWiring(opts.Config))
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
		if strings.Contains(strings.ToLower(c.Name), tool) {
			out.Checks = append(out.Checks, c)
		}
	}
	return out
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
				Message: "enrolled but [org_client] enabled = false — the org rail is NOT running (no push, no policy poll); set enabled = true in config.toml or run `observer unenroll`",
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
			Message: "[org_client] enabled but not enrolled — run `observer enroll --link <url>` to enrol",
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
			"config gap:    [org_client].org_server_url is unset — the node stays fully ACTIVE (push/announcement/routing-policy/guard-policy-poll all dial the persisted enrolment's server, %q, directly); the only effect is cosmetic — an R-205 bundle-rejection finding's Target string loses its server-URL prefix. Add org_server_url = %q to config.toml to restore that prefix", orgURL, orgURL,
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
		summary := fmt.Sprintf("last push:     %s — %s, %d rows", lastPushedAt, lastStatus, lastRows)
		if lastErr != "" {
			summary += fmt.Sprintf(" (err: %s)", lastErr)
		}
		details = append(details, summary)
		if lastStatus != "ok" {
			shareStatus = worseStatus(shareStatus, StatusWarn)
		}
	}
	msg := "enrolled — " + shareMsg
	if orgServerURLUnset {
		msg = fmt.Sprintf(
			"enrolled — ACTIVE, dialing the persisted server %s (org_server_url is unset in config; see the config gap detail for the one cosmetic thing that affects) — %s",
			orgURL, shareMsg,
		)
	}
	return Check{
		Name:    "org enrolment",
		Status:  shareStatus,
		Message: msg,
		Details: details,
	}
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
		Message: fmt.Sprintf("%d observer daemons running on the same DB — concurrent writers can desync cursor state",
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
			Message: "no pid→session entries — host tool hasn't fired SessionStart yet (re-run `observer init` after upgrading)",
		}
	}
	return Check{Name: "pidbridge.size", Status: StatusOK, Message: fmt.Sprintf("%d pid→session entries", count)}
}

func (r *Report) add(c Check) { r.Checks = append(r.Checks, c) }

// checkSchema verifies a non-zero schema version is recorded.
func checkSchema(ctx context.Context, database *sql.DB) Check {
	v, err := db.Version(ctx, database)
	if err != nil {
		return Check{Name: "db.schema", Status: StatusFail, Message: "schema_meta unreadable: " + err.Error()}
	}
	if v == 0 {
		return Check{Name: "db.schema", Status: StatusFail, Message: "no migrations applied (version 0)"}
	}
	return Check{Name: "db.schema", Status: StatusOK, Message: fmt.Sprintf("schema version %d applied", v)}
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
			Name:    "antigravity.family",
			Status:  StatusWarn,
			Message: fmt.Sprintf("%d Antigravity-CLI .pb file(s) present but [observer.antigravity] network_recovery is %q — set to \"local\" so the gRPC fallback can recover CLI conversations", cliPbs, net),
			Details: details,
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
			return Check{Name: "hooks.checksums", Status: StatusWarn, Message: "no hook_checksums.json yet — run `observer init` first"}
		}
		return Check{Name: "hooks.checksums", Status: StatusFail, Message: "read checksums: " + err.Error()}
	}
	var entries map[string]struct {
		SHA256     string `json:"sha256"`
		Registered string `json:"registered"`
		BinaryPath string `json:"binary_path"`
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
		sum := sha256.Sum256(body)
		got := hex.EncodeToString(sum[:])
		if got != want.SHA256 {
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
			Message: fmt.Sprintf("%d config file(s) modified externally — re-run `observer init` to refresh", len(drift)),
			Details: drift,
		}
	}
	return Check{Name: "hooks.checksums", Status: StatusOK, Message: fmt.Sprintf("%d config(s) match recorded checksums", matched)}
}

// checkCodexHookTrust reports whether observer-registered Codex hooks
// have been trust-approved by the user. Codex 0.129.0+ requires the
// user to manually mark each hook entry as trusted (via the codex
// `/hooks` slash command) the first time it appears; until then the
// hook is registered but won't fire. The trust state lives in
// `~/.codex/config.toml` under `[hooks.state]`, keyed by an opaque
// sha256 hash of the hook entry.
//
// The check has three outcomes:
//
//   - StatusOK if no codex hooks are registered at all (codex not
//     installed, or user opted out).
//   - StatusOK if every observer-owned hook in `~/.codex/hooks.json`
//     has a matching trusted_hash entry in config.toml.
//   - StatusWarn listing the specific event names that need trust,
//     with the exact instruction to fix.
//
// Pure read — never mutates user config. The trust hash itself isn't
// reverse-engineered (codex can change the algorithm in any release);
// we only check whether some `[hooks.state]` entry references our
// hooks.json path for a given event name. Anything keyed against our
// hooks.json counts as "the user has interacted with this entry"; the
// presence of `trusted_hash` confirms approval.
func checkCodexHookTrust(homeDir string) Check {
	hooksPath := filepath.Join(homeDir, ".codex", "hooks.json")
	configPath := filepath.Join(homeDir, ".codex", "config.toml")

	hooksRaw, err := os.ReadFile(hooksPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Check{Name: "codex.hook_trust", Status: StatusOK, Message: "no codex hooks registered"}
		}
		return Check{Name: "codex.hook_trust", Status: StatusWarn, Message: "read codex hooks.json: " + err.Error()}
	}
	var hooksFile struct {
		Hooks map[string][]struct {
			Hooks []struct {
				Type    string `json:"type"`
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(hooksRaw, &hooksFile); err != nil {
		return Check{Name: "codex.hook_trust", Status: StatusWarn, Message: "parse codex hooks.json: " + err.Error()}
	}

	// Collect event names that reference the observer binary. We
	// don't have access to the running binary path here so we sniff
	// for the `observer hook codex` command shape — narrow enough to
	// avoid false positives, broad enough to survive binary path
	// drift (the same logic the cursor-windows registration uses).
	var registered []string
	for event, groups := range hooksFile.Hooks {
		for _, g := range groups {
			for _, h := range g.Hooks {
				if h.Type == "command" && strings.Contains(h.Command, " hook codex ") {
					registered = append(registered, event)
					break
				}
			}
		}
	}
	sort.Strings(registered)
	if len(registered) == 0 {
		return Check{Name: "codex.hook_trust", Status: StatusOK, Message: "no observer-owned codex hooks found"}
	}

	// Read config.toml's [hooks.state] map. Keys look like
	// "<hooks-file-path>:<event_snake_case>:<group_index>:<hook_index>".
	cfgRaw, err := os.ReadFile(configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return codexHookTrustWarn(registered, hooksPath, "config.toml does not exist (codex never opened?)")
		}
		return Check{Name: "codex.hook_trust", Status: StatusWarn, Message: "read codex config.toml: " + err.Error()}
	}
	root := map[string]any{}
	if len(cfgRaw) > 0 {
		if err := toml.Unmarshal(cfgRaw, &root); err != nil {
			return Check{Name: "codex.hook_trust", Status: StatusWarn, Message: "parse codex config.toml: " + err.Error()}
		}
	}
	hooksState, _ := root["hooks"].(map[string]any)
	state, _ := hooksState["state"].(map[string]any)

	trustedEvents := map[string]bool{}
	for key, v := range state {
		entry, _ := v.(map[string]any)
		hash, _ := entry["trusted_hash"].(string)
		if hash == "" {
			continue
		}
		// Key shape: "<hooks-file-path>:<event_snake>:<idx>:<idx>".
		// Match by hooks-file-path prefix, then convert the snake-cased
		// event name back to CamelCase to compare against `registered`.
		if !strings.HasPrefix(key, hooksPath+":") {
			continue
		}
		rest := strings.TrimPrefix(key, hooksPath+":")
		parts := strings.SplitN(rest, ":", 2)
		if len(parts) == 0 {
			continue
		}
		camel := snakeToCamel(parts[0])
		trustedEvents[camel] = true
	}

	var untrusted []string
	for _, event := range registered {
		if !trustedEvents[event] {
			untrusted = append(untrusted, event)
		}
	}
	if len(untrusted) == 0 {
		return Check{
			Name:    "codex.hook_trust",
			Status:  StatusOK,
			Message: fmt.Sprintf("all %d codex hook(s) are trust-approved", len(registered)),
		}
	}
	return codexHookTrustWarn(untrusted, hooksPath, "")
}

func codexHookTrustWarn(events []string, hooksPath, extra string) Check {
	msg := fmt.Sprintf("%d codex hook(s) need trust approval — open `codex` and run /hooks to mark them trusted", len(events))
	if extra != "" {
		msg += " (" + extra + ")"
	}
	details := []string{
		"untrusted: " + strings.Join(events, ", "),
		"hooks file: " + hooksPath,
		"why: codex requires per-hook user trust before dispatch (security feature; no programmatic shortcut)",
	}
	return Check{Name: "codex.hook_trust", Status: StatusWarn, Message: msg, Details: details}
}

// snakeToCamel converts e.g. "session_start" → "SessionStart". Used to
// match codex's snake-cased trust-state event keys against our CamelCase
// hooks.json event names. Pure ASCII; codex doesn't use unicode events.
func snakeToCamel(s string) string {
	if s == "" {
		return ""
	}
	parts := strings.Split(s, "_")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, "")
}

// checkHookCommandsBinary looks at every recorded hook config and verifies
// the command it points to is the running observer binary. Mismatch
// usually means the binary was moved after `observer init`.
func checkHookCommandsBinary(homeDir, binaryPath string) Check {
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
		if e.BinaryPath != "" && e.BinaryPath != binaryPath {
			drift = append(drift, fmt.Sprintf("%s: registered=%s running=%s", path, e.BinaryPath, binaryPath))
		}
	}
	sort.Strings(drift)
	if len(drift) > 0 {
		return Check{
			Name: "hooks.binary", Status: StatusWarn,
			Message: fmt.Sprintf("%d hook(s) point at a different binary path — re-run `observer init`", len(drift)),
			Details: drift,
		}
	}
	return Check{Name: "hooks.binary", Status: StatusOK, Message: "all hooks point at the running binary"}
}

// checkMCPRegistrations probes the three MCP config locations and reports
// which contain an observer entry pointing at the running binary.
func checkMCPRegistrations(homeDir, binaryPath string) Check {
	if binaryPath == "" {
		return Check{Name: "mcp.registrations", Status: StatusWarn, Message: "binary path unknown"}
	}
	cases := []struct {
		tool string
		path string
		read func(string, string) (registered bool, mismatch bool, err error)
	}{
		{"claude-code", filepath.Join(homeDir, ".claude.json"), readJSONMCPEntry},
		{"cursor", filepath.Join(homeDir, ".cursor", "mcp.json"), readJSONMCPEntry},
		{"codex", filepath.Join(homeDir, ".codex", "config.toml"), readTOMLMCPEntry},
	}
	var registered, mismatched, absent []string
	for _, c := range cases {
		reg, mismatch, err := c.read(c.path, binaryPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			absent = append(absent, c.tool+": "+err.Error())
			continue
		}
		switch {
		case mismatch:
			mismatched = append(mismatched, c.tool)
		case reg:
			registered = append(registered, c.tool)
		default:
			absent = append(absent, c.tool)
		}
	}
	if len(mismatched) > 0 {
		return Check{
			Name: "mcp.registrations", Status: StatusWarn,
			Message: fmt.Sprintf("MCP entries for %s point at a different binary — re-run `observer init`", strings.Join(mismatched, ", ")),
			Details: append([]string{"registered: " + strings.Join(registered, ", ")}, "absent: "+strings.Join(absent, ", ")),
		}
	}
	if len(registered) == 0 {
		return Check{
			Name: "mcp.registrations", Status: StatusWarn,
			Message: "no MCP registrations found — run `observer init` to register",
			Details: []string{"absent: " + strings.Join(absent, ", ")},
		}
	}
	return Check{
		Name: "mcp.registrations", Status: StatusOK,
		Message: fmt.Sprintf("registered: %s", strings.Join(registered, ", ")),
	}
}

func readJSONMCPEntry(path, binary string) (registered, mismatch bool, err error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return false, false, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return false, false, err
	}
	servers := map[string]struct {
		Command string `json:"command"`
	}{}
	if raw, ok := top["mcpServers"]; ok {
		_ = json.Unmarshal(raw, &servers)
	}
	entry, ok := servers[mcp.ServerName]
	if !ok {
		return false, false, nil
	}
	if entry.Command == binary {
		return true, false, nil
	}
	return true, true, nil
}

func readTOMLMCPEntry(path, binary string) (registered, mismatch bool, err error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return false, false, err
	}
	root := map[string]any{}
	if err := toml.Unmarshal(body, &root); err != nil {
		return false, false, err
	}
	servers, _ := root["mcp_servers"].(map[string]any)
	entry, _ := servers[mcp.ServerName].(map[string]any)
	if entry == nil {
		return false, false, nil
	}
	cmd, _ := entry["command"].(string)
	if cmd == binary {
		return true, false, nil
	}
	return true, true, nil
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}
