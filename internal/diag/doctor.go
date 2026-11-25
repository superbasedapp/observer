package diag

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
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
	r.addAll(checkWindowsHookShells(homeOverride, opts.BinaryPath, opts.Getenv))
	r.addAll(checkCopilotCLIPowerShellOnHost(homeOverride, opts.BinaryPath, opts.Getenv))
	r.addAll(checkWindowsHookRunners(ctx, homeOverride, opts.BinaryPath, opts.Getenv))
	r.addAll(checkCrossOSLiveGated(homeOverride, opts.BinaryPath))
	r.addIf(checkRemoteHosts(opts.HomeDir, homeOverride != ""))
	r.addIf(checkCodexInWSL(opts.HomeDir, homeOverride != ""))
	r.addIf(checkWindowsSideRelocation(homeOverride, opts.BinaryPath))
	// Gates reached through another tool's hook registration (W-2b).
	r.addAll(checkReplayedVia(ctx, opts.HomeDir, opts.BinaryPath, opts.DB, time.Now()))
	r.add(checkCursorUsage(ctx, opts.DB, cursorFinishHooksWiring(cursorHooksFiles(opts.HomeDir, homeOverride))))
	r.add(checkPidBridge(ctx, opts.DB))
	r.add(checkConcurrentDaemons(opts.Config))
	r.add(checkDaemonVersion(opts.Config, opts.CLIVersion))
	r.add(checkCodexHookTrust(opts.HomeDir))
	r.addAll(checkForeignCodexHookTrust(homeOverride))
	r.add(checkRoutePort(opts.HomeDir, opts.Config))
	r.add(checkProxyClientAuth(opts.HomeDir, opts.Config))
	r.add(checkRouteHost(opts.HomeDir, opts.RouteSelection))
	r.addAll(checkRecordedRoutes(opts.HomeDir))
	r.addAll(checkRouteHold(opts.HomeDir))
	r.add(checkSupervisor(opts.HomeDir, supervisor.OSProbe()))
	r.add(checkCodexProviderRoute(opts.HomeDir, opts.Getenv, codexSystemRequirementsPath()))
	r.add(checkLiveGatedWriters())
	r.addAll(checkSurfaceCoverage(opts.HomeDir, homeOverride != "", opts.Getenv))
	r.add(checkRouteObserved(ctx, opts.DB, time.Now(), nil))
	r.addIf(checkWindowsProxyRoutes(ctx, opts.Config))
	r.addAll(checkRelay(homeOverride, time.Now()))
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
	r.addIf(checkCrossmountRow())
	r.addAll(opts.ExtraChecks)
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

// addAll appends every check of a family that reports several (or none).
func (r *Report) addAll(cs []Check) { r.Checks = append(r.Checks, cs...) }

// addIf appends c when ok, for a check that applies only on some hosts.
func (r *Report) addIf(c Check, ok bool) {
	if ok {
		r.add(c)
	}
}

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
		Message: fmt.Sprintf("the running daemon is not v%s (this CLI): %s - restart it to finish the upgrade: observer service restart (it takes the proxy routes off first and puts them back)",
			cli, strings.Join(stale, "; ")),
		Remediations: []remedy.Remediation{remedy.Of(remedy.RestartDaemon, "")},
	}
}
