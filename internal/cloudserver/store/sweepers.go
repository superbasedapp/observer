package store

// sweepers.go is the closed table of every exported sweep-like Store method
// and where it is run (findings 2026-11-22 CLOUD-01). The sweepers used to be
// wired one at a time by hand, and SweepExpiredEvidence was written, tested
// and promised by the docs but never scheduled, so evidence outlived its
// one-hour TTL whenever its job never ended. TestEveryStoreSweepHasASweeperRow
// (sweepers_test.go) parses this package and fails when an exported method
// whose name looks like a sweep has no row here, when a row names a method
// that no longer exists, or when the package a row names as its site holds no
// reference to the method (a call or a method value) in non-test code.
//
// Adding a sweep-like method therefore means adding its row: either the
// process and package that schedule it, or the reason it is not on a timer.

// sweeperRun says how a sweep-like Store method is run.
type sweeperRun string

const (
	// sweeperLoop is a ticker in a long-running process that is always on.
	sweeperLoop sweeperRun = "loop"
	// sweeperConditionalLoop is a ticker that runs only when its feature is
	// configured; the row's note says why nothing needs sweeping otherwise.
	sweeperConditionalLoop sweeperRun = "conditional-loop"
	// sweeperOperator is an operator command, never a timer; the row's note
	// says why that is enough.
	sweeperOperator sweeperRun = "operator"
)

// sweeper is one row of the sweepers table.
type sweeper struct {
	// method is the exported Store method.
	method string
	// run is how it is run.
	run sweeperRun
	// process is the observer-cloud process (serve or worker) or the
	// operator command that runs it.
	process string
	// site is the repository-relative package directory whose non-test code
	// references the method, by a call or a method value.
	site string
	// cadence is how often it runs.
	cadence string
	// note explains a conditional or operator row; a plain loop needs none.
	note string
}

// sweepers is the table, one row per exported sweep-like Store method.
var sweepers = []sweeper{
	{
		method: "SweepExpiredEvidence", run: sweeperLoop, process: "worker",
		site:    "internal/cloudserver/jobs",
		cadence: "at start, then every SBCI_EVIDENCE_SWEEP_INTERVAL (default 5m, 10s to 15m)",
		note:    "jobs.StartEvidenceSweeper; the worker role holds EXECUTE since cloud migration 0151",
	},
	{
		method: "SweepResultsRetention", run: sweeperLoop, process: "worker",
		site: "cmd/observer-cloud", cadence: "at start, then daily",
	},
	{
		method: "MinimiseOrgUsageDays", run: sweeperLoop, process: "worker",
		site: "cmd/observer-cloud", cadence: "at start, then daily (the org usage retention pass)",
	},
	{
		method: "ExpireOrgUsageDays", run: sweeperLoop, process: "worker",
		site: "cmd/observer-cloud", cadence: "at start, then daily (the org usage retention pass)",
	},
	{
		method: "PruneOrphanCommunitySnapshots", run: sweeperLoop, process: "worker",
		site: "cmd/observer-cloud", cadence: "at start, then hourly (the end of each community materialization pass)",
	},
	{
		method: "SweepExpiredPoPReplay", run: sweeperLoop, process: "serve",
		site: "cmd/observer-cloud", cadence: "every minute",
	},
	{
		method: "SweepExpiredExports", run: sweeperLoop, process: "serve",
		site: "cmd/observer-cloud", cadence: "every minute",
	},
	{
		method: "SweepExpiredCheckoutIntents", run: sweeperLoop, process: "serve",
		site: "cmd/observer-cloud", cadence: "every minute",
	},
	{
		method: "SweepRetention", run: sweeperLoop, process: "serve",
		site: "cmd/observer-cloud", cadence: "hourly",
	},
	{
		method: "SweepOIDCCodes", run: sweeperConditionalLoop, process: "serve",
		site: "cmd/observer-cloud", cadence: "every minute, while the platform OIDC issuer is on",
		note: "runs only when SBCI_OIDC_ISSUER is set; with the issuer off no authorization code is minted, so there is nothing to sweep. Passed as a method value to runOIDCMaintenance, not called directly",
	},
	{
		method: "ReapplyOrgDeletionsFromJournal", run: sweeperOperator, process: "observer-cloud restore-suppress",
		site: "cmd/observer-cloud", cadence: "on demand, after a point-in-time restore",
		note: "not a sweep of expired rows: it re-arms the org deletions the journal records after a restore, so it runs when the operator restores, never on a timer (its name matches the Reap prefix only)",
	},
}
