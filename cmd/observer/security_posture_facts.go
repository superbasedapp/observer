//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"path/filepath"
	"runtime"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policyfam/securityscanning"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// security_posture_facts.go adds the two posture facts only the daemon
// knows (lane SEC-H2, security plan 7.4's table): the age bucket of each
// advisory or content database the node holds, and the active scanner
// drivers whose support on this platform is short of supported. Enums only:
// no path, version or name beyond a driver id. Both are named in the row's
// Reported list, so a newer server tells "none" from "not reported". Built
// only with the dependency checks (sbo_omit_security_deps links
// security_posture_facts_omit.go, which reports neither).

// securityDatabaseKinds maps each content kind to its wire name.
var securityDatabaseKinds = []struct {
	kind content.Kind
	wire string
}{
	{content.MaliciousPackages, "malicious_packages"},
	{content.PopularNames, "popular_names"},
	{content.OSVExport, "osv_export"},
	{content.AgentCVETable, "agent_cve_table"},
}

// securityDatabaseAgeBucket is the bucket table (CLAUDE.md rule 5), walked
// top down; a database never installed is "never".
var securityDatabaseAgeBucket = []struct {
	under  time.Duration
	bucket string
}{
	{24 * time.Hour, "under_1d"},
	{7 * 24 * time.Hour, "under_7d"},
}

// databaseAgeBucket buckets one database's age (zero time: never).
func databaseAgeBucket(at, now time.Time) string {
	if at.IsZero() {
		return "never"
	}
	age := now.Sub(at)
	for _, b := range securityDatabaseAgeBucket {
		if age < b.under {
			return b.bucket
		}
	}
	return "over_7d"
}

// securityDatabaseAges reads each database's issue time from the content
// channel store, and for the OSV exports the oldest installed export in the
// node's own OSV database when it holds one (an individual node downloads
// them itself; a managed node may take them from the org mirror).
func securityDatabaseAges(cs securityContentStates, osv map[string]osvdb.Epoch, now time.Time) []orgcontract.SecurityDatabaseAge {
	out := make([]orgcontract.SecurityDatabaseAge, 0, len(securityDatabaseKinds))
	for _, k := range securityDatabaseKinds {
		var at time.Time
		if st, err := cs.State(k.kind); err == nil && st.IssuedAt != "" {
			at, _ = time.Parse(time.RFC3339, st.IssuedAt)
		}
		if k.kind == content.OSVExport {
			if oldest := oldestOSVEpoch(osv); !oldest.IsZero() && (at.IsZero() || oldest.Before(at)) {
				at = oldest
			}
		}
		out = append(out, orgcontract.SecurityDatabaseAge{Kind: k.wire, Bucket: databaseAgeBucket(at, now)})
	}
	return out
}

// securityContentStates is the content channel store's read (a seam for
// tests).
type securityContentStates interface {
	State(kind content.Kind) (content.State, error)
}

// oldestOSVEpoch is the fetch time of the oldest installed ecosystem
// export, zero when none is installed.
func oldestOSVEpoch(m map[string]osvdb.Epoch) time.Time {
	var oldest time.Time
	for _, e := range m {
		if e.Installed() && (oldest.IsZero() || e.FetchedAt.Before(oldest)) {
			oldest = e.FetchedAt
		}
	}
	return oldest
}

// securityPlatformGapRows are the scanner driver rows whose platform cells
// the posture reads, with the component that runs each.
func securityPlatformGapRows() []secscan.DriverRow {
	return []secscan.DriverRow{depscan.ScalibrRow(nil), depscan.OSVRow()}
}

// securityPlatformGaps lists each ACTIVE driver whose support on goos/goarch
// is short of supported.
func securityPlatformGaps(active map[string]bool, goos, goarch string) []orgcontract.SecurityPlatformGap {
	var out []orgcontract.SecurityPlatformGap
	for _, row := range securityPlatformGapRows() {
		if !active[row.ComponentID] {
			continue
		}
		if s := depscan.PlatformSupport(row, goos, goarch, ""); s != secscan.SupportSupported {
			out = append(out, orgcontract.SecurityPlatformGap{Driver: row.ID, Support: string(s)})
		}
	}
	return out
}

// securityPostureDaemonFacts adds the daemon facts to a posture row while
// the security module runs. A config path that does not resolve reports
// no database ages (rather than "never" for every one). An empty config
// path is a daemon whose base config did not load: neither fact is
// reported, so no database ages are read from a default home (SEC-H2
// merge, audit finding 4; config.ResolveGlobalPath("") would fall back to
// ~/.observer).
func securityPostureDaemonFacts(row *orgcontract.SecurityPostureRow, facts securityscanning.NodeFacts, configPath string, now time.Time) {
	if facts.ModuleOff || configPath == "" {
		return
	}
	row.PlatformGaps = securityPlatformGaps(facts.Active, runtime.GOOS, runtime.GOARCH)
	row.Reported = append(row.Reported, "platform_gaps")
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return
	}
	dir := secposture.LayoutFor(resolved).Dir
	osv, _ := osvdb.Open(filepath.Join(dir, "osv")).Epochs()
	row.DatabaseAges = securityDatabaseAges(depsContentStore(resolved), osv, now)
	row.Reported = append(row.Reported, "database_ages")
}
