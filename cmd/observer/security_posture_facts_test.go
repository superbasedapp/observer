//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policyfam/securityscanning"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

type fakeContentStates map[content.Kind]content.State

func (f fakeContentStates) State(k content.Kind) (content.State, error) {
	if st, ok := f[k]; ok {
		return st, nil
	}
	return content.State{}, errors.New("not installed")
}

// TestSecurityPostureDatabaseAges (lane SEC-H2): one row per bucket, the
// OSV exports read the older of the content channel and the node's own OSV
// database, and a database never installed is "never".
func TestSecurityPostureDatabaseAges(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		at   time.Time
		want string
	}{
		{time.Time{}, "never"},
		{now.Add(-time.Hour), "under_1d"},
		{now.Add(-48 * time.Hour), "under_7d"},
		{now.Add(-10 * 24 * time.Hour), "over_7d"},
	} {
		if got := databaseAgeBucket(c.at, now); got != c.want {
			t.Errorf("%v: %s, want %s", c.at, got, c.want)
		}
	}
	cs := fakeContentStates{
		content.MaliciousPackages: {IssuedAt: now.Add(-2 * time.Hour).Format(time.RFC3339)},
		content.OSVExport:         {IssuedAt: now.Add(-time.Hour).Format(time.RFC3339)},
	}
	osv := map[string]osvdb.Epoch{
		"npm":  {CRC32C: "a", FetchedAt: now.Add(-9 * 24 * time.Hour)},
		"PyPI": {CRC32C: "", FetchedAt: now.Add(-30 * 24 * time.Hour)}, // not installed: ignored
	}
	got := map[string]string{}
	for _, d := range securityDatabaseAges(cs, osv, now) {
		got[d.Kind] = d.Bucket
	}
	want := map[string]string{"malicious_packages": "under_1d", "popular_names": "never", "osv_export": "over_7d", "agent_cve_table": "never"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %s, want %s", k, got[k], v)
		}
	}
}

// TestSecurityPostureFactsPlatformGaps: only an active driver short of
// supported on the platform is named; an inactive one never is.
func TestSecurityPostureFactsPlatformGaps(t *testing.T) {
	if g := securityPlatformGaps(map[string]bool{}, "windows", "amd64"); len(g) != 0 {
		t.Fatalf("inactive drivers named: %+v", g)
	}
	all := map[string]bool{"security.scan.scalibr": true, "security.scan.osv": true}
	if g := securityPlatformGaps(all, "linux", "amd64"); len(g) != 0 {
		t.Fatalf("linux/amd64 is supported by both: %+v", g)
	}
	g := securityPlatformGaps(all, "plan9", "386")
	if len(g) != 2 || g[0].Support != "unsupported" {
		t.Fatalf("an unknown platform is unsupported for every active driver: %+v", g)
	}
}

// TestSecurityPostureDaemonFactsNeedALoadedBase (SEC-H2 merge, audit
// finding 4): a daemon whose base config did not load (empty config path)
// reports neither daemon fact, so no database ages are read from a default
// home; a loaded base reports both.
func TestSecurityPostureDaemonFactsNeedALoadedBase(t *testing.T) {
	setTestHome(t, t.TempDir())
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	facts := securityscanning.NodeFacts{Active: map[string]bool{"security.scan.osv": true}}
	var row orgcontract.SecurityPostureRow
	securityPostureDaemonFacts(&row, facts, "", now)
	if len(row.Reported) != 0 || row.DatabaseAges != nil || row.PlatformGaps != nil {
		t.Fatalf("an unloaded base reported daemon facts: %+v", row)
	}
	var loaded orgcontract.SecurityPostureRow
	securityPostureDaemonFacts(&loaded, facts, filepath.Join(t.TempDir(), "config.toml"), now)
	if !slices.Contains(loaded.Reported, "database_ages") || !slices.Contains(loaded.Reported, "platform_gaps") || len(loaded.DatabaseAges) == 0 {
		t.Fatalf("a loaded base must report both facts: %+v", loaded)
	}
}
