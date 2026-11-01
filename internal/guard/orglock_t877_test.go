package guard

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// Outcome texts the T-877 rows render (orgLayerOutcomeRows).
const (
	outcomeLockedDown = "no verified org layer is available, so local approvals are refused for every rule until a verified bundle is back"
	outcomeWithout    = "running without the org layer"
)

func outcomeEnforcing(version int64) string {
	return "enforcing the last verified org layer (version " + strconv.FormatInt(version, 10) + ")"
}

// orgBundleIssue returns the one load issue about the org bundle.
func orgBundleIssue(t *testing.T, g *Guard) string {
	t.Helper()
	var out []string
	for _, is := range g.LoadIssues() {
		if strings.HasPrefix(is, "org bundle ") {
			out = append(out, is)
		}
	}
	if len(out) != 1 {
		t.Fatalf("org bundle issues = %q, want exactly one", out)
	}
	return out[0]
}

// TestOrgBundleIssueSaysWhatIsEnforced pins T-877 (guard tamper re-test
// 2026-10-17): the load issue `observer guard status` prints as LOAD ISSUE
// says what the guard enforces in each state, instead of "running without
// the org layer" while the last verified layer was in force. One row per
// outcome row, plus the shapes that reach them.
func TestOrgBundleIssueSaysWhatIsEnforced(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		lock    func(env, pin string) config.GuardOrgLock
		tenancy func() bool
		deleted bool
		want    func(version int64) string
	}{
		{"managed, edited bundle: the last verified copy", managedLock, nil, false, outcomeEnforcing},
		{"managed, deleted bundle: the last verified copy", managedLock, nil, true, outcomeEnforcing},
		{"bundle and lock deleted, org expected: locked down", anchoredTamperedLock, nil, true, func(int64) string { return outcomeLockedDown }},
		{"no lock, edited bundle, tenancy unresolved: locked down", noLock, nil, false, func(int64) string { return outcomeLockedDown }},
		{"no lock, edited bundle, managed: locked down", noLock, func() bool { return true }, false, func(int64) string { return outcomeLockedDown }},
		{"individual node, edited bundle, no copy: without the org layer", noLock, func() bool { return false }, false, func(int64) string { return outcomeWithout }},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			version := int64(1100 + i)
			env, pin := signedEnvelope(t, version, orgOverridableBundleTOML)
			files := map[string]string{orgBundlePath: tamperEnvelope(t, env)}
			if tc.deleted {
				files = map[string]string{}
			}
			cfg := guardCfgOrg()
			cfg.Mode = "enforce"
			cfg.Lock = tc.lock(env, pin)
			g, err := New(Options{
				Config: cfg, Home: "/home/u", KnownProjectRoots: []string{"/home/u/proj"},
				ReadFile: fsMap(files), ManagedTenancy: tc.tenancy,
			})
			if err != nil {
				t.Fatalf("guard.New: %v", err)
			}
			issue := orgBundleIssue(t, g)
			if want := tc.want(version); !strings.HasSuffix(issue, " - "+want) {
				t.Fatalf("issue = %q, want it to end with %q", issue, want)
			}
			if strings.Count(issue, " - ") != 1 {
				t.Fatalf("issue %q states the outcome more than once", issue)
			}
		})
	}
}

// TestDaemonBundleIssueNamesTheLiveLayer: the daemon's posture check
// (OrgBundleFileIssue, the admin's guard event) and a failed reload both say
// the running guard keeps the org layer it loaded, by version, for an edited
// and for a deleted bundle (T-877; the re-test event read "running without
// the org layer").
func TestDaemonBundleIssueNamesTheLiveLayer(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		tamper func(files map[string]string, env string)
	}{
		{"edited", func(files map[string]string, env string) {
			files[orgBundlePath] = strings.Replace(env, "R-110", "R-111", 1)
		}},
		{"deleted", func(files map[string]string, _ string) { delete(files, orgBundlePath) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			const version = 1200
			env, pin := signedEnvelope(t, version, orgOverridableBundleTOML)
			files := map[string]string{orgBundlePath: env}
			cfg := guardCfgOrg()
			cfg.Mode = "enforce"
			g, err := New(Options{
				Config: cfg, Home: "/home/u", OrgKeyPinHash: pin, OrgBundleExpected: true,
				ReadFile:       func(p string) ([]byte, error) { return fsMap(files)(p) },
				ManagedTenancy: func() bool { return true },
			})
			if err != nil {
				t.Fatal(err)
			}
			tc.tamper(files, env)
			want := " - " + outcomeEnforcing(version)
			if issue, _ := g.OrgBundleFileIssue(); !strings.HasSuffix(issue, want) {
				t.Fatalf("file issue = %q, want it to end with %q", issue, want)
			}
			err = g.ReloadOrgLayer(context.Background())
			if err == nil || !strings.HasSuffix(err.Error(), want) {
				t.Fatalf("reload error = %v, want it to end with %q", err, want)
			}
		})
	}
}
