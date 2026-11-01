package guard

import (
	"context"
	"io/fs"
	"strings"
	"syscall"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// unreadableBundleFS serves files like fsMap, except the org bundle path,
// whose read fails the way a path the guard cannot read does (D-704, guard
// tamper re-test shape 3: a read-only directory planted at the bundle path,
// or a file this user may not read).
func unreadableBundleFS(files map[string]string, errno syscall.Errno) func(string) ([]byte, error) {
	inner := fsMap(files)
	return func(p string) ([]byte, error) {
		if strings.ReplaceAll(p, `\`, "/") == orgBundlePath {
			return nil, &fs.PathError{Op: "read", Path: p, Err: errno}
		}
		return inner(p)
	}
}

// TestUnreadableBundleKeepsTheLastVerifiedOrgLayer pins D-704 fix 1: while
// the bundle path cannot be read, a managed node keeps enforcing the last
// verified org layer (from construction, and across a live reload), records
// the tamper, and the posture loop's file check names the failure.
func TestUnreadableBundleKeepsTheLastVerifiedOrgLayer(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		errno syscall.Errno
	}{
		{"a directory planted at the bundle path", syscall.EISDIR},
		{"a bundle file this user may not read", syscall.EACCES},
	} {
		t.Run(tc.name+": construction", func(t *testing.T) {
			t.Parallel()
			env, pin := signedEnvelope(t, 704, orgOverridableBundleTOML)
			cfg := guardCfgOrg()
			cfg.Mode = "enforce"
			cfg.Lock = managedLock(env, pin)
			g, err := New(Options{
				Config: cfg, Home: "/home/u", KnownProjectRoots: []string{"/home/u/proj"},
				ReadFile: unreadableBundleFS(map[string]string{}, tc.errno),
			})
			if err != nil {
				t.Fatalf("guard.New: %v", err)
			}
			g.SetApprovalLookup(func(string, string, string) bool { return true })
			av, _ := g.EvaluateHook(rmRfEvent())
			if av.Verdict.Decision != policy.DecisionDeny {
				t.Fatalf("rm -rf / = %v (%s), want deny from the last verified org layer (issues %v)", av.Verdict.Decision, av.Verdict.Reason, g.LoadIssues())
			}
			if _, locked := g.OrgOverrideStatus("R-101"); !locked {
				t.Fatal("the org lock was dropped while the bundle path is unreadable")
			}
			st := g.OrgLockStatus()
			if !st.LastVerifiedInUse || !st.BundleTampered {
				t.Fatalf("OrgLockStatus = %+v, want the last verified copy in use and the tamper recorded", st)
			}
		})
		t.Run(tc.name+": live reload", func(t *testing.T) {
			t.Parallel()
			env, pin := signedEnvelope(t, 705, orgOverridableBundleTOML)
			files := map[string]string{orgBundlePath: env}
			unreadable := false
			cfg := guardCfgOrg()
			cfg.Mode = "enforce"
			g, err := New(Options{
				Config: cfg, Home: "/home/u", OrgKeyPinHash: pin, OrgBundleExpected: true,
				ReadFile: func(p string) ([]byte, error) {
					if unreadable {
						return unreadableBundleFS(files, tc.errno)(p)
					}
					return fsMap(files)(p)
				},
				ManagedTenancy: func() bool { return true },
			})
			if err != nil {
				t.Fatal(err)
			}
			unreadable = true
			if err := g.ReloadOrgLayer(context.Background()); err == nil {
				t.Fatal("reload over an unreadable bundle path returned nil")
			}
			if issue, _ := g.OrgBundleFileIssue(); issue == "" {
				t.Fatal("OrgBundleFileIssue is silent about an unreadable bundle path")
			}
			if _, locked := g.OrgOverrideStatus("R-101"); !locked {
				t.Fatal("the live guard dropped the org lock")
			}
			if !g.OrgLockStatus().BundleTampered {
				t.Fatal("the unreadable bundle path was not recorded as a tamper")
			}
		})
	}
}
