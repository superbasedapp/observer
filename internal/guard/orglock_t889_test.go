package guard

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// TestOrgBundleNoteFollowsTheCause pins T-889 (guard tamper re-test
// 2026-10-17, case 7 A2): with the bundle file DELETED, `observer guard
// status` printed a correct LOAD ISSUE ("... is missing although this node
// accepted a verified bundle - enforcing the last verified org layer") next to
// a NOTE that said "failed verification" and an "Org bundle:" line that said
// "does not verify". The NOTE (the layer's PolicyState note) and the status
// word (OrgLockStatus.BundleProblem) now follow the actual cause, one row per
// orgBundleCauseWords entry.
func TestOrgBundleNoteFollowsTheCause(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		file       func(env string) (body string, readErr error, present bool)
		wantNote   string
		wantStatus string
	}{
		{
			"edited bundle", func(env string) (string, error, bool) { return tamperEnvelope(t, env), nil, true },
			"failed verification", "does not verify",
		},
		{
			"deleted bundle", func(string) (string, error, bool) { return "", nil, false },
			"is missing", "is missing",
		},
		{
			"unreadable bundle", func(string) (string, error, bool) { return "", errors.New("permission denied"), false },
			"could not be read", "could not be read",
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			version := int64(1300 + i)
			env, pin := signedEnvelope(t, version, orgOverridableBundleTOML)
			body, readErr, present := tc.file(env)
			read := func(p string) ([]byte, error) {
				if strings.ReplaceAll(p, "\\", "/") == orgBundlePath {
					switch {
					case readErr != nil:
						return nil, readErr
					case present:
						return []byte(body), nil
					}
				}
				return fsMap(nil)(p)
			}
			cfg := guardCfgOrg()
			cfg.Mode = "enforce"
			cfg.Lock = managedLock(env, pin)
			g, err := New(Options{Config: cfg, Home: "/home/u", KnownProjectRoots: []string{"/home/u/proj"}, ReadFile: read})
			if err != nil {
				t.Fatalf("guard.New: %v", err)
			}
			var notes []string
			for _, st := range g.PolicyStates() {
				if st.Layer == layerOrg {
					notes = append(notes, st.Notes...)
				}
			}
			// The note carries the natively joined path (backslashes on
			// Windows).
			want := "org bundle " + filepath.FromSlash(orgBundlePath) + " " + tc.wantNote + "; " + outcomeEnforcing(version) +
				" until the organization's next accepted bundle"
			if len(notes) != 1 || notes[0] != want {
				t.Fatalf("org layer notes = %q, want [%q]", notes, want)
			}
			st := g.OrgLockStatus()
			if !st.LastVerifiedInUse || st.BundleProblem != tc.wantStatus {
				t.Fatalf("status = %+v, want the last verified layer and problem %q", st, tc.wantStatus)
			}
		})
	}
}

// TestOrgBundleCauseWordsCoverEveryCause: every cause has both words, and an
// unknown cause reads as the historical "does not verify".
func TestOrgBundleCauseWordsCoverEveryCause(t *testing.T) {
	t.Parallel()
	for c := bundleCauseRejected; c <= bundleCauseUnreadable; c++ {
		if w := c.words(); w.status == "" || w.note == "" {
			t.Errorf("cause %d has no wording: %+v", c, w)
		}
	}
	if w := orgBundleCause(99).words(); w.status != "does not verify" {
		t.Errorf("unknown cause reads %q", w.status)
	}
}
