//go:build !sbo_omit_security

package secsvc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// labelReader is a BaselineWriter holding one baseline, optionally with the
// org's approval reader (OrgBaselineApprovals).
type labelReader struct {
	b store.SecBaseline
}

func (r labelReader) AddSecBaseline(context.Context, store.SecBaseline) error { return nil }
func (r labelReader) LatestSecBaseline(context.Context, string) (store.SecBaseline, bool, error) {
	return r.b, true, nil
}

type labelReaderWithOrg struct {
	labelReader
	approved map[string]string
	err      error
}

func (r labelReaderWithOrg) SecOrgBaselineApproval(_ context.Context, rootHash, kind, ref string) (string, bool, error) {
	at, ok := r.approved[rootHash+"|"+kind+"|"+ref]
	return at, ok, r.err
}

// noGit answers every git call with an error (no commits to offer).
func noGit(context.Context, string, int, time.Duration, ...string) ([]byte, bool, error) {
	return nil, false, errors.New("no git")
}

// TestLoadBaselineViewOrgLabel (lane LEFT-SHARED): the org's approval of the
// project's own reference labels the baseline; a reader without approvals,
// another reference or an unreadable approval leaves it unlabelled, never an
// error; the baseline itself is unchanged either way.
func TestLoadBaselineViewOrgLabel(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	hash := secposture.ProjectRootHash(root)
	base := labelReader{b: store.SecBaseline{ProjectRootHash: hash, Kind: "commit", Ref: "c1", Approver: "cli"}}
	cases := []struct {
		name string
		r    BaselineWriter
		want string
	}{
		{"no approval reader (an older store)", base, ""},
		{"approved", labelReaderWithOrg{labelReader: base, approved: map[string]string{hash + "|commit|c1": "2026-10-24T10:00:00Z"}}, "2026-10-24T10:00:00Z"},
		{"another reference approved", labelReaderWithOrg{labelReader: base, approved: map[string]string{hash + "|commit|c2": "2026-10-24T10:00:00Z"}}, ""},
		{"unreadable approvals", labelReaderWithOrg{labelReader: base, approved: map[string]string{hash + "|commit|c1": "x"}, err: errors.New("db gone")}, ""},
	}
	for _, c := range cases {
		v, err := LoadBaselineView(ctx, noGit, c.r, root)
		if err != nil || v.Current == nil {
			t.Fatalf("%s: %+v %v", c.name, v, err)
		}
		if v.Current.OrgApprovedAt != c.want || v.Current.Ref != "c1" || v.Current.Approver != "cli" {
			t.Errorf("%s: current %+v, want org label %q", c.name, v.Current, c.want)
		}
	}
}
