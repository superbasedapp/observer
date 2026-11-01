//go:build !sbo_omit_security

package secsvc

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// TestComputeFillsTheProjectAudienceFields pins lane sec-p's one change to the
// posture writer: the reserved OrgProjectIDs and AssignmentEpoch come from
// Options.ProjectMatch (the core match record), keyed by the root hash, and
// stay empty without it.
func TestComputeFillsTheProjectAudienceFields(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	s, _ := newSvc(t, &fakeStore{}, now)
	f, err := s.Compute(context.Background(), "/a", now)
	if err != nil || f.OrgProjectIDs != nil || f.AssignmentEpoch != 0 {
		t.Fatalf("without a matcher: %+v %v", f, err)
	}
	s.o.ProjectMatch = func(hash string) ([]string, uint64) {
		if hash == secposture.ProjectRootHash("/a") {
			return []string{"X"}, 4
		}
		return nil, 0
	}
	f, err = s.Compute(context.Background(), "/a", now)
	if err != nil || !reflect.DeepEqual(f.OrgProjectIDs, []string{"X"}) || f.AssignmentEpoch != 4 {
		t.Fatalf("with a matcher: ids=%v epoch=%d err=%v", f.OrgProjectIDs, f.AssignmentEpoch, err)
	}
}
