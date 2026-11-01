//go:build !sbo_omit_security

package secsvc

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secexcept"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestSyncOrgExceptions is the node half of finding_exception (lane
// SEC-E3): an honoured grant moves its open finding out of open under
// granted_by org:<id>, capped at the grant's expiry; a grant for another
// rule or an unknown finding applies nothing; a grant that is no longer
// honoured ends the exception and the finding reopens; a developer's own
// exception is never touched.
func TestSyncOrgExceptions(t *testing.T) {
	ctx := context.Background()
	st := realStore(t)
	t0 := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)
	id, _, err := st.UpsertSecFinding(ctx, secretAt("/work/proj", "k1", "conf/a.py"), t0)
	if err != nil {
		t.Fatal(err)
	}
	mine, _, err := st.UpsertSecFinding(ctx, secretAt("/work/proj", "k2", "conf/b.py"), t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GrantException(ctx, ExceptionDeps{Store: st, Now: func() time.Time { return t0 }}, secexceptRequest(mine)); err != nil {
		t.Fatal(err)
	}
	d := OrgExceptionDeps{
		Store: st,
		OpenFindings: func(ctx context.Context) ([]secfinding.Finding, error) {
			return st.ListSecFindings(ctx, store.SecFindingFilter{Status: policy.FindingStatusOpen})
		},
		Ref: store.SecurityFindingRef,
		Now: func() time.Time { return t0 },
	}
	ref := store.SecurityFindingRef(id)
	wrongRule := []OrgException{{GrantID: 7, FindingRef: ref, RuleID: "S-999"}}
	if r, err := SyncOrgExceptions(ctx, d, wrongRule); err != nil || r.Applied != 0 {
		t.Fatalf("a grant for another rule applied: %+v %v", r, err)
	}
	until := t0.Add(48 * time.Hour)
	grants := []OrgException{{GrantID: 7, FindingRef: ref, RuleID: "S-721", ExpiresAt: until}}
	if r, err := SyncOrgExceptions(ctx, d, grants); err != nil || r.Applied != 1 {
		t.Fatalf("apply: %+v %v", r, err)
	}
	if r, err := SyncOrgExceptions(ctx, d, grants); err != nil || r.Applied != 0 || r.Ended != 0 {
		t.Fatalf("a second pass must change nothing: %+v %v", r, err)
	}
	open, _ := st.ListSecExceptions(ctx, store.SecExceptionFilter{OpenOnly: true})
	var org *store.SecException
	for i := range open {
		if open[i].GrantedBy == OrgGrantedBy(7) {
			org = &open[i]
		}
	}
	if org == nil || !org.ExpiresAt.Equal(until) || org.FindingID != id {
		t.Fatalf("org exception: %+v", open)
	}
	if f, _, _ := st.SecFindingByID(ctx, id); f.Status == policy.FindingStatusOpen {
		t.Fatal("the finding is still open")
	}
	// The grant is no longer honoured: the exception ends, the finding
	// reopens, and the developer's own exception stays.
	if r, err := SyncOrgExceptions(ctx, d, nil); err != nil || r.Ended != 1 {
		t.Fatalf("end: %+v %v", r, err)
	}
	if f, _, _ := st.SecFindingByID(ctx, id); f.Status != policy.FindingStatusOpen {
		t.Fatalf("the finding did not reopen: %s", f.Status)
	}
	if f, _, _ := st.SecFindingByID(ctx, mine); f.Status == policy.FindingStatusOpen {
		t.Fatal("the developer's own exception was ended")
	}
}

func secexceptRequest(findingID string) secexcept.Request {
	return secexcept.Request{FindingID: findingID, Reason: "false_positive", Expiry: "7d", Origin: secexcept.OriginCLI}
}
