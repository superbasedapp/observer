//go:build !sbo_omit_security

package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestSecOrgBaselineApprovals (lane LEFT-SHARED): the stored approvals are
// replaced whole by each applied pull and cleared by an empty one; a
// project's baseline is approved only under the project key its own finding
// rows carry (org_project_id, else project_identity_hash).
func TestSecOrgBaselineApprovals(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	seedSecOrgFinding(t, s, time.Now().UTC()) // root-1, identity hash "1"*64
	ident := strings.Repeat("1", 64)
	if _, ok, err := s.SecOrgBaselineApproval(ctx, "root-1", "commit", "c1"); err != nil || ok {
		t.Fatalf("nothing stored: %v %v", ok, err)
	}
	approvals := []orgcontract.SecurityBaselineApproval{
		{Project: ident, RefKind: "commit", Ref: "c1", ApprovedAt: "2026-10-24T10:00:00Z"},
		{Project: "another-project", RefKind: "commit", Ref: "c9", ApprovedAt: "2026-10-24T10:00:00Z"},
	}
	if err := s.ReplaceSecOrgBaselineApprovals(ctx, 3, approvals); err != nil {
		t.Fatal(err)
	}
	at, ok, err := s.SecOrgBaselineApproval(ctx, "root-1", "commit", "c1")
	if err != nil || !ok || at != "2026-10-24T10:00:00Z" {
		t.Fatalf("approved c1: %q %v %v", at, ok, err)
	}
	for _, c := range []struct{ root, kind, ref string }{
		{"root-1", "ci_result", "c1"}, {"root-1", "commit", "c9"}, {"root-2", "commit", "c1"},
	} {
		if _, ok, _ := s.SecOrgBaselineApproval(ctx, c.root, c.kind, c.ref); ok {
			t.Errorf("%+v must not read as approved", c)
		}
	}
	if err := s.ReplaceSecOrgBaselineApprovals(ctx, 4, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.SecOrgBaselineApproval(ctx, "root-1", "commit", "c1"); ok {
		t.Fatal("an empty pull must clear the approvals")
	}
}
