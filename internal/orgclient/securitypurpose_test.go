package orgclient

import (
	"context"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestNoteSecurityPurpose (lane SEC-E3): a closed id or "unset" from the
// push response is stored; free text or an unknown id never is.
func TestNoteSecurityPurpose(t *testing.T) {
	c, st := newPurposeTestClient(t)
	ctx := context.Background()
	for _, c2 := range []struct {
		body string
		want string
	}{
		{`{"accepted_rows":1}`, ""},
		{`{"security_purpose":"rank people"}`, ""},
		{`{"security_purpose":"audit_evidence"}`, "audit_evidence"},
		{`{"security_purpose":"unset"}`, "unset"},
	} {
		c.noteSecurityPurpose(ctx, []byte(c2.body))
		got, err := st.SecurityOrgPurpose(ctx)
		if err != nil || got != c2.want {
			t.Fatalf("%s: stored %q (%v), want %q", c2.body, got, err, c2.want)
		}
	}
}

// TestNoteSecurityVisibility (ruling P-089): the org's visibility settings
// from the push response are stored with closed field ids only; a malformed
// minimum or no key changes nothing.
func TestNoteSecurityVisibility(t *testing.T) {
	c, st := newPurposeTestClient(t)
	ctx := context.Background()
	if _, ok, _ := st.SecurityOrgVisibility(ctx); ok {
		t.Fatal("nothing heard yet must read as unknown")
	}
	c.noteSecurityPurpose(ctx, []byte(`{"security_visibility":{"min_group":3,"hidden_fields":["seen","user_email","agent"],"purpose_statement":true}}`))
	v, ok, err := st.SecurityOrgVisibility(ctx)
	if err != nil || !ok || v.MinGroup != 3 || strings.Join(v.HiddenFields, ",") != "agent,seen" || !v.PurposeStatement {
		t.Fatalf("stored %+v ok %v err %v", v, ok, err)
	}
	for _, body := range []string{`{"accepted_rows":1}`, `{"security_visibility":{"min_group":0}}`} {
		c.noteSecurityPurpose(ctx, []byte(body))
		if got, _, _ := st.SecurityOrgVisibility(ctx); got.MinGroup != 3 {
			t.Fatalf("%s changed the stored visibility: %+v", body, got)
		}
	}
}

func newPurposeTestClient(t *testing.T) (*Client, *store.Store) {
	t.Helper()
	s := newAgentStore(t)
	return newTestClient(t, s, nil), s
}
