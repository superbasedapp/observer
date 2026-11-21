package dashboard

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestAPIGuardApprovalsGrantOrExtend pins the P-232 POST contract: a second
// identical grant answers existing=true with the first grant's id and adds
// no row, for every scope; a different anchor is a new grant.
func TestAPIGuardApprovalsGrantOrExtend(t *testing.T) {
	t.Parallel()
	s, _ := newTestServer(t)
	st := store.New(s.opts.DB)
	ctx := context.Background()
	pid, err := st.UpsertProject(ctx, t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"sx1", "sx2"} {
		if err := st.UpsertSession(ctx, models.Session{ID: id, ProjectID: pid, Tool: "claude-code", StartedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	post := func(body string) (id int64, existing bool) {
		t.Helper()
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/api/guard/approvals", strings.NewReader(body)))
		if rec.Code != 200 {
			t.Fatalf("POST %s: %d %s", body, rec.Code, rec.Body.String())
		}
		var resp struct {
			ID       int64 `json:"id"`
			Existing bool  `json:"existing"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		return resp.ID, resp.Existing
	}
	cases := []struct {
		name, first, second string
		wantExisting        bool
	}{
		{"global twice", `{"rule_id":"S-794","scope":"global"}`, `{"rule_id":"S-794","scope":"global","ttl_hours":24}`, true},
		{"session twice", `{"rule_id":"S-793","scope":"session","session_id":"sx1","ttl_hours":24}`, `{"rule_id":"S-793","scope":"session","session_id":"sx1","ttl_hours":48}`, true},
		{"project twice from two sessions of one project", `{"rule_id":"S-792","scope":"project","session_id":"sx1"}`, `{"rule_id":"S-792","scope":"project","session_id":"sx2"}`, true},
		{"another session is a new grant", `{"rule_id":"S-791","scope":"session","session_id":"sx1"}`, `{"rule_id":"S-791","scope":"session","session_id":"sx2"}`, false},
	}
	for _, tc := range cases {
		firstID, firstExisting := post(tc.first)
		if firstExisting {
			t.Errorf("%s: the first grant reported existing", tc.name)
		}
		secondID, secondExisting := post(tc.second)
		if secondExisting != tc.wantExisting {
			t.Errorf("%s: second existing = %v, want %v", tc.name, secondExisting, tc.wantExisting)
		}
		if tc.wantExisting && secondID != firstID {
			t.Errorf("%s: second id %d, want the first grant's %d", tc.name, secondID, firstID)
		}
	}
	rows, err := st.ActiveGuardApprovals(ctx, "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 5 {
		t.Fatalf("active grants = %d, want 5 (one per key)", len(rows))
	}
}
