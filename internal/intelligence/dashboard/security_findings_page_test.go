//go:build !sbo_omit_security

package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func getFindingsPage(t *testing.T, s *Server, query string) securityFindingsPage {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleSecurityFindings(w, httptest.NewRequest(http.MethodGet, "/api/security/findings?"+query, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("list %s: %d %s", query, w.Code, w.Body)
	}
	var p securityFindingsPage
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestSecurityFindingsPaging: the list pages with a total (default 50, at
// most 1000 a page), sorts by severity descending by default (critical
// first) and by the whitelisted columns on request.
func TestSecurityFindingsPaging(t *testing.T) {
	s, root := newTestServer(t)
	st := store.New(s.db())
	hash := secposture.ProjectRootHash(root)
	ctx := context.Background()
	t0 := time.Now().Add(-time.Hour)
	sevs := policy.FindingSeverities()
	const n = 55
	for i := 0; i < n; i++ {
		if _, _, err := st.UpsertSecFinding(ctx, secfinding.Normalize(secfinding.Finding{
			LocalKey: fmt.Sprintf("k%02d", i), Rule: secfinding.Rule{ID: "S-721"}, Category: policy.FindingSecret,
			Severity: sevs[i%len(sevs)], Confidence: policy.FindingConfidenceHigh, Baseline: policy.FindingBaselineNew,
			Project: secfinding.Project{RootHash: hash}, Location: secfinding.Location{RelPath: "a.go"},
			Status: policy.FindingStatusOpen,
		}), t0.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	p := getFindingsPage(t, s, "project="+hash)
	if p.Total != n || p.Page != 1 || p.Limit != 50 || len(p.Findings) != 50 {
		t.Fatalf("first page: total %d page %d limit %d rows %d", p.Total, p.Page, p.Limit, len(p.Findings))
	}
	rank := map[string]int{}
	for i, sev := range sevs {
		rank[string(sev)] = i
	}
	for i := 1; i < len(p.Findings); i++ {
		a, b := p.Findings[i-1], p.Findings[i]
		if rank[a.Severity] < rank[b.Severity] || (a.Severity == b.Severity && a.LastSeen < b.LastSeen) {
			t.Fatalf("not severity desc, last_seen desc at %d: %+v then %+v", i, a, b)
		}
	}
	if p.Findings[0].Severity != string(policy.FindingSeverityCritical) {
		t.Fatalf("critical first: %+v", p.Findings[0])
	}
	if p2 := getFindingsPage(t, s, "project="+hash+"&page=2"); len(p2.Findings) != n-50 || p2.Page != 2 || p2.Total != n {
		t.Fatalf("second page: %+v", p2)
	}
	if p3 := getFindingsPage(t, s, "project="+hash+"&page=9"); len(p3.Findings) != 0 || p3.Total != n {
		t.Fatalf("past the end: %+v", p3)
	}
	if big := getFindingsPage(t, s, "project="+hash+"&limit=5000"); big.Limit != 1000 || len(big.Findings) != n {
		t.Fatalf("limit cap: %d %d", big.Limit, len(big.Findings))
	}
	asc := getFindingsPage(t, s, "project="+hash+"&sort=first_seen&dir=asc&limit=3")
	if len(asc.Findings) != 3 || asc.Findings[0].FirstSeen > asc.Findings[1].FirstSeen || asc.Findings[1].FirstSeen > asc.Findings[2].FirstSeen {
		t.Fatalf("first_seen asc: %+v", asc.Findings)
	}
	last := getFindingsPage(t, s, "project="+hash+"&sort=last_seen&limit=2")
	if len(last.Findings) != 2 || last.Findings[0].LastSeen < last.Findings[1].LastSeen {
		t.Fatalf("last_seen desc: %+v", last.Findings)
	}
	if none := getFindingsPage(t, s, "project="+hash+"&status=fixed_verified"); none.Total != 0 || len(none.Findings) != 0 {
		t.Fatalf("status filter: %+v", none)
	}
}
