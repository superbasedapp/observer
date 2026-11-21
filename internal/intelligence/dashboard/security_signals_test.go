//go:build !sbo_omit_security && !sbo_omit_security_deps

package dashboard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secexploit"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// security_signals_test.go pins the Code security page's ranking signals
// (plan sections 14.5 and 14.7, ruling Q14-4 (a)): the drawer and the list
// rows carry the reach tier and the KEV and EPSS labels, the EPSS citation
// rides every shown score, missing data reads "Exploit data unavailable",
// and sort=rank orders dependency findings KEV first, then reach, then EPSS,
// leaving every other finding where severity put it.

// installTestExploit writes KEV (listing CVE-2021-23337) and EPSS data with
// their records into the OSV store's exploit directory, vouched issued.
func installTestExploit(t *testing.T, s *Server, issued time.Time) {
	t.Helper()
	kev, err := secexploit.EncodeKEV(secexploit.KEVCatalog{
		CatalogVersion: "2026.11.03", DateReleased: "2026-11-03T14:00:01Z",
		Entries: []secexploit.KEVEntry{{CVE: "CVE-2021-23337", DateAdded: "2021-12-10"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	epss, err := secexploit.EncodeEPSS(secexploit.EPSSSet{
		ModelVersion: "v2026.06.15", ScoreDate: "2026-11-03T00:00:00Z",
		Rows: []secexploit.EPSSRow{
			{CVE: "CVE-2021-23337", ScoreMilli: 20, PercentileMilli: 700},
			{CVE: "CVE-2024-0001", ScoreMilli: 900, PercentileMilli: 995},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := osvdb.Open(s.securityOSVDir()).ExploitDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, k := range osvdb.ExploitKinds() {
		data := kev
		if k.Kind == content.EPSS {
			data = epss
		}
		if err := os.WriteFile(filepath.Join(dir, k.Artifact), data, 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		rec, err := osvdb.EncodeExploitRecord(osvdb.ExploitRecord{SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data)), Source: osvdb.SourceFeed, VouchedIssuedAt: issued.UTC().Format(time.RFC3339)})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(osvdb.ExploitRecordPath(dir, k), rec, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// seedRankFinding stores one open finding.
func seedRankFinding(t *testing.T, st *store.Store, rootHash, key, rule, msg, evidence string, cat policy.FindingCategory, sev policy.FindingSeverity) string {
	t.Helper()
	id, _, err := st.UpsertSecFinding(context.Background(), secfinding.Normalize(secfinding.Finding{
		LocalKey: key, Rule: secfinding.Rule{ID: rule, Pack: "osv"}, Category: cat, Severity: sev,
		Confidence: policy.FindingConfidenceHigh, Baseline: policy.FindingBaselineNew,
		Project: secfinding.Project{RootHash: rootHash}, Location: secfinding.Location{RelPath: "web/package-lock.json"},
		EvidenceRedacted: evidence, Message: msg, FixHint: "Upgrade the dependency.", Status: policy.FindingStatusOpen,
	}), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func listFindings(t *testing.T, s *Server, query string) securityFindingsPage {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleSecurityFindings(w, httptest.NewRequest(http.MethodGet, "/api/security/findings?"+query, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	var p securityFindingsPage
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSecurityFindingSignals(t *testing.T) {
	s, root := newTestServer(t)
	installTestOSV(t, s)
	st := store.New(s.db())
	hash := secposture.ProjectRootHash(root)
	kevID := seedRankFinding(t, st, hash, "dep-kev", "CVE-2021-23337",
		"Known vulnerability in a npm dependency (CVE-2021-23337, GHSA-35jh-r3h4-6jhm).", "npm lodash@4.17.20",
		policy.FindingVulnerableDependency, policy.FindingSeverityLow)
	epssID := seedRankFinding(t, st, hash, "dep-epss", "CVE-2024-0001",
		"Known vulnerability in a npm dependency (CVE-2024-0001).", "npm left-pad@1.0.0",
		policy.FindingVulnerableDependency, policy.FindingSeverityMedium)
	critID := seedRankFinding(t, st, hash, "dep-crit", "CVE-2024-0002",
		"Known vulnerability in a npm dependency (CVE-2024-0002).", "npm other@1.0.0",
		policy.FindingVulnerableDependency, policy.FindingSeverityCritical)
	secretID := seedRankFinding(t, st, hash, "secret", "S-721", "A secret in a file.", "",
		policy.FindingSecret, policy.FindingSeverityHigh)

	// No exploit data installed: every dependency row says so, nothing
	// claims "not exploited", and the rank keeps the severity order.
	p := listFindings(t, s, "status=open&sort=rank")
	want := []string{critID, secretID, epssID, kevID}
	if got := ids(p.Findings); !reflect.DeepEqual(got, want) {
		t.Fatalf("no data: order %v, want %v", got, want)
	}
	for _, f := range p.Findings {
		if f.Category != string(policy.FindingVulnerableDependency) {
			if f.Reach != nil || f.Exploit != nil {
				t.Fatalf("a %s row carries dependency signals", f.Category)
			}
			continue
		}
		if f.Exploit == nil || !reflect.DeepEqual(f.Exploit.Badges, []string{secexploit.BadgeUnavailable}) || f.Exploit.EPSSCitation != "" {
			t.Fatalf("no data: %+v", f.Exploit)
		}
		// npm has no import mapping yet: unknown, never "not imported".
		if f.Reach == nil || f.Reach.Level != "unknown" {
			t.Fatalf("reach %+v", f.Reach)
		}
	}

	installTestExploit(t, s, time.Now().Add(-time.Hour))
	p = listFindings(t, s, "status=open&sort=rank")
	// The dependency places (0, 2, 3) take KEV first, then the EPSS order;
	// the secret keeps its place.
	want = []string{kevID, secretID, epssID, critID}
	if got := ids(p.Findings); !reflect.DeepEqual(got, want) {
		t.Fatalf("ranked order %v, want %v", got, want)
	}
	kev := p.Findings[0].Exploit
	if kev == nil || kev.KEV == nil || kev.KEV.DateAdded != "2021-12-10" || kev.KEVNotice != secexploit.KEVNotice ||
		kev.EPSS == nil || kev.EPSSCitation != secexploit.EPSSCitation {
		t.Fatalf("KEV row %+v", kev)
	}
	if crit := p.Findings[3].Exploit; crit.KEV != nil || crit.EPSS != nil || !crit.KEVAvailable || crit.EPSSCitation != "" {
		t.Fatalf("unlisted, unscored row %+v", crit)
	}
	// The labels never change a severity, and severity order is still the
	// default.
	if p.Findings[0].Severity != string(policy.FindingSeverityLow) {
		t.Fatal("a label changed a severity")
	}
	if got := ids(listFindings(t, s, "status=open").Findings); !reflect.DeepEqual(got, []string{critID, secretID, epssID, kevID}) {
		t.Fatalf("severity order %v", got)
	}
	// Paging the ranked order.
	p = listFindings(t, s, "status=open&sort=rank&limit=2&page=2")
	if got := ids(p.Findings); !reflect.DeepEqual(got, []string{epssID, critID}) || p.Total != 4 {
		t.Fatalf("page 2: %v total %d", got, p.Total)
	}

	// The drawer carries the same labels.
	d, raw := getFindingDetail(t, s, kevID)
	if d.Finding.Exploit == nil || d.Finding.Exploit.KEV == nil || d.Finding.Reach == nil {
		t.Fatalf("drawer: %s", raw)
	}
	if got := d.Finding.Exploit.Badges; len(got) == 0 || got[0] != "Exploited in the wild (CISA KEV, added 2021-12-10)" {
		t.Fatalf("drawer badges %q", got)
	}

	// Past the age floor: unavailable again.
	installTestExploit(t, s, time.Now().Add(-15*24*time.Hour))
	d, _ = getFindingDetail(t, s, kevID)
	if !reflect.DeepEqual(d.Finding.Exploit.Badges, []string{secexploit.BadgeUnavailable}) {
		t.Fatalf("stale data: %q", d.Finding.Exploit.Badges)
	}
}

func ids(fs []securityFindingJS) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}
