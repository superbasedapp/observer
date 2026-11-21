package secmcp

import (
	"context"
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secexploit"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

// TestSummarizeRanks pins the answer's order (plan section 14.7, ruling
// Q14-4 (a)): worst severity first, then the dependency findings reordered
// among their places by KEV, reach, EPSS; other findings stay put, and the
// cut to 100 keeps the highest-ranked.
func TestSummarizeRanks(t *testing.T) {
	t.Parallel()
	sev := func(f secfinding.Finding, s policy.FindingSeverity) secfinding.Finding { f.Severity = s; return f }
	secret := secfinding.Finding{ID: "secret", Rule: secfinding.Rule{ID: "S-721"}, Category: policy.FindingSecret, Severity: policy.FindingSeverityCritical}
	fs := []secfinding.Finding{
		sev(depFinding("low-kev", "GHSA-1", "m"), policy.FindingSeverityLow),
		sev(depFinding("crit-none", "GHSA-2", "m"), policy.FindingSeverityCritical),
		secret,
		sev(depFinding("high-imported", "GHSA-3", "m"), policy.FindingSeverityHigh),
		sev(depFinding("high-epss", "GHSA-4", "m"), policy.FindingSeverityHigh),
	}
	hi, lo := 0.9, 0.1
	enrich := map[string]Enrichment{
		"low-kev":       {Reach: "not_imported_directly", KEV: &KEV{Listed: true, DateAdded: "2021-12-10"}, EPSS: &lo},
		"crit-none":     {Reach: "unknown", KEV: &KEV{}},
		"high-imported": {Reach: "imported", KEV: &KEV{}, EPSS: &lo},
		"high-epss":     {Reach: "unknown", KEV: &KEV{}, EPSS: &hi},
	}
	d := Deps{Enrich: func(_ context.Context, in EnrichInput) Enrichment { return enrich[in.Finding.ID] }}
	out := d.summarize(context.Background(), "/r", fs)
	var got []string
	for _, f := range out.Findings {
		got = append(got, f.ID)
	}
	// Severity first: crit-none, secret, high-imported, high-epss, low-kev;
	// the dependency places (1, 3, 4, 5) take the ranked dependencies.
	want := []string{"low-kev", "secret", "high-imported", "high-epss", "crit-none"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
	if out.Attribution != secexploit.EPSSCitation {
		t.Fatalf("attribution %q", out.Attribution)
	}
	// No score anywhere: no citation.
	d.Enrich = func(context.Context, EnrichInput) Enrichment { return Enrichment{Reach: "unknown"} }
	if a := d.summarize(context.Background(), "/r", fs).Attribution; a != "" {
		t.Fatalf("attribution without a score: %q", a)
	}

	// The cut keeps the highest-ranked: 150 low findings with nothing
	// known and one KEV-listed one last.
	var many []secfinding.Finding
	for i := 0; i < 150; i++ {
		many = append(many, sev(depFinding("n"+string(rune('a'+i%26))+string(rune('a'+i/26)), "GHSA-x", "m"), policy.FindingSeverityLow))
	}
	many = append(many, sev(depFinding("kev", "GHSA-y", "m"), policy.FindingSeverityLow))
	d.Enrich = func(_ context.Context, in EnrichInput) Enrichment {
		if in.Finding.ID == "kev" {
			return Enrichment{KEV: &KEV{Listed: true}}
		}
		return Enrichment{}
	}
	cut := d.summarize(context.Background(), "/r", many)
	if !cut.Truncated || len(cut.Findings) != maxFindings || cut.Findings[0].ID != "kev" || cut.Open != 151 {
		t.Fatalf("cut: truncated %v, %d listed, first %s, open %d", cut.Truncated, len(cut.Findings), cut.Findings[0].ID, cut.Open)
	}
}
