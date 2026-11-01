package orgcontract

import "testing"

// TestNormalizePostureFactsH2 (lane SEC-H2): the four posture facts keep
// only closed values, one entry per key; Reported keeps only the four fact
// names; a row without them normalizes to none (an older node).
func TestNormalizePostureFactsH2(t *testing.T) {
	in := SecurityPostureRow{
		Day: "2026-10-23", ShareLevel: "posture",
		DatabaseAges: []SecurityDatabaseAge{
			{Kind: "osv_export", Bucket: "under_1d"},
			{Kind: "osv_export", Bucket: "over_7d"},
			{Kind: "home/dev/secret", Bucket: "under_1d"},
			{Kind: "popular_names", Bucket: "yesterday"},
		},
		PlatformGaps: []SecurityPlatformGap{
			{Driver: "scalibr", Support: "untested"}, {Driver: "osv", Support: "supported"}, {Driver: "../x", Support: "unsupported"},
		},
		TrustVerdicts: []SecurityVerdictCount{{Verdict: "untrusted", Count: 2}, {Verdict: "clean", Count: 9}, {Verdict: "flagged", Count: -4}},
		GateOutcomes:  []SecurityGateOutcome{{Outcome: "waited", Events: 1}, {Outcome: "waited", Events: 7}, {Outcome: "skipped", Events: 1}},
		Reported:      []string{"gate_outcomes", "gate_outcomes", "secrets", "database_ages"},
	}
	out, ok := NormalizeSecurityPosture(in)
	if !ok {
		t.Fatal("dropped")
	}
	if len(out.DatabaseAges) != 1 || out.DatabaseAges[0].Bucket != "under_1d" {
		t.Errorf("database ages %+v", out.DatabaseAges)
	}
	if len(out.PlatformGaps) != 1 || out.PlatformGaps[0].Driver != "scalibr" {
		t.Errorf("platform gaps %+v", out.PlatformGaps)
	}
	if len(out.TrustVerdicts) != 2 || out.TrustVerdicts[1].Count != 0 {
		t.Errorf("trust verdicts %+v", out.TrustVerdicts)
	}
	if len(out.GateOutcomes) != 1 || out.GateOutcomes[0].Events != 1 {
		t.Errorf("gate outcomes %+v", out.GateOutcomes)
	}
	if len(out.Reported) != 2 || out.Reported[0] != "gate_outcomes" || out.Reported[1] != "database_ages" {
		t.Errorf("reported %+v", out.Reported)
	}
	older, _ := NormalizeSecurityPosture(SecurityPostureRow{Day: "2026-10-23", ShareLevel: "posture"})
	if older.DatabaseAges != nil || older.Reported != nil || older.GateOutcomes != nil {
		t.Errorf("an older node's row gained facts: %+v", older)
	}
}
