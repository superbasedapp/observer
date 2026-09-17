package orgcontract

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
)

// Bundle BUD-N contract tests: the per-subject caps and the cross-machine
// spend baseline are ADDITIVE fields on a SIGNED body, so the property that
// has to hold is not "the fields exist" but "adding them did not break either
// direction of the signature".

func testSigningKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

// TestBudgetPolicySigning_OldBodyStillVerifies is the compatibility direction
// that MUST hold unconditionally: a body signed by a server that never heard of
// Subject/Spent* still verifies on a node that has them.
//
// It works because every new field is appended at the end of the struct and
// carries omitempty, so the canonical bytes of a body that sets none of them
// are byte-identical to what they were before the fields existed. The test
// signs bytes produced from a HAND-WRITTEN JSON document (an old server's
// output, decoded by the new struct) rather than from the new struct, so a
// future field inserted in the middle — or one missing omitempty — fails here.
func TestBudgetPolicySigning_OldBodyStillVerifies(t *testing.T) {
	t.Parallel()
	pub, priv := testSigningKey(t)
	const oldJSON = `{"version":7,"resolved_scope":"team:9","cap_usd":500,` +
		`"period":"calendar_month","timezone":"America/Los_Angeles","enforcement":"hard",` +
		`"caps":[{"period":"calendar_month","timezone":"America/Los_Angeles","cap_usd":500,` +
		`"enforcement":"hard","resolved_scope":"team:9"}]}`

	var body BudgetPolicyBody
	if err := json.Unmarshal([]byte(oldJSON), &body); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	// The old server signed over ITS OWN bytes. Re-marshalling the decoded body
	// on the new struct must reproduce them exactly.
	re, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(re) != oldJSON {
		t.Fatalf("re-marshalled body differs from the old server's bytes:\n got %s\nwant %s", re, oldJSON)
	}
	doc, err := SignBudgetPolicy(priv, "org-1", "member-1", body)
	if err != nil {
		t.Fatalf("SignBudgetPolicy: %v", err)
	}
	if err := VerifyBudgetPolicy(pub, "org-1", "member-1", doc); err != nil {
		t.Fatalf("VerifyBudgetPolicy on an old-shaped body: %v", err)
	}
	if body.Caps[0].Subject != nil || body.Caps[0].SpentUSD != 0 || body.Caps[0].SpentExcludesMachine {
		t.Fatalf("decoding an old body populated a new field: %+v", body.Caps[0])
	}
}

// TestBudgetPolicySigning_SubjectAndSpentAreSigned pins the other half: the new
// fields are INSIDE the signature, so a man in the middle cannot add a subject
// cap, inflate a baseline, or re-date a measurement on a genuinely signed body.
func TestBudgetPolicySigning_SubjectAndSpentAreSigned(t *testing.T) {
	t.Parallel()
	pub, priv := testSigningKey(t)
	body := BudgetPolicyBody{
		Version: 12, ResolvedScope: "member-1", Period: BudgetPolicyPeriodCalendarDay,
		Enforcement: BudgetPolicyEnforcementHard,
		Caps: []BudgetPolicyCap{{
			Period: BudgetPolicyPeriodCalendarDay, CapUSD: 25, Enforcement: BudgetPolicyEnforcementHard,
			ResolvedScope: "member-1",
			SpentUSD:      9.5, SpentAsOf: "2026-09-15T10:00:00Z", SpentExcludesMachine: true,
		}, {
			Period: BudgetPolicyPeriodCalendarDay, CapUSD: 5, Enforcement: BudgetPolicyEnforcementSoft,
			ResolvedScope: "member-1",
			Subject:       &BudgetSubject{Kind: BudgetSubjectTool, ID: "claude-code"},
		}},
	}
	doc, err := SignBudgetPolicy(priv, "org-1", "member-1", body)
	if err != nil {
		t.Fatalf("SignBudgetPolicy: %v", err)
	}
	if err := VerifyBudgetPolicy(pub, "org-1", "member-1", doc); err != nil {
		t.Fatalf("VerifyBudgetPolicy: %v", err)
	}

	tampered := []struct {
		name  string
		apply func(*BudgetPolicyDoc)
	}{
		{"adds a subject cap", func(d *BudgetPolicyDoc) {
			d.Caps = append(append([]BudgetPolicyCap(nil), d.Caps...), BudgetPolicyCap{
				Period: BudgetPolicyPeriodCalendarDay, CapUSD: 1,
				Subject: &BudgetSubject{Kind: BudgetSubjectModel, ID: "gpt-5"},
			})
		}},
		{"inflates the baseline", func(d *BudgetPolicyDoc) {
			caps := append([]BudgetPolicyCap(nil), d.Caps...)
			caps[0].SpentUSD = 24.99
			d.Caps = caps
		}},
		{"re-dates the measurement", func(d *BudgetPolicyDoc) {
			caps := append([]BudgetPolicyCap(nil), d.Caps...)
			caps[0].SpentAsOf = "2030-01-01T00:00:00Z"
			d.Caps = caps
		}},
		{"claims machine exclusion", func(d *BudgetPolicyDoc) {
			caps := append([]BudgetPolicyCap(nil), d.Caps...)
			caps[1].SpentExcludesMachine = true
			d.Caps = caps
		}},
		{"retargets the subject", func(d *BudgetPolicyDoc) {
			caps := append([]BudgetPolicyCap(nil), d.Caps...)
			subject := *caps[1].Subject
			subject.ID = "codex"
			caps[1].Subject = &subject
			d.Caps = caps
		}},
	}
	for _, tc := range tampered {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			bad := doc
			bad.Caps = append([]BudgetPolicyCap(nil), doc.Caps...)
			tc.apply(&bad)
			if err := VerifyBudgetPolicy(pub, "org-1", "member-1", bad); err == nil {
				t.Fatalf("tampered document verified — the new fields are outside the signature")
			}
		})
	}
}

// TestBudgetPolicyDigest_CoversTheNewFields pins that the ETag substrate moved
// with them: a body whose ONLY difference is a subject cap or a baseline must
// not answer 304 against the previous one. (IssuedAt stays excluded — that is
// the existing rule and it is re-asserted here because this test would be the
// obvious place to break it.)
func TestBudgetPolicyDigest_CoversTheNewFields(t *testing.T) {
	t.Parallel()
	base := BudgetPolicyBody{
		Version: 3, Period: BudgetPolicyPeriodCalendarDay,
		Caps: []BudgetPolicyCap{{Period: BudgetPolicyPeriodCalendarDay, CapUSD: 10}},
	}
	digestOf := func(b BudgetPolicyBody) string {
		d, err := BudgetPolicyDigest(BudgetPolicyDoc{BudgetPolicyBody: b})
		if err != nil {
			t.Fatalf("BudgetPolicyDigest: %v", err)
		}
		return d
	}
	baseDigest := digestOf(base)

	dated := base
	dated.IssuedAt = "2026-09-15T10:00:00Z"
	if digestOf(dated) != baseDigest {
		t.Errorf("IssuedAt changed the digest — the 304 fast path depends on it not doing so")
	}

	withSpend := base
	withSpend.Caps = []BudgetPolicyCap{{Period: BudgetPolicyPeriodCalendarDay, CapUSD: 10, SpentUSD: 4}}
	if digestOf(withSpend) == baseDigest {
		t.Errorf("a changed baseline did not change the digest — the node would 304 past it")
	}

	withSubject := base
	withSubject.Caps = []BudgetPolicyCap{{
		Period: BudgetPolicyPeriodCalendarDay, CapUSD: 10,
		Subject: &BudgetSubject{Kind: BudgetSubjectTool, ID: "codex"},
	}}
	if digestOf(withSubject) == baseDigest {
		t.Errorf("a new subject cap did not change the digest")
	}

	// SpentAsOf is INCLUDED, reversing the earlier exclusion (adversarial review
	// P2-4 excluded it by analogy with IssuedAt; the follow-up review found the
	// P1 that analogy created). SpentAsOf is not decoration: it is the only
	// input to internal/orgbudget's `stale` rule, so a re-measurement that
	// answered 304 froze the node's stamp, aged a current baseline into `stale`
	// past BaselineMaxAge, and made the node enforce the org's cap against local
	// spend alone — under-counting by whatever the other machine had spent.
	// Keeping it in the validator is what lets a re-measurement REACH the node.
	spent := BudgetPolicyBody{
		Version: 3, Period: BudgetPolicyPeriodCalendarDay,
		Caps: []BudgetPolicyCap{{
			Period: BudgetPolicyPeriodCalendarDay, CapUSD: 10,
			SpentUSD: 4, SpentAsOf: "2026-09-15T10:00:00Z", SpentExcludesMachine: true,
		}},
	}
	restamped := BudgetPolicyBody{
		Version: 3, Period: BudgetPolicyPeriodCalendarDay,
		Caps: []BudgetPolicyCap{{
			Period: BudgetPolicyPeriodCalendarDay, CapUSD: 10,
			SpentUSD: 4, SpentAsOf: "2026-09-15T10:02:00Z", SpentExcludesMachine: true,
		}},
	}
	if digestOf(spent) == digestOf(restamped) {
		t.Errorf("a re-measurement at a later time kept the same digest — the node would 304 past it and age a current baseline into `stale`")
	}
	// A body with NO baseline carries no SpentAsOf to move, so it keeps 304ing
	// exactly as it did before: the cost of including the field falls only on
	// the members the field exists for.
	bare := BudgetPolicyBody{
		Version: 3, Period: BudgetPolicyPeriodCalendarDay,
		Caps: []BudgetPolicyCap{{Period: BudgetPolicyPeriodCalendarDay, CapUSD: 10}},
	}
	bareAgain := bare
	bareAgain.IssuedAt = "2026-09-15T10:02:00Z"
	if digestOf(bare) != digestOf(bareAgain) {
		t.Errorf("a baseline-free body moved its digest across a re-mint — every poll would be a full 200 for members the baseline never touches")
	}
	moved := restamped
	moved.Caps = []BudgetPolicyCap{{
		Period: BudgetPolicyPeriodCalendarDay, CapUSD: 10,
		SpentUSD: 5, SpentAsOf: "2026-09-15T10:02:00Z", SpentExcludesMachine: true,
	}}
	if digestOf(moved) == digestOf(restamped) {
		t.Errorf("a changed SpentUSD did not change the digest — the node would 304 past a moved baseline")
	}
	// The digest must not MUTATE the caller's document: the node verifies and
	// persists the same body it hashed, and a blanked measurement time would
	// make every baseline undated (and therefore stale) after one ETag call.
	kept := BudgetPolicyDoc{BudgetPolicyBody: spent}
	if _, err := BudgetPolicyDigest(kept); err != nil {
		t.Fatalf("BudgetPolicyDigest: %v", err)
	}
	if kept.Caps[0].SpentAsOf != "2026-09-15T10:00:00Z" || kept.IssuedAt != spent.IssuedAt {
		t.Errorf("BudgetPolicyDigest mutated the caller's document: %+v", kept.Caps[0])
	}
}

// TestBudgetPolicyCapSubjectKey is the normalisation table. An unknown kind or
// an empty id is IGNORED — never widened into a cap on everything, which is the
// failure mode that would matter.
func TestBudgetPolicyCapSubjectKey(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name          string
		subject       *BudgetSubject
		wantKind      string
		wantID        string
		wantRecognise bool
	}{
		{name: "nil subject is a whole-caller cap"},
		{
			name: "tool", subject: &BudgetSubject{Kind: "tool", ID: "claude-code"},
			wantKind: BudgetSubjectTool, wantID: "claude-code", wantRecognise: true,
		},
		{
			name: "case and spaces are folded", subject: &BudgetSubject{Kind: " Tool ", ID: "  Claude-Code "},
			wantKind: BudgetSubjectTool, wantID: "claude-code", wantRecognise: true,
		},
		{
			name: "model", subject: &BudgetSubject{Kind: "model", ID: "GPT-5"},
			wantKind: BudgetSubjectModel, wantID: "gpt-5", wantRecognise: true,
		},
		{name: "unknown kind is ignored", subject: &BudgetSubject{Kind: "project", ID: "acme"}},
		{name: "empty id is ignored", subject: &BudgetSubject{Kind: "tool", ID: "   "}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			kind, id, ok := BudgetPolicyCap{Subject: tc.subject}.SubjectKey()
			if ok != tc.wantRecognise || kind != tc.wantKind || id != tc.wantID {
				t.Fatalf("SubjectKey() = (%q, %q, %v), want (%q, %q, %v)",
					kind, id, ok, tc.wantKind, tc.wantID, tc.wantRecognise)
			}
		})
	}
}
