package secfeed

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

func TestDecideProvenance(t *testing.T) {
	vs := func(has ...bool) []VersionProvenance {
		out := make([]VersionProvenance, len(has))
		for i, h := range has {
			out[i] = VersionProvenance{Version: string(rune('a' + i)), Has: h, Order: i}
		}
		return out
	}
	cases := []struct {
		name string
		in   ProvenanceFacts
		want policy.InstallProvenance
	}{
		// Row no_facts.
		{"no versions", ProvenanceFacts{Target: "a"}, policy.InstallProvenanceUnknown},
		{"no target", ProvenanceFacts{Versions: vs(true)}, policy.InstallProvenanceUnknown},
		{"target not published", ProvenanceFacts{Target: "z", Versions: vs(true, true)}, policy.InstallProvenanceUnknown},
		// Row present.
		{"target has it", ProvenanceFacts{Target: "b", Versions: vs(false, true)}, policy.InstallProvenancePresent},
		// Row regressed.
		{"earlier version had it", ProvenanceFacts{Target: "c", Versions: vs(false, true, false)}, policy.InstallProvenanceRegressed},
		// Row absent: only a later version had it, or none ever did.
		{"only later had it", ProvenanceFacts{Target: "a", Versions: vs(false, true)}, policy.InstallProvenanceAbsent},
		{"none ever", ProvenanceFacts{Target: "b", Versions: vs(false, false)}, policy.InstallProvenanceAbsent},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := DecideProvenance(c.in); got != c.want {
				t.Fatalf("DecideProvenance = %q, want %q", got, c.want)
			}
		})
	}
}

func TestDecideCopiesProvenanceOnlyWhenAnswered(t *testing.T) {
	now := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	base := func(st OnlineStatus) DecideInput {
		return DecideInput{
			Spec:           InstallSpec{Eco: EcoNpm, Name: "left-pad", Version: "1.0.0"},
			IndexFreshness: content.Fresh,
			Online:         OnlineAnswer{Status: st, Provenance: policy.InstallProvenanceRegressed, FirstPublished: now.Add(-1000 * time.Hour)},
			Now:            now,
		}
	}
	cases := []struct {
		name string
		in   func() DecideInput
		want policy.InstallProvenance
	}{
		{"answered", func() DecideInput { return base(OnlineAnswered) }, policy.InstallProvenanceRegressed},
		{"failed", func() DecideInput { return base(OnlineFailed) }, policy.InstallProvenanceNotChecked},
		{"not found", func() DecideInput { return base(OnlineNotFound) }, policy.InstallProvenanceNotChecked},
		{"not asked", func() DecideInput { return base(OnlineNotAsked) }, policy.InstallProvenanceNotChecked},
		{"private name", func() DecideInput { in := base(OnlineAnswered); in.Private = true; return in }, policy.InstallProvenanceNotChecked},
		{"private answer", func() DecideInput { in := base(OnlineAnswered); in.Online.Private = true; return in }, policy.InstallProvenanceNotChecked},
		{"invalid spec", func() DecideInput { in := base(OnlineAnswered); in.Spec.Invalid = true; return in }, policy.InstallProvenanceNotChecked},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Decide(c.in())
			if got.Provenance != c.want {
				t.Fatalf("Provenance = %q, want %q", got.Provenance, c.want)
			}
		})
	}
	// The provenance never changes the verdict.
	in := base(OnlineAnswered)
	with := Decide(in)
	in.Online.Provenance = ""
	without := Decide(in)
	if with.Verdict != without.Verdict || with.Reason != without.Reason {
		t.Fatalf("provenance changed the verdict: %v/%s vs %v/%s", with.Verdict, with.Reason, without.Verdict, without.Reason)
	}
}
