package platformcontract

import (
	"encoding/json"
	"errors"
	"testing"
)

// TestAvailabilityBodyValidate walks one case per rule: the issued_at check,
// every reach row, the required fields, the uniqueness checks and every
// org_controls and ingest row.
func TestAvailabilityBodyValidate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(b *AvailabilityBody)
		field  string // "" = valid
	}{
		{"golden body", func(*AvailabilityBody) {}, ""},
		{"empty sections", func(b *AvailabilityBody) { b.Components, b.OrgControls, b.ReleaseFlags = nil, nil, nil }, ""},
		{"issued_at not RFC 3339", func(b *AvailabilityBody) { b.IssuedAt = "2026-11-13" }, "issued_at"},
		{"issued_at not UTC", func(b *AvailabilityBody) { b.IssuedAt = "2026-11-13T12:00:00+01:00" }, "issued_at"},
		{"reach off with orgs", func(b *AvailabilityBody) { b.Components[1].Orgs = []string{testOrg} }, "components[org.gateway].orgs"},
		{"reach named without orgs", func(b *AvailabilityBody) { b.Components[0].Orgs = nil }, "components[org.enrichment].orgs"},
		{"reach named with a cohort", func(b *AvailabilityBody) { b.Components[0].Cohort = "ring" }, "components[org.enrichment].cohort"},
		{"reach cohort without a cohort", func(b *AvailabilityBody) { b.ReleaseFlags[0].Cohort = "" }, "release_flags[rf-new-ingest-path].cohort"},
		{"reach stage-default bare", func(b *AvailabilityBody) { b.Components[1].Reach = ReachStageDefault }, ""},
		{"unknown reach", func(b *AvailabilityBody) { b.Components[1].Reach = "everywhere" }, "components[org.gateway].reach"},
		{"repeated named org", func(b *AvailabilityBody) { b.Components[0].Orgs = []string{testOrg, testOrg} }, "components[org.enrichment].orgs"},
		{"component without a reason", func(b *AvailabilityBody) { b.Components[0].Reason = " " }, "components[org.enrichment].reason"},
		{"component without an author", func(b *AvailabilityBody) { b.Components[0].Author = "" }, "components[org.enrichment].author"},
		{"repeated component", func(b *AvailabilityBody) { b.Components[1].Component = "org.enrichment" }, "components.component"},
		{"blank component", func(b *AvailabilityBody) { b.Components[1].Component = "" }, "components.component"},
		{"repeated flag", func(b *AvailabilityBody) { b.ReleaseFlags = append(b.ReleaseFlags, b.ReleaseFlags[0]) }, "release_flags.flag"},
		{"org control with no control", func(b *AvailabilityBody) { b.OrgControls[0].Ingest = nil }, "org_controls[" + testOrg + "]"},
		{"org control without a reason", func(b *AvailabilityBody) { b.OrgControls[0].Reason = "" }, "org_controls[" + testOrg + "].reason"},
		{"repeated org", func(b *AvailabilityBody) { b.OrgControls[1].Org = testOrg }, "org_controls.org"},
		{"ingest: unknown mode", func(b *AvailabilityBody) { b.OrgControls[0].Ingest.Mode = "drop" }, "org_controls[" + testOrg + "].ingest"},
		{"ingest: platform-wide", func(b *AvailabilityBody) {
			b.OrgControls[1].Ingest = &IngestControl{Mode: IngestPause}
		}, "org_controls[*].ingest"},
		{"ingest: throttle without a rate", func(b *AvailabilityBody) { b.OrgControls[0].Ingest.RatePerMinute = 0 }, "org_controls[" + testOrg + "].ingest"},
		{"ingest: pause with a rate", func(b *AvailabilityBody) { b.OrgControls[0].Ingest.Mode = IngestPause }, "org_controls[" + testOrg + "].ingest"},
		{"ingest: pause", func(b *AvailabilityBody) {
			b.OrgControls[0].Ingest = &IngestControl{Mode: IngestPause}
		}, ""},
		{"inference: unknown admission", func(b *AvailabilityBody) { b.OrgControls[1].Inference[0].Admission = "half" }, "org_controls[*].inference.admission"},
		{"inference: unknown dispatch", func(b *AvailabilityBody) { b.OrgControls[1].Inference[0].Dispatch = "" }, "org_controls[*].inference.dispatch"},
		{"inference: repeated route", func(b *AvailabilityBody) {
			b.OrgControls[1].Inference = append(b.OrgControls[1].Inference, b.OrgControls[1].Inference[0])
		}, "org_controls[*].inference.route"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := cloneBody(t, goldenAvailabilityBody())
			tc.mutate(&b)
			err := b.Validate()
			if tc.field == "" {
				if err != nil {
					t.Fatalf("Validate = %v, want nil", err)
				}
				return
			}
			var v *ValidationError
			if !asValidation(err, &v) || v.Field != tc.field {
				t.Fatalf("Validate = %v, want a ValidationError on %q", err, tc.field)
			}
		})
	}
}

// cloneBody deep-copies through JSON so a case's mutation never reaches the
// shared golden value; it also proves the body round-trips.
func cloneBody(t *testing.T, b AvailabilityBody) AvailabilityBody {
	t.Helper()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var out AvailabilityBody
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func asValidation(err error, v **ValidationError) bool { return errors.As(err, v) }

func TestAvailabilityEnumsAreClosed(t *testing.T) {
	t.Parallel()
	for _, r := range KnownReaches() {
		if !r.Valid() {
			t.Errorf("reach %q", r)
		}
	}
	for _, m := range KnownIngestModes() {
		if !m.Valid() {
			t.Errorf("ingest mode %q", m)
		}
	}
	for _, s := range KnownInferenceStates() {
		if !s.Valid() {
			t.Errorf("inference state %q", s)
		}
	}
	if Reach("").Valid() || IngestMode("").Valid() || InferenceState("").Valid() || DocumentKind("").Valid() {
		t.Error("the empty value is valid")
	}
	if len(reachRules()) != len(KnownReaches()) {
		t.Error("the reach table does not cover every reach")
	}
}
