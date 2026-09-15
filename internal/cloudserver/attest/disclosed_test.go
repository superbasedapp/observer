package attest

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestDisclosedAttestorHealthyForAttestedResourceAndPolicy(t *testing.T) {
	b := boundBinding()
	d := DisclosedAttestor{AttestedResourceID: b.ARMResourceID, PolicyVersion: "1", AttestedBy: "santosh"}
	att, err := d.Attest(context.Background(), b, time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !att.Healthy {
		t.Fatalf("want healthy for the disclosed resource, got %+v", att)
	}
	for _, want := range []string{ModeProviderRetentionDisclosed, "policy v1", b.ARMResourceID, "santosh"} {
		if !strings.Contains(att.Reason, want) {
			t.Errorf("reason must carry %q, got %q", want, att.Reason)
		}
	}
	// The persisted value must never read as a disabled-logging claim.
	if strings.HasPrefix(att.ContentLoggingValue, "false") {
		t.Fatalf("disclosed mode must never claim ContentLogging=false, got %q", att.ContentLoggingValue)
	}
	if !strings.Contains(att.ContentLoggingValue, "not-disabled") || !strings.Contains(att.ContentLoggingValue, ModeProviderRetentionDisclosed) {
		t.Errorf("content logging value must name the disclosed posture, got %q", att.ContentLoggingValue)
	}
}

func TestDisclosedAttestorFailsClosed(t *testing.T) {
	full := boundBinding()
	cases := []struct {
		name string
		att  DisclosedAttestor
		b    Binding
		want string
	}{
		{"different resource", DisclosedAttestor{AttestedResourceID: full.ARMResourceID + "-other", PolicyVersion: "1"}, full, "not covered"},
		{"empty attested id", DisclosedAttestor{AttestedResourceID: "", PolicyVersion: "1"}, full, "not covered"},
		{"empty policy version", DisclosedAttestor{AttestedResourceID: full.ARMResourceID, PolicyVersion: "  "}, full, "no policy version"},
		{"incomplete binding", DisclosedAttestor{AttestedResourceID: full.ARMResourceID, PolicyVersion: "1"}, Binding{}, "not bound"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			att, err := tc.att.Attest(context.Background(), tc.b, time.Now())
			if err != nil {
				t.Fatalf("fail-closed must be a nil error, got %v", err)
			}
			if att.Healthy {
				t.Fatalf("want fail-closed (unhealthy), got %+v", att)
			}
			if !strings.Contains(att.Reason, tc.want) || !strings.Contains(att.Reason, ModeProviderRetentionDisclosed) {
				t.Errorf("reason = %q, want it to name the mode and %q", att.Reason, tc.want)
			}
		})
	}
}

func TestRefusingAttestorAlwaysFailsClosed(t *testing.T) {
	for _, b := range []Binding{boundBinding(), {}} {
		att, err := RefusingAttestor{Reason: "conflicting attestation modes"}.Attest(context.Background(), b, time.Now())
		if err != nil {
			t.Fatalf("nil error expected, got %v", err)
		}
		if att.Healthy || att.Reason != "conflicting attestation modes" {
			t.Fatalf("want unhealthy with the configured reason, got %+v", att)
		}
	}
	att, _ := RefusingAttestor{}.Attest(context.Background(), boundBinding(), time.Now())
	if att.Healthy || att.Reason == "" {
		t.Fatalf("empty reason must still fail closed with a reason, got %+v", att)
	}
}
