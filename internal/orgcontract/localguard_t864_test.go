package orgcontract

import (
	"reflect"
	"testing"
	"time"
)

// defaultReportedDetectors is what an untouched node reports for the shipped
// detector set: only the detectors whose effective mode differs from the
// global ask-once (the re-test's baseline report on node 1, T-864 gap 3).
var defaultReportedDetectors = map[string]string{
	"email": "off", "github_pat": "block", "phone_e164": "off", "phone_nanp": "off",
}

// TestLocalGuardWeakeningsDefaultDetectorSet pins T-864 gap 3: the shipped
// default detector set is never a weakening (it opened a false
// local_weakening on an untouched node), while a detector switched below its
// own floor still is.
func TestLocalGuardWeakeningsDefaultDetectorSet(t *testing.T) {
	base := func(det map[string]string) *LocalGuardPosture {
		return &LocalGuardPosture{Enabled: true, Mode: "observe", PromptEnabled: true, PromptMode: "ask-once", DetectorModes: det}
	}
	for _, tc := range []struct {
		name string
		det  map[string]string
		want []string
	}{
		{"untouched node, shipped defaults", defaultReportedDetectors, nil},
		{"no overrides at all", nil, nil},
		{"us_ssn switched off", map[string]string{"email": "off", "us_ssn": "off"}, []string{LocalGuardKeyDetectors}},
		{"github_pat loosened to warn", map[string]string{"github_pat": "warn"}, []string{LocalGuardKeyDetectors}},
		{"a detector the defaults do not name switched off", map[string]string{"aws_access_key": "off"}, []string{LocalGuardKeyDetectors}},
		{"email raised to block is fine", map[string]string{"email": "block"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := LocalGuardWeakenings(base(tc.det), nil); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("weakenings = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLocalGuardDetectorFloor(t *testing.T) {
	for id, want := range map[string]string{
		"email": "off", "phone_nanp": "off", "us_ssn": LocalGuardPromptFloor, "github_pat": LocalGuardPromptFloor, "aws_access_key": LocalGuardPromptFloor,
	} {
		if got := LocalGuardDetectorFloor(id); got != want {
			t.Errorf("LocalGuardDetectorFloor(%s) = %q, want %q", id, got, want)
		}
	}
	m := LocalGuardDefaultDetectorModes()
	m["email"] = "block"
	if LocalGuardDefaultDetectorModes()["email"] != "off" {
		t.Fatal("LocalGuardDefaultDetectorModes returned the shared table")
	}
}

// TestGuardTamperReport pins the gen4 record's validation and its per-event
// rendering (T-864 gap 4).
func TestGuardTamperReport(t *testing.T) {
	now := time.Date(2026, 10, 16, 8, 0, 0, 0, time.UTC)
	ok := &GuardTamperReport{Repairs: 2, LastAt: "2026-10-16T07:12:00Z", LastKind: GuardTamperOrgBundle}
	for _, tc := range []struct {
		name  string
		r     *GuardTamperReport
		valid bool
	}{
		{"nil", nil, true},
		{"well formed", ok, true},
		{"unknown kind", &GuardTamperReport{Repairs: 1, LastAt: ok.LastAt, LastKind: "rm_tamper"}, false},
		{"bad time", &GuardTamperReport{Repairs: 1, LastAt: "yesterday", LastKind: GuardTamperGovernance}, false},
		{"zero repairs", &GuardTamperReport{LastAt: ok.LastAt, LastKind: GuardTamperGovernance}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.r.Valid(); got != tc.valid {
				t.Fatalf("Valid = %v, want %v", got, tc.valid)
			}
		})
	}
	if !ok.Live(now) || ok.Live(now.Add(GuardTamperWindow)) {
		t.Fatal("Live window wrong")
	}
	later := *ok
	later.LastAt = "2026-10-16T07:40:00Z"
	if ok.Event() == later.Event() {
		t.Fatal("two repairs at different times render the same event")
	}
	for _, k := range GuardTamperKinds() {
		if !GuardTamperKindKnown(k) {
			t.Fatalf("kind %s not known", k)
		}
	}
}
