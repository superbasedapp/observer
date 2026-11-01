package orgcontract

import (
	"reflect"
	"testing"
)

// TestLocalGuardWeakDetectors pins T-888: the detectors behind a
// guard.prompt.detectors weakening, each judged against its own floor, sorted,
// and agreeing with LocalGuardWeakenings on whether the key is weak.
func TestLocalGuardWeakDetectors(t *testing.T) {
	for _, tc := range []struct {
		name string
		det  map[string]string
		want []string
	}{
		{"untouched node, shipped defaults", defaultReportedDetectors, nil},
		{"no overrides", nil, nil},
		{"the re-test edit (C-a2)", map[string]string{"github_pat": "off", "us_ssn": "off", "email": "off"}, []string{"github_pat", "us_ssn"}},
		{"loosened, not off", map[string]string{"github_pat": "warn"}, []string{"github_pat"}},
		{"a detector the defaults do not name", map[string]string{"aws_access_key": "off"}, []string{"aws_access_key"}},
		{"raised above the floor", map[string]string{"email": "block", "us_ssn": "block"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &LocalGuardPosture{Enabled: true, Mode: "enforce", PromptEnabled: true, PromptMode: "ask-once", DetectorModes: tc.det}
			got := LocalGuardWeakDetectors(p)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("weak detectors = %v, want %v", got, tc.want)
			}
			keyWeak := false
			for _, k := range LocalGuardWeakenings(p, nil) {
				keyWeak = keyWeak || k == LocalGuardKeyDetectors
			}
			if keyWeak != (len(got) > 0) {
				t.Fatalf("LocalGuardWeakenings disagrees: key weak %v, detectors %v", keyWeak, got)
			}
		})
	}
	if LocalGuardWeakDetectors(nil) != nil {
		t.Error("a nil posture names detectors")
	}
}
