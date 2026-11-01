package orgcontract

import (
	"reflect"
	"testing"
)

// TestLocalGuardWeakenings is the T-848 floor table, one case per row of
// LocalGuardWeakenings' check table plus the pin overrides.
func TestLocalGuardWeakenings(t *testing.T) {
	strong := func() *LocalGuardPosture {
		return &LocalGuardPosture{Enabled: true, Mode: "enforce", PromptEnabled: true, PromptMode: "ask-once"}
	}
	tests := []struct {
		name   string
		edit   func(p *LocalGuardPosture)
		pinned map[string]string
		nilIn  bool
		want   []string
	}{
		{"pre-gen3 node reports nothing", nil, nil, true, nil},
		{"default-strong posture", func(*LocalGuardPosture) {}, nil, false, nil},
		{"observe is the shipped default, not a weakening", func(p *LocalGuardPosture) { p.Mode = "observe" }, nil, false, nil},
		{"guard disabled (audit a1)", func(p *LocalGuardPosture) { p.Enabled = false }, nil, false, []string{LocalGuardKeyEnabled}},
		{"guard mode off", func(p *LocalGuardPosture) { p.Mode = "off" }, nil, false, []string{LocalGuardKeyMode}},
		{"observe below a published enforce pin", func(p *LocalGuardPosture) { p.Mode = "observe" }, map[string]string{LocalGuardKeyMode: "enforce"}, false, []string{LocalGuardKeyMode}},
		{"published guard.enabled=false is the org's choice", func(p *LocalGuardPosture) { p.Enabled = false }, map[string]string{LocalGuardKeyEnabled: "false"}, false, nil},
		{"prompt guard off (audit a2)", func(p *LocalGuardPosture) { p.PromptEnabled = false }, nil, false, []string{LocalGuardKeyPromptEnabled}},
		{"prompt mode warn (audit a2)", func(p *LocalGuardPosture) { p.PromptMode = "warn" }, nil, false, []string{LocalGuardKeyPromptMode}},
		{"detector off (audit a2)", func(p *LocalGuardPosture) { p.DetectorModes = map[string]string{"github_pat": "off"} }, nil, false, []string{LocalGuardKeyDetectors}},
		{"stricter detector is fine", func(p *LocalGuardPosture) { p.DetectorModes = map[string]string{"github_pat": "block"} }, nil, false, nil},
		{"local allow-list", func(p *LocalGuardPosture) { p.AllowListCount = 1 }, nil, false, []string{LocalGuardKeyAllow}},
		{"the full a2 shape", func(p *LocalGuardPosture) {
			p.PromptMode = "warn"
			p.DetectorModes = map[string]string{"github_pat": "off", "us_ssn": "off"}
		}, nil, false, []string{LocalGuardKeyPromptMode, LocalGuardKeyDetectors}},
		// T-876 (re-test 2026-10-17 C-a2): with the prompt guard off, the
		// mode and the detectors set below the floor in the same edit are
		// still listed, one row each.
		{"prompt off hides no lowered prompt mode", func(p *LocalGuardPosture) {
			p.PromptEnabled = false
			p.PromptMode = "warn"
		}, nil, false, []string{LocalGuardKeyPromptEnabled, LocalGuardKeyPromptMode}},
		{"prompt off hides no lowered detector", func(p *LocalGuardPosture) {
			p.PromptEnabled = false
			p.DetectorModes = map[string]string{"github_pat": "off"}
		}, nil, false, []string{LocalGuardKeyPromptEnabled, LocalGuardKeyDetectors}},
		{"prompt off with untouched prompt settings names only the switch", func(p *LocalGuardPosture) { p.PromptEnabled = false }, nil, false, []string{LocalGuardKeyPromptEnabled}},
		{"the re-test C-a2 edit, every setting named", func(p *LocalGuardPosture) {
			p.PromptEnabled = false
			p.PromptMode = "warn"
			p.DetectorModes = map[string]string{"github_pat": "off", "us_ssn": "off"}
		}, nil, false, []string{LocalGuardKeyPromptEnabled, LocalGuardKeyPromptMode, LocalGuardKeyDetectors}},
		// T-875 (re-test C-a1): the guard switches as the developer set them,
		// below the organization's published pins.
		{"the re-test C-a1 edit below published pins", func(p *LocalGuardPosture) {
			p.Enabled = false
			p.Mode = "observe"
		}, map[string]string{LocalGuardKeyEnabled: "true", LocalGuardKeyMode: "enforce"}, false, []string{LocalGuardKeyEnabled, LocalGuardKeyMode}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var p *LocalGuardPosture
			if !tc.nilIn {
				p = strong()
				tc.edit(p)
			}
			if got := LocalGuardWeakenings(p, tc.pinned); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("weakenings = %v, want %v", got, tc.want)
			}
		})
	}
}
