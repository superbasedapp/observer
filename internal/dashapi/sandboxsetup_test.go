package dashapi

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

// TestSandboxSetupWireFields pins the JSON field names of the sandbox setup
// contract (plan section 3.6): the web mirror (web/src/lib/sandboxSetupTypes.ts)
// and five lanes code against them.
func TestSandboxSetupWireFields(t *testing.T) {
	cases := []struct {
		name string
		v    any
		want []string
	}{
		{
			"step",
			SandboxSetupStep{Display: "d", DisplayIsCommand: true, Fields: []string{"K"}, Command: "c", Reason: "r", Disclosure: "x", After: "a", Docs: "o", Record: &ToolInstallRecord{}, Consent: &SandboxSetupConsent{}},
			[]string{"prereq", "kind", "label", "state", "class", "channel", "display", "display_is_command", "fields", "command", "reason", "disclosure", "after", "docs", "can_run", "can_undo", "record", "consent"},
		},
		{
			"step without the optional fields",
			SandboxSetupStep{},
			[]string{"prereq", "kind", "label", "state", "class", "channel", "can_run", "can_undo"},
		},
		{"consent", SandboxSetupConsent{URL: "u"}, []string{"pin", "version", "sha256", "bytes", "source", "url"}},
		{"plan", SandboxSetupPlan{Blocked: "b", Beta: "β"}, []string{"backend", "label", "steps", "next", "ready", "blocked", "beta", "checked", "fingerprint"}},
		{"plan without beta", SandboxSetupPlan{Blocked: "b"}, []string{"backend", "label", "steps", "next", "ready", "blocked", "checked", "fingerprint"}},
		{"summary", SandboxSetupSummary{Blocked: "b", Beta: "β", Next: "n"}, []string{"backend", "label", "ready", "blocked", "beta", "next"}},
		{"run request", SandboxSetupRunRequest{Consent: &SandboxSetupConsent{}, FromFile: "f", Key: "k", Fields: map[string]string{"A": "v"}}, []string{"step", "action", "fingerprint", "consent", "from_file", "key", "fields"}},
		{"started", SandboxSetupStarted{Handle: "h", Label: "l", OpID: "o", Plan: &SandboxSetupPlan{}}, []string{"kind", "handle", "label", "op_id", "plan"}},
		{"op", SandboxSetupOp{Error: "e"}, []string{"id", "status", "done_bytes", "total_bytes", "error"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, want := jsonKeys(t, tc.v), sorted(tc.want); !reflect.DeepEqual(got, want) {
				t.Errorf("keys = %v, want %v", got, want)
			}
		})
	}
}

// TestToolInstallRecordSubjectFields: the sandbox fields are omitted on a
// tool record, so the existing tool routes' answers are unchanged.
func TestToolInstallRecordSubjectFields(t *testing.T) {
	keys := jsonKeys(t, ToolInstallRecord{})
	for _, k := range []string{"subject_kind", "backend", "source", "digest", "placed_path", "elevated"} {
		for _, got := range keys {
			if got == k {
				t.Errorf("zero record carries %q", k)
			}
		}
	}
	full := jsonKeys(t, ToolInstallRecord{SubjectKind: "sandbox", Backend: "b", Source: "s", Digest: "d", PlacedPath: "p", Elevated: true})
	for _, k := range []string{"subject_kind", "backend", "source", "digest", "placed_path", "elevated"} {
		found := false
		for _, got := range full {
			found = found || got == k
		}
		if !found {
			t.Errorf("record lacks %q", k)
		}
	}
}

// TestSandboxSetupCodes: the closed error-code list, each distinct.
func TestSandboxSetupCodes(t *testing.T) {
	want := []string{"plan_changed", "not_allowed_by_org", "install_disabled", "elevation_disabled", "consent_required", "live_runs", "step_not_runnable", "unknown_step", "not_in_build", "terminal_unavailable"}
	if got := SandboxSetupCodes(); !reflect.DeepEqual(got, want) {
		t.Errorf("codes = %v, want %v", got, want)
	}
	if ErrSandboxSetupNotInBuild == nil {
		t.Error("ErrSandboxSetupNotInBuild is nil")
	}
}

func jsonKeys(t *testing.T, v any) []string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return sorted(out)
}

func sorted(xs []string) []string {
	out := append([]string(nil), xs...)
	sort.Strings(out)
	return out
}
