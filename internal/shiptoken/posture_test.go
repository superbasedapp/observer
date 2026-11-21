package shiptoken

import (
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestEveryAdmittedFamilyHasAContentRule forces a raw-content decision for
// every family a ship-token batch may land (CA-D19).
func TestEveryAdmittedFamilyHasAContentRule(t *testing.T) {
	ruled := map[string]bool{}
	for _, r := range contentRules {
		if ruled[r.family] {
			t.Errorf("family %s has two content rules", r.family)
		}
		ruled[r.family] = true
		if !r.whole && len(r.fields) == 0 && r.reason == "" {
			t.Errorf("family %s declares no content without a reason", r.family)
		}
		if !admittedFamilies[r.family] {
			t.Errorf("content rule for %s, which is not admitted", r.family)
		}
	}
	for _, f := range AdmittedFamilies() {
		if !ruled[f] {
			t.Errorf("admitted family %s has no raw-content rule", f)
		}
	}
}

// TestContentFieldsExist pins every named content field to its row type.
func TestContentFieldsExist(t *testing.T) {
	et := reflect.TypeOf(orgcontract.PushEnvelope{})
	for _, r := range contentRules {
		var rowType reflect.Type
		for i := 0; i < et.NumField(); i++ {
			if jsonName(et.Field(i)) == r.family {
				rowType = et.Field(i).Type
			}
		}
		if rowType == nil {
			t.Fatalf("family %s is not an envelope field", r.family)
		}
		for rowType.Kind() == reflect.Slice || rowType.Kind() == reflect.Pointer {
			rowType = rowType.Elem()
		}
		names := map[string]bool{}
		for j := 0; j < rowType.NumField(); j++ {
			names[jsonName(rowType.Field(j))] = true
		}
		for _, f := range r.fields {
			if !names[f] {
				t.Errorf("%s has no field %q", r.family, f)
			}
		}
	}
}

func TestRawContentAndPosture(t *testing.T) {
	meta := orgcontract.PushEnvelope{
		Sessions:         []orgcontract.SessionRow{{ID: "s", ProjectRootHash: "h", GitRemoteHash: "g", ExecutionLocation: "vendor_cloud"}},
		Actions:          []orgcontract.ActionRow{{SessionID: "s", TargetHash: "th", SourceFileHash: "fh"}},
		TokenUsage:       []orgcontract.TokenUsageRow{{SessionID: "s", SourceFileHash: "fh"}},
		SessionTaskItems: []orgcontract.SessionTaskItemRow{{SessionID: "s", Key: "k", Status: "done"}},
	}
	cases := []struct {
		name string
		env  orgcontract.PushEnvelope
		want map[string]int
	}{
		{"metadata only", meta, map[string]int{}},
		{"a raw project root", func() orgcontract.PushEnvelope {
			e := meta
			e.Sessions = []orgcontract.SessionRow{{ID: "s", ProjectRoot: "/home/user/repo"}}
			return e
		}(), map[string]int{"sessions": 1}},
		{"a raw action target", func() orgcontract.PushEnvelope {
			e := meta
			e.Actions = []orgcontract.ActionRow{{SessionID: "s", Target: "a.go"}, {SessionID: "s"}}
			return e
		}(), map[string]int{"actions": 1}},
		{"task prose", func() orgcontract.PushEnvelope {
			e := meta
			e.SessionTaskItems = []orgcontract.SessionTaskItemRow{{SessionID: "s", Content: "write the plan"}}
			return e
		}(), map[string]int{"session_task_items": 1}},
		{"a whole-content family", func() orgcontract.PushEnvelope {
			e := meta
			e.SessionVerbositySummaries = []orgcontract.SessionVerbosityRow{{SessionID: "s"}}
			return e
		}(), map[string]int{"session_verbosity": 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RawContent(tc.env)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("RawContent = %v, want %v", got, tc.want)
			}
			if !ContentAllowed(PostureFullContent, got) {
				t.Fatal("full content must allow every batch")
			}
			if ContentAllowed(PostureMetadataOnly, got) != (len(tc.want) == 0) {
				t.Fatalf("metadata-only allowed = %v for %v", ContentAllowed(PostureMetadataOnly, got), got)
			}
		})
	}
	if PostureForEnrolment(true) != PostureFullContent || PostureForEnrolment(false) != PostureMetadataOnly {
		t.Fatal("posture table")
	}
}
