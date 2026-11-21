package secassess

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

// jsonKeys returns the sorted keys of the JSON object v encodes to.
func jsonKeys(t *testing.T, v any) []string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal %s: %v", b, err)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// TestModelVocabJSONKeys pins the field names of the vocabulary: the web's
// ModelVocab type (secAssessModel.ts) reads exactly these.
func TestModelVocabJSONKeys(t *testing.T) {
	v := ModelVocab()
	tests := []struct {
		name string
		got  any
		want []string
	}{
		{"the vocabulary", v, []string{"ai_frameworks", "bands", "component_types", "linddun", "stride", "wstg"}},
		{"a STRIDE row", v.Stride[0], []string{"id", "letter", "name", "question"}},
		{"a LINDDUN row", v.Linddun[0], []string{"id", "name", "question"}},
		{"a component type that holds no logs", v.ComponentTypes[0], []string{"class", "id", "name"}},
		{"a component type that holds logs", VocabComponentType{ID: "log_store", Class: "data_store", HoldsLogs: true, Name: "Log or audit store"}, []string{"class", "holds_logs", "id", "name"}},
		{"a test category row", v.WSTG[0], []string{"applies_when", "id", "intent", "title"}},
		{"an AI framework row", v.AIFrameworks[0], []string{"id", "name"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := jsonKeys(t, tc.got); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("keys = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestModelVocabRowsFollowTheTables walks every row of every table: one
// assertion per entry, so a table row added later is sent on its own.
func TestModelVocabRowsFollowTheTables(t *testing.T) {
	v := ModelVocab()
	if len(v.Stride) != len(StrideCategories) {
		t.Fatalf("stride rows = %d, want %d", len(v.Stride), len(StrideCategories))
	}
	for i, c := range StrideCategories {
		want := VocabStride{ID: c.ID, Letter: c.Letter, Name: c.Name, Question: c.Question}
		if v.Stride[i] != want {
			t.Errorf("stride[%d] = %+v, want %+v", i, v.Stride[i], want)
		}
	}
	if len(v.Linddun) != len(LinddunCategories) {
		t.Fatalf("linddun rows = %d, want %d", len(v.Linddun), len(LinddunCategories))
	}
	for i, c := range LinddunCategories {
		want := VocabLinddun{ID: c.ID, Name: c.Name, Question: c.Question}
		if v.Linddun[i] != want {
			t.Errorf("linddun[%d] = %+v, want %+v", i, v.Linddun[i], want)
		}
	}
	if len(v.ComponentTypes) != len(ComponentTypes) {
		t.Fatalf("component type rows = %d, want %d", len(v.ComponentTypes), len(ComponentTypes))
	}
	for i, c := range ComponentTypes {
		want := VocabComponentType{ID: c.ID, Class: string(c.Class), HoldsLogs: c.HoldsLogs, Name: c.Name}
		if v.ComponentTypes[i] != want {
			t.Errorf("component_types[%d] = %+v, want %+v", i, v.ComponentTypes[i], want)
		}
	}
	if len(v.WSTG) != len(WSTGCategories) {
		t.Fatalf("wstg rows = %d, want %d", len(v.WSTG), len(WSTGCategories))
	}
	for i, c := range WSTGCategories {
		want := VocabWSTG{ID: c.ID, Title: c.Title, Intent: c.Intent, AppliesWhen: c.AppliesWhen}
		if v.WSTG[i] != want {
			t.Errorf("wstg[%d] = %+v, want %+v", i, v.WSTG[i], want)
		}
	}
	if len(v.AIFrameworks) != len(AIFrameworks) {
		t.Fatalf("ai framework rows = %d, want %d", len(v.AIFrameworks), len(AIFrameworks))
	}
	for i, f := range AIFrameworks {
		want := VocabAIFramework{ID: f.ID, Name: f.Name}
		if v.AIFrameworks[i] != want {
			t.Errorf("ai_frameworks[%d] = %+v, want %+v", i, v.AIFrameworks[i], want)
		}
	}
	if len(v.Bands) != len(Bands) {
		t.Fatalf("band rows = %d, want %d", len(v.Bands), len(Bands))
	}
	for i, b := range Bands {
		if v.Bands[i] != string(b) {
			t.Errorf("bands[%d] = %q, want %q", i, v.Bands[i], b)
		}
	}
}

// TestModelVocabWords pins a few values of the vocabulary as the web's fixture
// holds them (FIXTURE_VOCAB in secAssessModelFixture.ts), so the two sides
// agree on the words and on the order.
func TestModelVocabWords(t *testing.T) {
	v := ModelVocab()
	if got, want := v.Stride[0], (VocabStride{"spoofing", "S", "Spoofing", "Can something pretend to be this element, or to be a caller of it?"}); got != want {
		t.Errorf("stride[0] = %+v", got)
	}
	if got, want := v.Stride[5].ID, "elevation_of_privilege"; got != want {
		t.Errorf("stride[5] = %q, want %q", got, want)
	}
	if got, want := v.Linddun[4], (VocabLinddun{"disclosure_of_information", "Disclosure of information", "Can personal data reach someone who should not have it?"}); got != want {
		t.Errorf("linddun[4] = %+v", got)
	}
	var logStore VocabComponentType
	for _, c := range v.ComponentTypes {
		if c.ID == "log_store" {
			logStore = c
		}
	}
	if want := (VocabComponentType{"log_store", "data_store", true, "Log or audit store"}); logStore != want {
		t.Errorf("log_store = %+v, want %+v", logStore, want)
	}
	if got := v.WSTG[3]; got.ID != "ATHN" || got.Title != "Authentication" || got.AppliesWhen != "login" {
		t.Errorf("wstg[3] = %+v", got)
	}
	if want := []string{"low", "medium", "high", "critical"}; !reflect.DeepEqual(v.Bands, want) {
		t.Errorf("bands = %v, want %v", v.Bands, want)
	}
	if got, want := v.AIFrameworks[1], (VocabAIFramework{"owasp_agentic", "OWASP Top 10 for agentic applications"}); got != want {
		t.Errorf("ai_frameworks[1] = %+v", got)
	}
}

// TestModelVocabJSONRoundTrip pins that the vocabulary survives the encoding
// the server sends it in, empty slices included: a table never encodes as
// null.
func TestModelVocabJSONRoundTrip(t *testing.T) {
	v := ModelVocab()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back ModelVocabulary
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(v, back) {
		t.Errorf("the vocabulary changed in a round trip:\n%+v\n%+v", v, back)
	}
	var generic map[string]any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for k, val := range generic {
		list, ok := val.([]any)
		if !ok || len(list) == 0 {
			t.Errorf("%s = %v, want a non-empty list", k, val)
		}
	}
	// holds_logs is written only where it is true.
	for _, c := range generic["component_types"].([]any) {
		row := c.(map[string]any)
		_, has := row["holds_logs"]
		if has != (row["id"] == "log_store") {
			t.Errorf("holds_logs present = %v on %v", has, row["id"])
		}
	}
}

// TestModelVocabCopiesAreIndependent pins that a caller that changes the
// result leaves the tables, and the next result, as they were.
func TestModelVocabCopiesAreIndependent(t *testing.T) {
	first := ModelVocab()
	first.Stride[0].Name = "changed"
	first.Linddun[0].Question = "changed"
	first.ComponentTypes[0].Class = "changed"
	first.WSTG[0].Intent = "changed"
	first.AIFrameworks[0].Name = "changed"
	first.Bands[0] = "changed"
	first.Stride = append(first.Stride[:1], first.Stride[2:]...)

	if StrideCategories[0].Name == "changed" || LinddunCategories[0].Question == "changed" ||
		ComponentTypes[0].Class == "changed" || WSTGCategories[0].Intent == "changed" ||
		AIFrameworks[0].Name == "changed" || Bands[0] == "changed" {
		t.Fatal("changing the vocabulary changed a table")
	}
	if len(StrideCategories) != 6 || StrideCategories[1].ID != "tampering" {
		t.Error("changing the vocabulary reordered a table")
	}
	second := ModelVocab()
	if second.Stride[0].Name != "Spoofing" || second.Bands[0] != "low" || len(second.Stride) != 6 {
		t.Errorf("the next vocabulary carries the change: %+v", second.Stride[0])
	}
}
