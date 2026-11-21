package promptreg

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)

func TestValidName(t *testing.T) {
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{"support-reply", true},
		{"a", true},
		{"A.b_c-9", true},
		{"9lives", true},
		{"", false},
		{"-lead", false},
		{".lead", false},
		{"has space", false},
		{"a/b", false},
		{strings.Repeat("a", 128), true},
		{strings.Repeat("a", 129), false},
		{"ünï", false},
	} {
		if got := ValidName(tc.name); got != tc.ok {
			t.Errorf("ValidName(%q) = %v, want %v", tc.name, got, tc.ok)
		}
	}
}

func TestErrorStatusRows(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
		ok     bool
	}{
		{badRequest("x"), 400, "bad_request", true},
		{ErrPromptNotFound, 404, "prompt_not_found", true},
		{ErrVersionNotFound, 404, "version_not_found", true},
		{ErrLabelNotSet, 404, "label_not_set", true},
		{ErrNothingToRollBack, 409, "nothing_to_roll_back", true},
		{ErrNoChange, 409, "no_change", true},
		{ErrTypeMismatch, 409, "type_mismatch", true},
		{ErrApprovalRequired, 409, "approval_required", true},
		{ErrSelfApproval, 403, "self_approval", true},
		{ErrProposalNotFound, 404, "proposal_not_found", true},
		{ErrProposalClosed, 409, "proposal_closed", true},
		{ErrProposalStale, 409, "proposal_stale", true},
		{errors.New("disk on fire"), 500, "internal", false},
	} {
		s, c, ok := ErrorStatus(tc.err)
		if s != tc.status || c != tc.code || ok != tc.ok {
			t.Errorf("ErrorStatus(%v) = %d %s %v, want %d %s %v", tc.err, s, c, ok, tc.status, tc.code, tc.ok)
		}
	}
}

func TestParseSelector(t *testing.T) {
	for _, tc := range []struct {
		label, version string
		want           Selector
		wantErr        bool
	}{
		{"", "", Selector{Label: "production"}, false},
		{"staging", "", Selector{Label: "staging"}, false},
		{" production ", "", Selector{Label: "production"}, false},
		{"", "3", Selector{Version: 3}, false},
		{"staging", "3", Selector{}, true},
		{"latest", "", Selector{}, true},
		{"", "0", Selector{}, true},
		{"", "-1", Selector{}, true},
		{"", "x", Selector{}, true},
	} {
		got, err := ParseSelector(tc.label, tc.version)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("ParseSelector(%q,%q) = %+v, %v", tc.label, tc.version, got, err)
		}
		if err != nil && !errors.Is(err, ErrBadRequest) {
			t.Errorf("ParseSelector error %v is not ErrBadRequest", err)
		}
	}
	if got := (Selector{Version: 2}).ResolvedBy(); got != "version:2" {
		t.Errorf("ResolvedBy = %q", got)
	}
	if got := (Selector{Label: "staging"}).ResolvedBy(); got != "label:staging" {
		t.Errorf("ResolvedBy = %q", got)
	}
}

func TestResolve(t *testing.T) {
	labels := LabelState{LabelProduction: 2}
	for _, tc := range []struct {
		name   string
		sel    Selector
		latest int
		want   int
		err    error
	}{
		{"no prompt", Selector{Label: "production"}, 0, 0, ErrPromptNotFound},
		{"label", Selector{Label: "production"}, 3, 2, nil},
		{"label unset", Selector{Label: "staging"}, 3, 0, ErrLabelNotSet},
		{"version", Selector{Version: 3}, 3, 3, nil},
		{"version past latest", Selector{Version: 4}, 3, 0, ErrVersionNotFound},
		{"bad label", Selector{Label: "dev"}, 3, 0, ErrBadRequest},
	} {
		got, err := Resolve(tc.sel, tc.latest, labels)
		if got != tc.want || !errors.Is(err, tc.err) {
			t.Errorf("%s: Resolve = %d, %v; want %d, %v", tc.name, got, err, tc.want, tc.err)
		}
	}
}

func TestPlanMove(t *testing.T) {
	labels := LabelState{LabelProduction: 2}
	for _, tc := range []struct {
		name   string
		latest int
		label  string
		to     int
		want   Move
		err    error
	}{
		{"set unset label", 3, "staging", 3, Move{Label: "staging", From: 0, To: 3, Actor: "u", At: t0}, nil},
		{"move", 3, "production", 3, Move{Label: "production", From: 2, To: 3, Actor: "u", At: t0}, nil},
		{"no change", 3, "production", 2, Move{}, ErrNoChange},
		{"missing version", 3, "production", 4, Move{}, ErrVersionNotFound},
		{"zero version", 3, "production", 0, Move{}, ErrVersionNotFound},
		{"bad label", 3, "latest", 1, Move{}, ErrBadRequest},
		{"no prompt", 0, "production", 1, Move{}, ErrPromptNotFound},
	} {
		got, err := PlanMove(labels, tc.latest, tc.label, tc.to, "u", t0)
		if !reflect.DeepEqual(got, tc.want) || !errors.Is(err, tc.err) {
			t.Errorf("%s: PlanMove = %+v, %v; want %+v, %v", tc.name, got, err, tc.want, tc.err)
		}
	}
}

// TestPlanRollbackWalksBack pins contract section 6: repeated rollbacks walk
// back through the promotions, a manual move back is itself a promotion, and
// a first assignment has nothing behind it.
func TestPlanRollbackWalksBack(t *testing.T) {
	var hist []Move
	labels := LabelState{}
	move := func(to int) {
		m, err := PlanMove(labels, 9, LabelStaging, to, "u", t0)
		if err != nil {
			t.Fatalf("move %d: %v", to, err)
		}
		hist = append(hist, m)
		labels = labels.Apply(m)
	}
	rollback := func() (int, error) {
		m, err := PlanRollback(labels, nil, hist, LabelStaging, "u", t0)
		if err != nil {
			return 0, err
		}
		if !m.Rollback || m.From != labels[LabelStaging] {
			t.Fatalf("rollback move %+v", m)
		}
		hist = append(hist, m)
		labels = labels.Apply(m)
		return m.To, nil
	}
	if _, err := rollback(); !errors.Is(err, ErrLabelNotSet) {
		t.Fatalf("unset label rollback: %v", err)
	}
	move(1)
	move(2)
	move(3)
	// An unrelated label's history never counts.
	hist = append(hist, Move{Label: LabelProduction, From: 1, To: 3})
	for _, want := range []int{2, 1} {
		got, err := rollback()
		if err != nil || got != want {
			t.Fatalf("rollback = %d, %v; want %d", got, err, want)
		}
	}
	if _, err := rollback(); !errors.Is(err, ErrNothingToRollBack) {
		t.Fatalf("rollback past the first assignment: %v", err)
	}
	move(3) // 1 -> 3, a promotion
	if got, err := rollback(); err != nil || got != 1 {
		t.Fatalf("rollback after re-promotion = %d, %v; want 1", got, err)
	}
	if _, err := PlanRollback(labels, nil, hist, "latest", "u", t0); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("bad label: %v", err)
	}
}

func TestNewVersionValidation(t *testing.T) {
	text := json.RawMessage(`"Hello {{name}}"`)
	chat := json.RawMessage(`[{"role":"system","content":"hi"}]`)
	for _, tc := range []struct {
		name     string
		pname    string
		existing Type
		d        Draft
		err      error
	}{
		{"text default type", "p", "", Draft{Prompt: text}, nil},
		{"chat", "p", "", Draft{Type: TypeChat, Prompt: chat, Labels: []string{"staging", "production", "staging"}}, nil},
		{"bad name", "a/b", "", Draft{Prompt: text}, ErrBadRequest},
		{"missing prompt", "p", "", Draft{}, ErrBadRequest},
		{"text not a string", "p", "", Draft{Prompt: chat}, ErrBadRequest},
		{"chat bad role", "p", "", Draft{Type: TypeChat, Prompt: json.RawMessage(`[{"role":"robot","content":"x"}]`)}, ErrBadRequest},
		{"chat as JSON text", "p", "", Draft{Type: TypeChat, Prompt: json.RawMessage(`"[{\"role\":\"user\",\"content\":\"x\"}]"`)}, nil},
		{"chat unknown field", "p", "", Draft{Type: TypeChat, Prompt: json.RawMessage(`[{"role":"user","content":"x","name":"y"}]`)}, ErrBadRequest},
		{"chat empty", "p", "", Draft{Type: TypeChat, Prompt: json.RawMessage(`[]`)}, ErrBadRequest},
		{"bad type", "p", "", Draft{Type: "image", Prompt: text}, ErrBadRequest},
		{"type mismatch", "p", TypeChat, Draft{Prompt: text}, ErrTypeMismatch},
		{"config not object", "p", "", Draft{Prompt: text, Config: json.RawMessage(`[1]`)}, ErrBadRequest},
		{"config too big", "p", "", Draft{Prompt: text, Config: json.RawMessage(`{"a":"` + strings.Repeat("x", MaxConfigBytes) + `"}`)}, ErrBadRequest},
		{"body too big", "p", "", Draft{Prompt: json.RawMessage(`"` + strings.Repeat("x", MaxBodyBytes+1) + `"`)}, ErrBadRequest},
		{"commit too long", "p", "", Draft{Prompt: text, CommitMessage: strings.Repeat("x", MaxCommitMessageBytes+1)}, ErrBadRequest},
		{"bad label", "p", "", Draft{Prompt: text, Labels: []string{"latest"}}, ErrBadRequest},
	} {
		_, err := NewVersion(tc.pname, 1, tc.existing, tc.d, "u", t0)
		if !errors.Is(err, tc.err) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.err)
		}
	}
	if got := DraftLabels(Draft{Labels: []string{"staging", "production", "staging"}}); !reflect.DeepEqual(got, []string{"production", "staging"}) {
		t.Errorf("DraftLabels = %v", got)
	}
}

func TestNewVersionCanonical(t *testing.T) {
	v, err := NewVersion("p", 2, TypeText, Draft{
		Prompt: json.RawMessage(` "a <b> & {{c}}" `), Config: json.RawMessage(`{ "model" : "m",  "t": 0.2 }`),
	}, "u", t0.Add(500*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if string(v.Prompt) != `"a <b> & {{c}}"` || string(v.Config) != `{"model":"m","t":0.2}` {
		t.Fatalf("canonical prompt %s config %s", v.Prompt, v.Config)
	}
	if !v.CreatedAt.Equal(t0) || v.Type != TypeText || !strings.HasPrefix(v.Digest, "sha256:") || len(v.Digest) != 71 {
		t.Fatalf("version %+v", v)
	}
	again, _ := NewVersion("p", 2, TypeText, Draft{Prompt: json.RawMessage(`"a <b> & {{c}}"`), Config: json.RawMessage(`{"model":"m","t":0.2}`)}, "other", t0.Add(time.Hour))
	if again.Digest != v.Digest {
		t.Fatal("the digest depends on the actor or time; it must hash content only")
	}
	other, _ := NewVersion("p", 3, TypeText, Draft{Prompt: json.RawMessage(`"a <b> & {{c}}"`)}, "u", t0)
	if other.Digest == v.Digest {
		t.Fatal("the digest ignores the version number")
	}
	empty, _ := NewVersion("p", 1, "", Draft{Prompt: json.RawMessage(`"x"`), Config: json.RawMessage(`null`)}, "u", t0)
	if string(empty.Config) != "{}" {
		t.Fatalf("null config = %s", empty.Config)
	}
}

type compileCase struct {
	Name      string            `json:"name"`
	Type      Type              `json:"type"`
	Prompt    json.RawMessage   `json:"prompt"`
	Variables []string          `json:"variables"`
	Values    map[string]string `json:"values"`
	Want      json.RawMessage   `json:"want"`
	Missing   []string          `json:"missing"`
}

// TestCompileCases runs the normative compile cases the SDKs share
// (sdk/contract/prompt-compile-cases.json, contract section 4).
func TestCompileCases(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "sdk", "contract", "prompt-compile-cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Cases []compileCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Cases) < 10 {
		t.Fatalf("only %d cases", len(file.Cases))
	}
	for _, tc := range file.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			v, err := NewVersion("p", 1, "", Draft{Type: tc.Type, Prompt: tc.Prompt}, "u", t0)
			if err != nil {
				t.Fatalf("NewVersion: %v", err)
			}
			vars, err := Variables(v.Type, v.Prompt)
			if err != nil || !reflect.DeepEqual(vars, nonNilStrings(tc.Variables)) {
				t.Fatalf("Variables = %v, %v; want %v", vars, err, tc.Variables)
			}
			got, err := Compile(v.Type, v.Prompt, tc.Values)
			if tc.Missing != nil {
				var me *MissingVariablesError
				if !errors.As(err, &me) || !reflect.DeepEqual(me.Names, tc.Missing) {
					t.Fatalf("Compile err = %v, want missing %v", err, tc.Missing)
				}
				return
			}
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			if !jsonEqual(t, got, tc.Want) {
				t.Fatalf("Compile = %s, want %s", got, tc.Want)
			}
		})
	}
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &y); err != nil {
		t.Fatal(err)
	}
	return reflect.DeepEqual(x, y)
}

func TestETagMatches(t *testing.T) {
	const e = `"abc"`
	for _, tc := range []struct {
		h  string
		ok bool
	}{
		{`"abc"`, true},
		{`W/"abc"`, true},
		{`"x", "abc"`, true},
		{`*`, true},
		{``, false},
		{`"abd"`, false},
		{`abc`, false},
	} {
		if got := ETagMatches(tc.h, e); got != tc.ok {
			t.Errorf("ETagMatches(%q) = %v", tc.h, got)
		}
	}
}

func sampleVersion(t *testing.T) Version {
	t.Helper()
	v, err := NewVersion("support-reply", 3, "", Draft{
		Prompt: json.RawMessage(`"Hello {{customer}}, thanks for writing about {{topic}}."`),
		Config: json.RawMessage(`{"model":"gpt-5.1-mini","temperature":0.2}`), CommitMessage: "tone fix",
	}, "admin-1", t0)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestFetchGolden pins the fetch body to the recorded contract fixture
// (sdk/contract/prompt-fetch-response.json): the org and the machine both
// serve these bytes.
func TestFetchGolden(t *testing.T) {
	v := sampleVersion(t)
	f, err := Fetch(v, LabelState{LabelProduction: 3, LabelStaging: 4}, Selector{Label: LabelProduction})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "sdk", "contract", "prompt-fetch-response.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Headers map[string]string `json:"headers"`
		Body    json.RawMessage   `json:"body"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(t, f.Body, fixture.Body) {
		t.Fatalf("fetch body drifted from the fixture:\n got %s\nwant %s", f.Body, fixture.Body)
	}
	if fixture.Headers["Etag"] != f.ETag {
		t.Fatalf("fixture ETag %q, served %q", fixture.Headers["Etag"], f.ETag)
	}
	if !bytes.HasSuffix(f.Body, []byte("\n")) || !strings.Contains(string(f.Body), `"prompt":"Hello {{customer}}`) {
		t.Fatalf("body %s", f.Body)
	}
}

func TestFetchETagFollowsLabels(t *testing.T) {
	v := sampleVersion(t)
	sel := Selector{Label: LabelProduction}
	a, _ := Fetch(v, LabelState{LabelProduction: 3}, sel)
	b, _ := Fetch(v, LabelState{LabelProduction: 3}, sel)
	c, _ := Fetch(v, LabelState{LabelProduction: 3, LabelStaging: 3}, sel)
	d, _ := Fetch(v, LabelState{LabelProduction: 3}, Selector{Version: 3})
	if a.ETag != b.ETag {
		t.Fatal("the ETag is not deterministic")
	}
	if a.ETag == c.ETag {
		t.Fatal("a label moving onto the version must change the ETag")
	}
	if a.ETag == d.ETag {
		t.Fatal("resolved_by is in the body, so a version fetch has its own ETag")
	}
}

func TestListPages(t *testing.T) {
	rows := []Summary{{Name: "a", LatestVersion: 1}, {Name: "b", LatestVersion: 2, Labels: LabelState{"production": 2}}, {Name: "c"}}
	q, err := ParseListQuery("2", "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := List(rows, q)
	if err != nil {
		t.Fatal(err)
	}
	var got ListBody
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Prompts) != 2 || got.NextAfter != "b" || got.Prompts[0].Labels == nil {
		t.Fatalf("page %+v", got)
	}
	b, _ = List(rows[:1], q)
	_ = json.Unmarshal(b, &got)
	if got.NextAfter != "" || len(got.Prompts) != 1 {
		t.Fatalf("last page %+v", got)
	}
	for _, bad := range [][2]string{{"0", ""}, {"501", ""}, {"x", ""}, {"", "a/b"}} {
		if _, err := ParseListQuery(bad[0], bad[1]); !errors.Is(err, ErrBadRequest) {
			t.Errorf("ParseListQuery(%q,%q) = %v", bad[0], bad[1], err)
		}
	}
}

func TestDetail(t *testing.T) {
	v1, _ := NewVersion("p", 1, "", Draft{Prompt: json.RawMessage(`"{{a}}"`)}, "u", t0)
	v2, _ := NewVersion("p", 2, TypeText, Draft{Prompt: json.RawMessage(`"{{b}}"`)}, "u", t0)
	hist := []Move{{Label: "production", From: 0, To: 1, At: t0}, {Label: "production", From: 1, To: 2, At: t0}, {Label: "staging", From: 0, To: 2, At: t0}}
	d, err := Detail("p", []Version{v1, v2}, LabelState{"production": 2, "staging": 2}, nil, hist)
	if err != nil {
		t.Fatal(err)
	}
	if d.LatestVersion != 2 || d.Type != TypeText || len(d.Versions) != 2 || d.Versions[0].Version != 2 {
		t.Fatalf("detail %+v", d)
	}
	if !reflect.DeepEqual(d.Versions[0].Labels, []string{"production", "staging"}) || d.History[0].Label != "staging" {
		t.Fatalf("labels/history %+v", d)
	}
	if !reflect.DeepEqual(d.RollbackTargets, LabelState{"production": 1}) {
		t.Fatalf("rollback targets %+v", d.RollbackTargets)
	}
}

func TestTimeRoundTrip(t *testing.T) {
	s := FormatTime(t0.Add(123 * time.Millisecond))
	got, err := ParseTime(s)
	if err != nil || !got.Equal(t0) || s != "2026-11-19T10:00:00Z" {
		t.Fatalf("%q %v %v", s, got, err)
	}
	if z, err := ParseTime(""); err != nil || !z.IsZero() || FormatTime(time.Time{}) != "" {
		t.Fatal("zero time")
	}
}
