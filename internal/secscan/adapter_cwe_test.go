package secscan

import (
	"reflect"
	"strconv"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secfinding/sarif"
)

// TestCWEFromTags: one row per tag form, the malformed ones and the
// duplicates; an untagged rule gives nil.
func TestCWEFromTags(t *testing.T) {
	t.Parallel()
	many := make([]string, 0, 40)
	for i := 1; i <= 40; i++ {
		many = append(many, "CWE-"+strconv.Itoa(i))
	}
	cases := []struct {
		name string
		tags []string
		want []string
	}{
		{"nil tags", nil, nil},
		{"no cwe tag", []string{"security", "correctness"}, nil},
		{"external form", []string{"external/cwe/cwe-79"}, []string{"CWE-79"}},
		{"upper form", []string{"CWE-79"}, []string{"CWE-79"}},
		{"lower form", []string{"cwe-79"}, []string{"CWE-79"}},
		{"mixed case external", []string{"External/CWE/CWE-89"}, []string{"CWE-89"}},
		{"colon form", []string{"cwe:22"}, []string{"CWE-22"}},
		{"title suffix after colon", []string{"CWE-79: Improper Neutralization of Input"}, []string{"CWE-79"}},
		{"title suffix after space", []string{"external/cwe/cwe-89 SQL injection"}, []string{"CWE-89"}},
		{"surrounding space", []string{"  cwe-78  "}, []string{"CWE-78"}},
		{"leading zeros normalized", []string{"CWE-0079"}, []string{"CWE-79"}},
		{"duplicate across forms", []string{"CWE-79", "external/cwe/cwe-79", "cwe-79"}, []string{"CWE-79"}},
		{"order kept", []string{"cwe-89", "security", "cwe-79", "cwe-89"}, []string{"CWE-89", "CWE-79"}},
		{"malformed: no number", []string{"cwe-", "external/cwe/cwe-"}, nil},
		{"malformed: letters", []string{"cwe-abc", "cwe-7x"}, nil},
		{"malformed: zero", []string{"cwe-0", "cwe-000"}, nil},
		{"malformed: too long", []string{"cwe-123456"}, nil},
		{"malformed: negative", []string{"cwe--5"}, nil},
		{"malformed: no separator", []string{"cwe79"}, nil},
		{"malformed: trailing junk", []string{"cwe-79abc", "cwe-79;drop"}, nil},
		{"malformed amid good", []string{"cwe-x", "cwe-20"}, []string{"CWE-20"}},
		{"unrelated prefix", []string{"owasp/cwe-79", "mycwe-79"}, nil},
		{"bounded", many, many[:maxCWEPerFinding]},
	}
	for _, tc := range cases {
		got := cweFromTags(tc.tags)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: cweFromTags(%q) = %v, want %v", tc.name, tc.tags, got, tc.want)
		}
		for _, c := range got {
			if !policy.ValidCWE(c) {
				t.Errorf("%s: %q is not a valid CWE id", tc.name, c)
			}
		}
	}
}

// TestAdaptCarriesCWE: a tagged rule fills References.CWE through every row;
// the same run without CWE tags leaves the finding unchanged.
func TestAdaptCarriesCWE(t *testing.T) {
	t.Parallel()
	doc := func(props string) sarif.Run {
		src := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x","rules":[{"id":"r1","properties":` + props + `}]}},"results":[{"ruleId":"r1","level":"error","locations":[{"physicalLocation":{"artifactLocation":{"uri":"a/b.go"},"region":{"startLine":3}}}]}]}]}`
		lg, err := sarif.Decode([]byte(src))
		if err != nil {
			t.Fatal(err)
		}
		return lg.Runs[0]
	}
	opt := AdaptOptions{ProjectRoot: "/work/project", ProjectRootHash: "h", Scope: policy.FindingScopeManual}
	for _, name := range []string{"sarif-import", "custom", "opengrep"} {
		row, _ := Adapter(name)
		tagged, _ := Adapt(row, doc(`{"tags":["security","external/cwe/cwe-79","CWE-79","cwe-bad","CWE-89"]}`), opt)
		bare, _ := Adapt(row, doc(`{}`), opt)
		notags, _ := Adapt(row, doc(`{"tags":["security"]}`), opt)
		if len(tagged) != 1 || len(bare) != 1 || len(notags) != 1 {
			t.Fatalf("%s: %d/%d/%d findings", name, len(tagged), len(bare), len(notags))
		}
		if want := []string{"CWE-79", "CWE-89"}; !reflect.DeepEqual(tagged[0].References.CWE, want) {
			t.Errorf("%s: tagged CWE = %v, want %v", name, tagged[0].References.CWE, want)
		}
		if len(bare[0].References.CWE) != 0 || len(notags[0].References.CWE) != 0 {
			t.Errorf("%s: an untagged rule gained CWE: %v / %v", name, bare[0].References.CWE, notags[0].References.CWE)
		}
		// The CWE tags change References and nothing else (identity, key and
		// severity are unchanged).
		a, b := tagged[0], bare[0]
		a.References, b.References = secfinding.References{}, secfinding.References{}
		if !reflect.DeepEqual(a, b) {
			t.Errorf("%s: tags changed more than References:\n%+v\n%+v", name, a, b)
		}
		if !reflect.DeepEqual(bare[0], notags[0]) {
			t.Errorf("%s: a non-CWE tag changed the finding", name)
		}
	}
	// The existing fixture carries no CWE tag: unchanged.
	row, _ := Adapter("opengrep")
	fs, _ := Adapt(row, loadRun(t, "opengrep.sarif"), AdaptOptions{ProjectRoot: "/work/project", RulePrefix: "home.u.observer.rules", Scope: policy.FindingScopeManual})
	if len(fs) != 1 || len(fs[0].References.CWE) != 0 {
		t.Errorf("opengrep fixture: %+v", fs)
	}
}
