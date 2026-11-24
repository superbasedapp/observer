package availcompose

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/components"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

const (
	orgA = "ab0e3298-277a-4098-99d8-d62d320776ad"
	orgB = "76a93b7b-ede7-48f2-b980-767dee4d56aa"
)

// TestSectionsMatchStaffVocabulary pins the section names to the staff
// vocabulary (and through it to the availability_inputs.section CHECK).
func TestSectionsMatchStaffVocabulary(t *testing.T) {
	t.Parallel()
	var want []string
	for _, s := range staffauth.KnownSections {
		want = append(want, string(s))
	}
	if got := Sections(); !slices.Equal(got, want) {
		t.Fatalf("Sections() = %v, staffauth.KnownSections = %v", got, want)
	}
}

// TestValidateInput: one case per rule an input can break, including the five
// values the Part A e2e review (SC-3) found stored, and the shapes that pass.
func TestValidateInput(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, section, key, value string
		ok                        bool
		want                      string
	}{
		{"named component", SectionComponents, "org.security", `{"reach":"named","orgs":["` + orgA + `"]}`, true, ""},
		{"component off", SectionComponents, "org.security", `{"reach":"off"}`, true, ""},
		{"component stage default", SectionComponents, "org.digest", `{"reach":"stage-default"}`, true, ""},
		{"component cohort", SectionComponents, "org.security", `{"reach":"cohort","cohort":"ring-1"}`, true, ""},
		{"SC-3 #1 unknown reach", SectionComponents, "org.security", `{"reach":"bogus"}`, false, "reach: unknown value"},
		{"SC-3 #2 unknown component", SectionComponents, "no.such.component", `{"reach":"named","orgs":["` + orgA + `"]}`, false, "unknown component"},
		{"named org not an id", SectionComponents, "org.security", `{"reach":"named","orgs":["x"]}`, false, "not an org id"},
		{"named org upper case", SectionComponents, "org.security", `{"reach":"named","orgs":["` + strings.ToUpper(orgA) + `"]}`, false, "not an org id"},
		{"named without orgs", SectionComponents, "org.security", `{"reach":"named"}`, false, "required for named reach"},
		{"core cannot be listed", SectionComponents, "org.core", `{"reach":"off"}`, false, "core is always available"},
		{"not offerable in pooled", SectionComponents, "org.sor.s3", `{"reach":"named","orgs":["` + orgA + `"]}`, false, "not offerable in pooled"},
		{"unknown field", SectionComponents, "org.security", `{"reach":"off","extra":1}`, false, "unknown field"},
		{"trailing data", SectionComponents, "org.security", `{"reach":"off"} {}`, false, "trailing data"},
		{"org pause", SectionOrgControls, orgA, `{"org":"` + orgA + `","ingest":{"mode":"pause"}}`, true, ""},
		{"org throttle", SectionOrgControls, orgB, `{"org":"` + orgB + `","ingest":{"mode":"throttle","rate_per_minute":30}}`, true, ""},
		{"platform inference", SectionOrgControls, PlatformKey, `{"org":"*","inference":[{"admission":"paused","dispatch":"on"}]}`, true, ""},
		{"SC-3 #3 org row naming every org", SectionOrgControls, orgA, `{"org":"*","ingest":{"mode":"pause"}}`, false, "must name"},
		{"SC-3 #4 negative throttle", SectionOrgControls, orgB, `{"org":"` + orgB + `","ingest":{"mode":"throttle","rate_per_minute":-5}}`, false, "throttle needs a positive rate"},
		{"org row naming another org", SectionOrgControls, orgA, `{"org":"` + orgB + `","ingest":{"mode":"pause"}}`, false, "must name"},
		{"platform ingest", SectionOrgControls, PlatformKey, `{"org":"*","ingest":{"mode":"pause"}}`, false, "never platform-wide"},
		{"platform row naming an org", SectionOrgControls, PlatformKey, `{"org":"` + orgA + `","inference":[{"admission":"paused","dispatch":"on"}]}`, false, "must name"},
		{"org key not an id", SectionOrgControls, "acme", `{"org":"acme","ingest":{"mode":"pause"}}`, false, "neither an org id"},
		{"no control", SectionOrgControls, orgA, `{"org":"` + orgA + `"}`, false, "carries no control"},
		{"pause with a rate", SectionOrgControls, orgA, `{"org":"` + orgA + `","ingest":{"mode":"pause","rate_per_minute":3}}`, false, "pause carries no rate"},
		{"repeated route", SectionOrgControls, orgA, `{"org":"` + orgA + `","inference":[{"admission":"on","dispatch":"on"},{"admission":"off","dispatch":"on"}]}`, false, "repeated entry"},
		{"unknown inference state", SectionOrgControls, orgA, `{"org":"` + orgA + `","inference":[{"admission":"maybe","dispatch":"on"}]}`, false, "admission"},
		{"flag named", SectionReleaseFlags, "flag.x", `{"reach":"named","orgs":["` + orgA + `"]}`, true, ""},
		{"SC-3 #5 cohort without a cohort", SectionReleaseFlags, "flag.x", `{"reach":"cohort"}`, false, "required for cohort reach"},
		{"unknown section", "bogus", "x", `{}`, false, "not an availability section"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateInput(c.section, c.key, []byte(c.value))
			if c.ok {
				if err != nil {
					t.Fatalf("ValidateInput = %v, want ok", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateInput = nil, want an error naming %q", c.want)
			}
			if !errors.Is(err, ErrInvalidInput) {
				t.Errorf("error %v does not wrap ErrInvalidInput", err)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not name %q", err, c.want)
			}
		})
	}
}

func goodInputs() []Input {
	return []Input{
		{Section: SectionReleaseFlags, Key: "flag.x", Value: []byte(`{"reach":"off"}`), Reason: "r3", Author: "staff:a"},
		{Section: SectionOrgControls, Key: orgB, Value: []byte(`{"org":"` + orgB + `","ingest":{"mode":"pause"}}`), Reason: "r2", Author: "staff:b"},
		{Section: SectionOrgControls, Key: PlatformKey, Value: []byte(`{"org":"*","inference":[{"admission":"paused","dispatch":"on"}]}`), Reason: "r4", Author: "staff:b"},
		{Section: SectionComponents, Key: "org.security", Value: []byte(`{"reach":"named","orgs":["` + orgB + `","` + orgA + `"]}`), Reason: "r1", Author: "staff:a"},
	}
}

var at = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

func TestComposeIsDeterministicAndValid(t *testing.T) {
	t.Parallel()
	in := goodInputs()
	c1, err := Compose(in, at)
	if err != nil || len(c1.Problems) > 0 {
		t.Fatalf("Compose = %v, problems %v", err, c1.Problems)
	}
	rev := slices.Clone(in)
	slices.Reverse(rev)
	c2, err := Compose(rev, at)
	if err != nil {
		t.Fatal(err)
	}
	if string(c1.JSON) != string(c2.JSON) {
		t.Fatalf("input order changed the body:\n%s\n%s", c1.JSON, c2.JSON)
	}
	// What the signer and a host run on it.
	b, err := DecodeBody(c1.JSON)
	if err != nil {
		t.Fatalf("DecodeBody: %v", err)
	}
	if err := components.CheckEnvelope(b); err != nil {
		t.Fatalf("CheckEnvelope: %v", err)
	}
	if b.IssuedAt != "2026-11-23T12:00:00Z" {
		t.Errorf("issued_at = %q", b.IssuedAt)
	}
	if got := b.Components[0]; got.Component != "org.security" || !slices.Equal(got.Orgs, []string{orgB, orgA}) {
		t.Errorf("component row = %+v, want org.security with its orgs sorted", got)
	}
	if b.OrgControls[0].Org != pc.AllOrgs || b.OrgControls[0].Reason != "r4" || b.OrgControls[0].Author != "staff:b" {
		t.Errorf("first org control = %+v, want the platform-wide row with its reason and author", b.OrgControls[0])
	}
}

func TestComposeEmptyInputsIsAValidEmptyBody(t *testing.T) {
	t.Parallel()
	c, err := Compose(nil, at)
	if err != nil || len(c.Problems) > 0 {
		t.Fatalf("Compose(nil) = %v %v", err, c.Problems)
	}
	if string(c.JSON) != `{"issued_at":"2026-11-23T12:00:00Z","components":[],"org_controls":[],"release_flags":[]}` {
		t.Fatalf("empty body = %s", c.JSON)
	}
}

func TestComposeReportsEveryProblemAndNoBody(t *testing.T) {
	t.Parallel()
	in := append(goodInputs(),
		Input{Section: SectionComponents, Key: "no.such.component", Value: []byte(`{"reach":"off"}`), Reason: "x", Author: "staff:a"},
		Input{Section: SectionOrgControls, Key: orgA, Value: []byte(`{"org":"*","ingest":{"mode":"pause"}}`), Reason: "x", Author: "staff:a"},
	)
	c, err := Compose(in, at)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Problems) != 2 || c.JSON != nil {
		t.Fatalf("problems = %v, json = %s; want 2 problems and no body", c.Problems, c.JSON)
	}
	if c.Problems[0].Section != SectionComponents || c.Problems[1].Key != orgA {
		t.Errorf("problems out of section order: %v", c.Problems)
	}
}

func TestDigest(t *testing.T) {
	t.Parallel()
	in := goodInputs()
	d := Digest(in)
	if len(d) != 64 {
		t.Fatalf("digest %q", d)
	}
	rev := slices.Clone(in)
	slices.Reverse(rev)
	if Digest(rev) != d {
		t.Error("input order changed the digest")
	}
	spaced := slices.Clone(in)
	spaced[0].Value = []byte(`{ "reach" : "off" }`)
	if Digest(spaced) != d {
		t.Error("whitespace in a value changed the digest")
	}
	for i, mut := range []func(*Input){
		func(x *Input) { x.Value = []byte(`{"reach":"stage-default"}`) },
		func(x *Input) { x.Reason = "other" },
		func(x *Input) { x.Author = "staff:z" },
		func(x *Input) { x.Key = "flag.y" },
	} {
		m := slices.Clone(in)
		mut(&m[0])
		if Digest(m) == d {
			t.Errorf("mutation %d did not change the digest", i)
		}
	}
	if Digest(in[:3]) == d {
		t.Error("removing an input did not change the digest")
	}
}

func TestDiff(t *testing.T) {
	t.Parallel()
	prev, err := Compose(goodInputs(), at)
	if err != nil {
		t.Fatal(err)
	}
	if got := Diff(&prev.Body, &prev.Body); len(got) != 0 {
		t.Fatalf("Diff(same) = %v", got)
	}
	later, err := Compose(goodInputs(), at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got := Diff(&prev.Body, &later.Body); len(got) != 0 {
		t.Fatalf("issued_at alone made a change: %v", got)
	}
	in := goodInputs()
	in[0] = Input{Section: SectionReleaseFlags, Key: "flag.x", Value: []byte(`{"reach":"stage-default"}`), Reason: "r3", Author: "staff:a"}  // changed
	in = slices.Delete(in, 1, 2)                                                                                                             // org B removed
	in = append(in, Input{Section: SectionComponents, Key: "org.digest", Value: []byte(`{"reach":"off"}`), Reason: "r5", Author: "staff:a"}) // added
	next, err := Compose(in, at)
	if err != nil || len(next.Problems) > 0 {
		t.Fatal(err, next.Problems)
	}
	got := Diff(&prev.Body, &next.Body)
	want := []struct {
		section, key string
		kind         ChangeKind
	}{
		{SectionComponents, "org.digest", ChangeAdded},
		{SectionOrgControls, orgB, ChangeRemoved},
		{SectionReleaseFlags, "flag.x", ChangeChanged},
	}
	if len(got) != len(want) {
		t.Fatalf("Diff = %+v", got)
	}
	for i, w := range want {
		g := got[i]
		if g.Section != w.section || g.Key != w.key || g.Kind != w.kind {
			t.Errorf("change %d = %s/%s %s, want %s/%s %s", i, g.Section, g.Key, g.Kind, w.section, w.key, w.kind)
		}
		if (g.Kind == ChangeAdded) != (g.Before == nil) || (g.Kind == ChangeRemoved) != (g.After == nil) {
			t.Errorf("change %d before/after = %s / %s", i, g.Before, g.After)
		}
	}
	all := Diff(nil, &next.Body)
	if len(all) != 4 || slices.ContainsFunc(all, func(c Change) bool { return c.Kind != ChangeAdded }) {
		t.Errorf("Diff(nil, next) = %+v, want every row added", all)
	}
	platform := Diff(nil, &prev.Body)
	if !slices.ContainsFunc(platform, func(c Change) bool { return c.Section == SectionOrgControls && c.Key == PlatformKey }) {
		t.Errorf("the platform-wide row is not keyed %q: %+v", PlatformKey, platform)
	}
}

func TestDecodeBodyRefusesUnknownFields(t *testing.T) {
	t.Parallel()
	if _, err := DecodeBody([]byte(`{"issued_at":"2026-11-23T12:00:00Z","components":[],"org_controls":[],"release_flags":[],"x":1}`)); err == nil {
		t.Fatal("DecodeBody accepted an unknown field")
	}
	if _, err := DecodeBody([]byte(`{"issued_at":"yesterday","components":[],"org_controls":[],"release_flags":[]}`)); err == nil {
		t.Fatal("DecodeBody accepted a bad issued_at")
	}
}

// TestComposedBodyRoundTripsThroughJSON: the body a host decodes equals the
// composed one.
func TestComposedBodyRoundTripsThroughJSON(t *testing.T) {
	t.Parallel()
	c, err := Compose(goodInputs(), at)
	if err != nil {
		t.Fatal(err)
	}
	var back pc.AvailabilityBody
	if err := json.Unmarshal(c.JSON, &back); err != nil {
		t.Fatal(err)
	}
	again, err := json.Marshal(back)
	if err != nil || string(again) != string(c.JSON) {
		t.Fatalf("round trip changed the body:\n%s\n%s", c.JSON, again)
	}
}
