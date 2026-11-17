package releaseflag

import (
	"errors"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/components"
)

func day(m time.Month, d int) time.Time { return time.Date(2026, m, d, 0, 0, 0, 0, time.UTC) }

// testOnlyFlag is a fixture; it is not in the declared table.
func testOnlyFlag() Flag {
	return Flag{
		Name: "test-only-fixture", Component: "org.core", Owner: "lane-test",
		Defaults: map[DeploymentKind]bool{KindSharedSaaS: true, KindDedicated: false, KindSelfHosted: false},
		Created:  day(time.January, 1), Expires: day(time.February, 1),
	}
}

func componentExists(id string) bool { _, ok := components.Get(id); return ok }

func TestResolve(t *testing.T) {
	t.Parallel()
	partial := testOnlyFlag()
	partial.Name = "partial"
	partial.Defaults = map[DeploymentKind]bool{KindSharedSaaS: true}
	s := New([]Flag{testOnlyFlag(), partial})
	cases := []struct {
		name    string
		flag    string
		kind    DeploymentKind
		want    bool
		wantErr bool
	}{
		{"saas on", "test-only-fixture", KindSharedSaaS, true, false},
		{"dedicated off", "test-only-fixture", KindDedicated, false, false},
		{"self-hosted off", "test-only-fixture", KindSelfHosted, false, false},
		{"unknown flag", "nope", KindSharedSaaS, false, true},
		{"missing kind default", "partial", KindDedicated, false, true},
		{"unknown kind", "test-only-fixture", DeploymentKind("x"), false, true},
	}
	for _, c := range cases {
		got, err := s.Resolve(c.flag, c.kind)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("%s: got (%v, %v), want (%v, err=%v)", c.name, got, err, c.want, c.wantErr)
		}
	}
	if _, err := s.Resolve("nope", KindSharedSaaS); !errors.Is(err, ErrUnknownFlag) {
		t.Errorf("unknown flag error not ErrUnknownFlag: %v", err)
	}
}

func TestExpiryCheck(t *testing.T) {
	t.Parallel()
	s := New([]Flag{testOnlyFlag()})
	cases := []struct {
		name     string
		now      time.Time
		changed  []string
		wantFail int
		wantWarn int
	}{
		{"not expired, touched", day(time.January, 15), []string{"org.core"}, 0, 0},
		{"expired and touched fails", day(time.February, 2), []string{"org.core"}, 1, 0},
		{"expired untouched warns", day(time.February, 2), []string{"org.oidc"}, 0, 1},
		{"expired no changes warns", day(time.February, 2), nil, 0, 1},
	}
	for _, c := range cases {
		r := s.Check(c.now, c.changed)
		if len(r.Failures) != c.wantFail || len(r.Warnings) != c.wantWarn || r.Failed() != (c.wantFail > 0) {
			t.Errorf("%s: got %d failures %d warnings", c.name, len(r.Failures), len(r.Warnings))
		}
	}
	if got := s.Expired(day(time.February, 2)); len(got) != 1 || got[0].Name != "test-only-fixture" {
		t.Errorf("Expired = %v", got)
	}
	if got := s.Expired(day(time.January, 2)); len(got) != 0 {
		t.Errorf("Expired before expiry = %v", got)
	}
}

func TestValidateRules(t *testing.T) {
	t.Parallel()
	mut := func(f func(*Flag)) []Flag { x := testOnlyFlag(); f(&x); return []Flag{x} }
	cases := []struct {
		name  string
		flags []Flag
		ok    bool
	}{
		{"valid", []Flag{testOnlyFlag()}, true},
		{"no owner", mut(func(f *Flag) { f.Owner = "" }), false},
		{"unknown component", mut(func(f *Flag) { f.Component = "no.such" }), false},
		{"missing kind default", mut(func(f *Flag) { f.Defaults = map[DeploymentKind]bool{KindSharedSaaS: true} }), false},
		{"expiry before creation", mut(func(f *Flag) { f.Expires = f.Created.Add(-time.Hour) }), false},
		{"too long lived", mut(func(f *Flag) { f.Expires = f.Created.Add(MaxLifetime + time.Hour) }), false},
		{"duplicate", []Flag{testOnlyFlag(), testOnlyFlag()}, false},
		{"empty name", mut(func(f *Flag) { f.Name = "" }), false},
	}
	for _, c := range cases {
		if err := Validate(c.flags, componentExists); (err == nil) != c.ok {
			t.Errorf("%s: err = %v", c.name, err)
		}
	}
}

// TestDeclaredFlagsAreValid pins every declared flag: owner, existing
// component, expiry after creation, a default for every deployment kind.
func TestDeclaredFlagsAreValid(t *testing.T) {
	t.Parallel()
	if err := Validate(Declared(), componentExists); err != nil {
		t.Fatal(err)
	}
}
