package crossplane

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestRepositoryHashMatchesTheNodeRemoteHash(t *testing.T) {
	// The node stores git.NormalizeRemote(origin) and hashes it; an app that
	// reports the https URL of the same repository must hash identically.
	want := hashHex("github.com/acme/payments-api")
	for _, raw := range []string{
		"https://github.com/acme/payments-api",
		"https://github.com/acme/payments-api.git",
		"git@github.com:acme/payments-api.git",
		"ssh://git@github.com/acme/payments-api",
		"  https://github.com/acme/payments-api/  ",
	} {
		if got := RepositoryHash(raw); got != want {
			t.Errorf("RepositoryHash(%q) = %s, want %s", raw, got, want)
		}
	}
	if RepositoryHash("") != "" || RepositoryHash("   ") != "" {
		t.Error("empty repository must hash to empty")
	}
}

func TestRepositoryFormHashes(t *testing.T) {
	forms := RepositoryFormHashes("https://github.com/Acme/Payments")
	if len(forms) != 2 || forms[0] != RepositoryHash("https://github.com/Acme/Payments") || forms[1] != hashHex("github.com/acme/payments") {
		t.Errorf("forms = %v", forms)
	}
	if got := RepositoryFormHashes("https://git.internal.example/Acme/Payments"); len(got) != 1 {
		t.Errorf("a self-hosted host gets no lowercased form: %v", got)
	}
	if RepositoryFormHashes("") != nil && len(RepositoryFormHashes("")) != 0 {
		t.Error("empty input has no forms")
	}
}

func TestProjectIDAndRootHash(t *testing.T) {
	h := ProjectRootHash("/home/a/payments")
	if h != hashHex("/home/a/payments") || ProjectID(h) != h[:16] {
		t.Errorf("root hash %s id %s", h, ProjectID(h))
	}
	if ProjectRootHash("") != "" || ProjectID("abc") != "abc" {
		t.Error("empty/short inputs")
	}
}

// TestLinkRules is one case per row of linkRules, plus precedence and no-match.
func TestLinkRules(t *testing.T) {
	repo := RepositoryHash("https://github.com/acme/api")
	up := RepositoryHash("https://github.com/upstream/api")
	cases := []struct {
		name     string
		svc      ServiceSignals
		projects []ProjectSignals
		want     []Match
	}{
		{
			name:     "project root",
			svc:      ServiceSignals{ProjectIDs: []string{"p1"}},
			projects: []ProjectSignals{{ProjectID: "p1"}, {ProjectID: "p2", RemoteHash: repo}},
			want:     []Match{{"p1", RuleProjectRoot}},
		},
		{
			name:     "project root with no signals row still links",
			svc:      ServiceSignals{ProjectIDs: []string{"p9"}},
			projects: nil,
			want:     []Match{{"p9", RuleProjectRoot}},
		},
		{
			name:     "repository",
			svc:      ServiceSignals{RepositoryHashes: []string{repo}},
			projects: []ProjectSignals{{ProjectID: "p1", RemoteHash: repo}, {ProjectID: "p2", RemoteHash: up}},
			want:     []Match{{"p1", RuleRepository}},
		},
		{
			name:     "upstream",
			svc:      ServiceSignals{RepositoryHashes: []string{up}},
			projects: []ProjectSignals{{ProjectID: "p1", RemoteHash: repo, UpstreamRemoteHash: up}},
			want:     []Match{{"p1", RuleUpstream}},
		},
		{
			name:     "strongest rule wins per project",
			svc:      ServiceSignals{ProjectIDs: []string{"p1"}, RepositoryHashes: []string{repo}},
			projects: []ProjectSignals{{ProjectID: "p1", RemoteHash: repo}, {ProjectID: "p3", RemoteHash: repo}},
			want:     []Match{{"p1", RuleProjectRoot}, {"p3", RuleRepository}},
		},
		{
			name:     "no match",
			svc:      ServiceSignals{RepositoryHashes: []string{repo}},
			projects: []ProjectSignals{{ProjectID: "p1", RemoteHash: up}, {ProjectID: "p2"}},
			want:     []Match{},
		},
		{
			name:     "empty hashes never match",
			svc:      ServiceSignals{RepositoryHashes: []string{""}, ProjectIDs: []string{""}},
			projects: []ProjectSignals{{ProjectID: "p1"}},
			want:     []Match{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Link(c.svc, c.projects); !reflect.DeepEqual(got, c.want) {
				t.Errorf("Link = %v, want %v", got, c.want)
			}
		})
	}
	if !reflect.DeepEqual(RuleNames(), []string{RuleProjectRoot, RuleRepository, RuleUpstream}) {
		t.Errorf("RuleNames = %v", RuleNames())
	}
}

func TestStrongestRule(t *testing.T) {
	if got := StrongestRule(RuleUpstream, RuleRepository); got != RuleRepository {
		t.Errorf("got %q", got)
	}
	if StrongestRule() != "" || StrongestRule("bogus") != "" {
		t.Error("unknown")
	}
}

func TestBuildRunSeries(t *testing.T) {
	days := []string{"2026-11-01", "2026-11-02", "2026-11-03"}
	got := BuildRunSeries(days,
		[]DayCost{{"2026-11-01", 1, 10}, {"2026-11-01", 0.5, 5}, {"2026-10-31", 9, 9}},
		[]DayCost{{"2026-11-03", 2, 20}})
	want := []BuildRunPoint{
		{Date: "2026-11-01", BuildUSD: 1.5, BuildTokens: 15},
		{Date: "2026-11-02"},
		{Date: "2026-11-03", RunUSD: 2, RunTokens: 20},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("series = %+v", got)
	}
}

func TestWindowDays(t *testing.T) {
	s := time.Date(2026, 11, 1, 15, 0, 0, 0, time.UTC)
	u := time.Date(2026, 11, 3, 1, 0, 0, 0, time.UTC)
	if got := WindowDays(s, u, 0); !reflect.DeepEqual(got, []string{"2026-11-01", "2026-11-02", "2026-11-03"}) {
		t.Errorf("days = %v", got)
	}
	if got := WindowDays(s, u, 2); !reflect.DeepEqual(got, []string{"2026-11-02", "2026-11-03"}) {
		t.Errorf("capped = %v", got)
	}
	if WindowDays(u, s, 0) != nil {
		t.Error("reversed window")
	}
}

func TestNewRegressionSpan(t *testing.T) {
	from := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	to := from.Add(48 * time.Hour)
	cases := []struct {
		name     string
		from, to time.Time
		lookback time.Duration
		wantErr  bool
		wantBack time.Duration
	}{
		{"default lookback", from, to, -1, false, DefaultLookback},
		{"zero lookback", from, to, 0, false, 0},
		{"clamped lookback", from, to, 90 * 24 * time.Hour, false, MaxLookback},
		{"reversed", to, from, -1, true, 0},
		{"missing", time.Time{}, to, -1, true, 0},
		{"too long", from, from.Add(40 * 24 * time.Hour), -1, true, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := NewRegressionSpan(c.from, c.to, c.lookback)
			if c.wantErr {
				if !errors.Is(err, ErrRegressionWindow) {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err != nil || r.Lookback != c.wantBack || !r.Since.Equal(c.from.Add(-c.wantBack)) {
				t.Fatalf("span = %+v err %v", r, err)
			}
		})
	}
}

func TestClassify(t *testing.T) {
	from := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	r, err := NewRegressionSpan(from, from.Add(24*time.Hour), 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	h := func(n int) time.Time { return from.Add(time.Duration(n) * time.Hour) }
	cases := []struct {
		name          string
		started, last time.Time
		want          string
	}{
		{"inside the lookback", h(-30), h(-20), WhenBefore},
		{"spans into the regression", h(-30), h(2), WhenDuring},
		{"inside the regression", h(3), h(4), WhenDuring},
		{"instant session", h(-10), time.Time{}, WhenBefore},
		{"too early", h(-100), h(-60), ""},
		{"after", h(30), h(31), ""},
		{"no start", time.Time{}, h(1), ""},
		{"last before start", h(-10), h(-20), WhenBefore},
	}
	for _, c := range cases {
		if got := r.Classify(c.started, c.last); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// TestNormalizeRepositoryFailsClosed: review finding R-C24. An input
// git.NormalizeRemote cannot parse comes back unchanged from it, userinfo and
// all; the stored and shown repository is then empty, while the hash still
// joins.
func TestNormalizeRepositoryFailsClosed(t *testing.T) {
	for raw, want := range map[string]string{
		"https://user:tok@[bad/x":          "",
		"https://%zz":                      "",
		"tok@host":                         "",
		"/home/u/repo":                     "",
		`C:\src\repo`:                      "",
		"ftp://":                           "",
		"https://tok@github.com/a/b.git":   "github.com/a/b",
		"git@github.com:a/b.git":           "github.com/a/b",
		"ssh://git@github.com:22/a/b":      "github.com/a/b",
		" github.com/a/b ":                 "github.com/a/b", //nolint:gocritic // surrounding whitespace is the input under test
		"https://git.example.com:8443/a/b": "git.example.com:8443/a/b",
		"":                                 "",
	} {
		if got := NormalizeRepository(raw); got != want {
			t.Errorf("NormalizeRepository(%q) = %q, want %q", raw, got, want)
		}
	}
	if RepositoryHash("/home/u/repo") == "" {
		t.Fatal("a path-shaped remote still hashes (a node hashes its own remote the same way)")
	}
}
