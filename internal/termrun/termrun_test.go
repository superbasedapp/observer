package termrun

import (
	"testing"
	"time"
)

func TestKindValid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		k    Kind
		want bool
	}{
		{KindHandoff, true},
		{KindFresh, true},
		{KindAttach, true},
		{KindResume, true},
		{KindSSH, true},
		{Kind(""), false},
		{Kind("shell"), false},
	}
	for _, tc := range cases {
		if got := tc.k.Valid(); got != tc.want {
			t.Errorf("Kind(%q).Valid() = %v, want %v", tc.k, got, tc.want)
		}
	}
}

func TestSourceValid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		s    Source
		want bool
	}{
		{SourceOOB, true},
		{SourceDiscovered, true},
		{SourceMarker, true},
		{SourceHeuristic, true},
		{Source(""), false},
		{Source("guess"), false},
	}
	for _, tc := range cases {
		if got := tc.s.Valid(); got != tc.want {
			t.Errorf("Source(%q).Valid() = %v, want %v", tc.s, got, tc.want)
		}
	}
}

func TestScore(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	later := at.Add(time.Minute)
	cases := []struct {
		name       string
		obs        []Observation
		wantOK     bool
		wantConf   float64
		wantSource Source
		wantAt     time.Time
	}{
		{"empty", nil, false, 0, "", time.Time{}},
		{"only invalid", []Observation{{Source: "bogus", At: at}}, false, 0, "", time.Time{}},
		{"single oob", []Observation{{Source: SourceOOB, At: at}}, true, 0.95, SourceOOB, at},
		{"single heuristic", []Observation{{Source: SourceHeuristic, At: at}}, true, 0.40, SourceHeuristic, at},
		{
			"strongest wins (oob over heuristic, order-independent)",
			[]Observation{{Source: SourceHeuristic, At: at}, {Source: SourceOOB, At: later}},
			true, 0.95, SourceOOB, later,
		},
		{
			"marker over heuristic",
			[]Observation{{Source: SourceMarker, At: at}, {Source: SourceHeuristic, At: later}},
			true, 0.70, SourceMarker, at,
		},
		{
			"invalid ignored, valid kept",
			[]Observation{{Source: "bogus", At: later}, {Source: SourceMarker, At: at}},
			true, 0.70, SourceMarker, at,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Score("run-1", "sess-1", tc.obs)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if got.RunID != "run-1" || got.SessionID != "sess-1" {
				t.Errorf("ids = (%q,%q), want (run-1,sess-1)", got.RunID, got.SessionID)
			}
			if got.Confidence != tc.wantConf {
				t.Errorf("confidence = %v, want %v", got.Confidence, tc.wantConf)
			}
			if got.Source != tc.wantSource {
				t.Errorf("source = %q, want %q", got.Source, tc.wantSource)
			}
			if !got.ObservedAt.Equal(tc.wantAt) {
				t.Errorf("observedAt = %v, want %v", got.ObservedAt, tc.wantAt)
			}
		})
	}
}

func TestCorrelationLinkable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		conf float64
		want bool
	}{
		{0.95, true},
		{0.70, true},
		{MinLinkConfidence, true},
		{0.49, false},
		{0.40, false},
		{0, false},
	}
	for _, tc := range cases {
		c := Correlation{Confidence: tc.conf}
		if got := c.Linkable(); got != tc.want {
			t.Errorf("Correlation{Confidence:%v}.Linkable() = %v, want %v", tc.conf, got, tc.want)
		}
	}
}

// The source→confidence ordering must be strict so "strongest wins" is
// well-defined: oob > discovered > marker > heuristic. SourceDiscovered sits
// between the known-id OOB echo and a transcript marker, and must stay above the
// link threshold so a discovered id still attaches downstream links.
func TestConfidenceOrdering(t *testing.T) {
	t.Parallel()
	oob := confidenceFor(SourceOOB)
	discovered := confidenceFor(SourceDiscovered)
	marker := confidenceFor(SourceMarker)
	heur := confidenceFor(SourceHeuristic)
	if !(oob > discovered && discovered > marker && marker > heur) {
		t.Fatalf("expected oob(%v) > discovered(%v) > marker(%v) > heuristic(%v)", oob, discovered, marker, heur)
	}
	if confidenceFor(Source("bogus")) != 0 {
		t.Errorf("unknown source must score 0")
	}
	// The OOB source must clear the link threshold; heuristic alone must not.
	if oob < MinLinkConfidence {
		t.Errorf("oob confidence %v must be linkable", oob)
	}
	// A DISCOVERED id, though weaker than a known-id echo, must still link (it is
	// a trusted-channel echo, just of an inferred id) — else the codex discovery
	// path would surface nothing.
	if discovered < MinLinkConfidence {
		t.Errorf("discovered confidence %v must be linkable", discovered)
	}
	if heur >= MinLinkConfidence {
		t.Errorf("heuristic confidence %v must NOT be linkable on its own", heur)
	}
}

func TestNewRunIDAndCorrelationTokenUnique(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id, err := NewRunID()
		if err != nil {
			t.Fatalf("NewRunID: %v", err)
		}
		if len(id) != 43 {
			t.Errorf("run id length = %d, want 43 (base64url of 32 bytes)", len(id))
		}
		if seen[id] {
			t.Fatalf("duplicate run id %q", id)
		}
		seen[id] = true

		tok, err := NewCorrelationToken()
		if err != nil {
			t.Fatalf("NewCorrelationToken: %v", err)
		}
		if seen[tok] {
			t.Fatalf("correlation nonce collided with an id: %q", tok)
		}
		seen[tok] = true
	}
}

func TestHashDomainSeparation(t *testing.T) {
	t.Parallel()
	// Empty inputs hash to "".
	if HashProjectRoot("") != "" || HashCorrelationToken("") != "" {
		t.Fatal("empty input must hash to empty string")
	}
	// Deterministic.
	first := HashProjectRoot("/home/x/proj")
	second := HashProjectRoot("/home/x/proj")
	if first != second {
		t.Fatal("HashProjectRoot not deterministic")
	}
	// Hex-encoded SHA-256 → 64 chars.
	if got := len(HashProjectRoot("/x")); got != 64 {
		t.Errorf("hash length = %d, want 64", got)
	}
	// Domain separation: the SAME raw value hashes differently in the two
	// domains, so a project-root hash can never be linked to a nonce hash.
	const same = "collision-probe"
	if HashProjectRoot(same) == HashCorrelationToken(same) {
		t.Fatal("project-root and correlation-nonce hashes must be domain-separated")
	}
}

// TestRemoteSensitiveKinds pins WHICH run kinds a remote-exposed dashboard
// hides when [remote].allow_terminal_view is off. KindSSH is in the gated set
// (docs/plans/ssh-remote-profiles-plan-2026-08-27.md §5): a live shell on
// another machine is at least as likely to echo secrets as an attach/resume
// TUI. A fresh/handoff launch is the honest non-sensitive floor.
func TestRemoteSensitiveKinds(t *testing.T) {
	t.Parallel()
	cases := []struct {
		k    Kind
		want bool
	}{
		{KindAttach, true},
		{KindResume, true},
		{KindSSH, true},
		{KindFresh, false},
		{KindHandoff, false},
		{Kind("unknown"), false},
	}
	for _, tc := range cases {
		if got := IsRemoteSensitiveKind(tc.k); got != tc.want {
			t.Errorf("IsRemoteSensitiveKind(%q) = %v, want %v", tc.k, got, tc.want)
		}
	}
}
