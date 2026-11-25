package applane

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/reserve"
)

func TestModelAllowed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		patterns []string
		model    string
		want     bool
	}{
		{"exact", []string{"gpt-5-nano"}, "gpt-5-nano", true},
		{"exact case-insensitive", []string{"GPT-5-nano"}, "gpt-5-NANO", true},
		{"prefix glob", []string{"gpt-5*"}, "gpt-5-mini", true},
		{"glob crosses slash", []string{"openai/*"}, "openai/gpt-5-nano", true},
		{"middle glob", []string{"claude-*-5-5"}, "claude-haiku-5-5", true},
		{"middle glob miss", []string{"claude-*-5-5"}, "claude-haiku-4-5", false},
		{"no match", []string{"gpt-5-nano"}, "gpt-5", false},
		{"empty model never matches", []string{"*"}, "", false},
		{"star matches any", []string{"*"}, "anything", true},
		{"empty list", nil, "gpt-5", false},
		{"empty pattern ignored", []string{""}, "gpt-5", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ModelAllowed(tc.patterns, tc.model); got != tc.want {
				t.Fatalf("ModelAllowed(%v, %q) = %v, want %v", tc.patterns, tc.model, got, tc.want)
			}
		})
	}
}

func TestLanePatterns(t *testing.T) {
	t.Parallel()
	m := map[string][]string{"openai": {"gpt-5-nano"}, AllLanesKey: {"claude-*"}}
	if p, ok := LanePatterns(m, "openai"); !ok || len(p) != 1 || p[0] != "gpt-5-nano" {
		t.Fatalf("own entry: %v %v", p, ok)
	}
	if p, ok := LanePatterns(m, "anthropic"); !ok || p[0] != "claude-*" {
		t.Fatalf("fallback entry: %v %v", p, ok)
	}
	if _, ok := LanePatterns(map[string][]string{"openai": {"x"}}, "other"); ok {
		t.Fatal("no entry and no * must mean no list")
	}
}

func TestValidRequestID(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"sdk-0123456789abcdef":        true,
		"req_abc.def:1-2":             true,
		"short":                       false,
		"has space in it ok?":         false,
		"bad\r\nheader-injection-xxx": false,
		"":                            false,
	}
	long := make([]byte, MaxRequestIDLen+1)
	for i := range long {
		long[i] = 'a'
	}
	cases[string(long)] = false
	cases[string(long[:MaxRequestIDLen])] = true
	for id, want := range cases {
		if got := ValidRequestID(id); got != want {
			t.Errorf("ValidRequestID(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestNormalizeService(t *testing.T) {
	t.Parallel()
	long := make([]byte, MaxServiceLen+1)
	for i := range long {
		long[i] = 's'
	}
	cases := []struct{ in, want string }{
		{"\t Support-Bot \n", "Support-Bot"},
		{"", ""},
		{"bad\x01name", ""},
		{string(long), ""},
	}
	for _, tc := range cases {
		if got := NormalizeService(tc.in); got != tc.want {
			t.Errorf("NormalizeService(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestLaneKindsAndURLs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		upstream, kind, client string
	}{
		{"https://api.openai.com", KindOpenAI, "http://127.0.0.1:8820/up/x/v1"},
		{"https://api.anthropic.com", KindAnthropic, "http://127.0.0.1:8820/up/x"},
		{"https://openrouter.ai/api", KindOpenRouter, "http://127.0.0.1:8820/up/x/v1"},
		{"https://generativelanguage.googleapis.com", KindGemini, "http://127.0.0.1:8820/up/x/v1beta"},
		{"http://127.0.0.1:11434", KindOpenAICompatible, "http://127.0.0.1:8820/up/x/v1"},
		{"::not a url", KindOpenAICompatible, "http://127.0.0.1:8820/up/x/v1"},
	}
	for _, tc := range cases {
		k := KindOf(tc.upstream)
		if k != tc.kind {
			t.Errorf("KindOf(%q) = %q, want %q", tc.upstream, k, tc.kind)
		}
		if got := ClientBaseURL(8820, "x", k); got != tc.client {
			t.Errorf("ClientBaseURL(%q) = %q, want %q", tc.kind, got, tc.client)
		}
	}
}

func TestIncludeUsageHost(t *testing.T) {
	t.Parallel()
	for host, want := range map[string]bool{
		"api.openai.com":    true,
		"OpenRouter.ai":     true,
		"api.anthropic.com": false,
		"127.0.0.1":         false,
		"api.together.xyz":  false,
	} {
		if got := IncludeUsageHost(host); got != want {
			t.Errorf("IncludeUsageHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestValidLaneIDAndUpstream(t *testing.T) {
	t.Parallel()
	for id, want := range map[string]bool{"openai": true, "my-app_2": true, "auto": false, "": false, "Up": false, "a/b": false} {
		if got := ValidLaneID(id); got != want {
			t.Errorf("ValidLaneID(%q) = %v, want %v", id, got, want)
		}
	}
	for u, want := range map[string]bool{
		"https://api.openai.com":    true,
		"https://openrouter.ai/api": true,
		"http://127.0.0.1:11434":    true,
		"http://localhost:1234":     true,
		"http://example.com":        false,
		"https://x.test/?k=v":       false,
		"https://user:pw@x.test":    false,
		"ftp://x.test":              false,
		"api.openai.com":            false,
	} {
		if got := ValidUpstream(u); got != want {
			t.Errorf("ValidUpstream(%q) = %v, want %v", u, got, want)
		}
	}
}

func usdCap(name string, limit, recorded float64, since time.Time) Cap {
	return Cap{Group: name, Name: name, Unit: reserve.UnitUSD, Limit: limit, Recorded: recorded, Since: since}
}

func TestLedgerReserveRules(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	since := now.Add(-time.Hour)
	cases := []struct {
		name     string
		req      Request
		admitted bool
		hold     bool
		rule     string
	}{
		{"no caps admits without a hold", Request{WorstUSD: 5, Now: now}, true, false, reserve.RuleWithinCaps},
		{"fits under the cap", Request{Caps: []Cap{usdCap("c", 1, 0.5, since)}, WorstUSD: 0.4, Now: now}, true, true, reserve.RuleWithinCaps},
		{"recorded plus worst case passes the cap", Request{Caps: []Cap{usdCap("c", 1, 0.7, since)}, WorstUSD: 0.4, Now: now}, false, false, reserve.RuleHardBreach},
		{"soft cap warns and holds", Request{Caps: []Cap{{Group: "s", Name: "s", Unit: reserve.UnitUSD, Limit: 1, Recorded: 2, Since: since, Soft: true}}, WorstUSD: 0.1, Now: now}, true, true, reserve.RuleSoftBreachWarned},
		{"unpriced model under a USD cap refuses", Request{Caps: []Cap{usdCap("c", 100, 0, since)}, UnpricedUSD: true, Now: now}, false, false, reserve.RuleUnknownCapped},
		{"observe mode holds a refused call", Request{Caps: []Cap{usdCap("c", 1, 0.9, since)}, WorstUSD: 0.4, Force: true, Now: now}, false, true, reserve.RuleHardBreach},
		{"token cap", Request{Caps: []Cap{{Group: "t", Name: "t", Unit: reserve.UnitTokens, Limit: 1000, Recorded: 900, Since: since}}, WorstTokens: 200, Now: now}, false, false, reserve.RuleHardBreach},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := NewLedger().Reserve(tc.req)
			if d.Admitted != tc.admitted || (d.Hold != nil) != tc.hold || d.Rule != tc.rule {
				t.Fatalf("got admitted=%v hold=%v rule=%q, want %v %v %q", d.Admitted, d.Hold != nil, d.Rule, tc.admitted, tc.hold, tc.rule)
			}
		})
	}
}

func TestLedgerCountsInFlightAndSettles(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	l := NewLedger()
	c := Cap{Group: "u", Name: "u", EndUser: "alice", Unit: reserve.UnitUSD, Limit: 1, Since: now.Add(-time.Hour)}
	r := Request{Caps: []Cap{c}, EndUser: "alice", WorstUSD: 0.4, Now: now}
	a := l.Reserve(r)
	b := l.Reserve(r)
	third := l.Reserve(r)
	if !a.Admitted || !b.Admitted || third.Admitted {
		t.Fatalf("two 0.4 holds fit under 1, the third does not: %v %v %v", a.Admitted, b.Admitted, third.Admitted)
	}
	// Another user's cap is not charged with alice's holds.
	bob := c
	bob.EndUser = "bob"
	if got := l.Held(bob, now); got != 0 {
		t.Fatalf("bob held = %v, want 0", got)
	}
	// Settle one at its actual (recorded elsewhere): counts only for the grace.
	a.Hold.Close(Close{Outcome: reserve.OutcomeSettle, USD: 0.1, RecordedElsewhere: true}, now)
	if got := l.Held(c, now); got < 0.49 || got > 0.51 {
		t.Fatalf("held after settle = %v, want 0.5", got)
	}
	if got := l.Held(c, now.Add(DefaultGrace+time.Second)); got < 0.39 || got > 0.41 {
		t.Fatalf("held after grace = %v, want 0.4 (only the open hold)", got)
	}
	// Unknown usage stays at the worst case past the grace.
	b.Hold.Close(Close{Outcome: reserve.OutcomeReconcile, RecordedElsewhere: true}, now)
	if got := l.Held(c, now.Add(DefaultGrace+time.Second)); got < 0.39 || got > 0.41 {
		t.Fatalf("held after reconcile = %v, want 0.4 (worst case kept)", got)
	}
	// A second close is a no-op.
	b.Hold.Close(Close{Outcome: reserve.OutcomeRelease}, now)
	if got := l.Held(c, now.Add(DefaultGrace+time.Second)); got < 0.39 || got > 0.41 {
		t.Fatalf("second close changed the books: %v", got)
	}
	if l.Open() != 0 {
		t.Fatalf("open = %d, want 0", l.Open())
	}
}

func TestLedgerReleaseRefunds(t *testing.T) {
	t.Parallel()
	now := time.Now()
	l := NewLedger()
	c := usdCap("c", 1, 0, now.Add(-time.Hour))
	d := l.Reserve(Request{Caps: []Cap{c}, WorstUSD: 0.9, Now: now})
	d.Hold.Close(Close{Outcome: reserve.OutcomeRelease}, now)
	if got := l.Held(c, now); got != 0 {
		t.Fatalf("released hold still counted: %v", got)
	}
}

// TestLedgerConcurrentReservationHolds is the plan's "the in-memory
// reservation holds under 20 concurrent calls": 20 calls of 0.1 against a
// cap of 1.0 admit exactly 10.
func TestLedgerConcurrentReservationHolds(t *testing.T) {
	t.Parallel()
	now := time.Now()
	l := NewLedger()
	c := usdCap("c", 1.0, 0, now.Add(-time.Hour))
	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted := 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := l.Reserve(Request{Caps: []Cap{c}, WorstUSD: 0.1, Now: now})
			if d.Admitted {
				mu.Lock()
				admitted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if admitted != 10 {
		t.Fatalf("admitted %d of 20, want 10", admitted)
	}
}

func TestLedgerBoundKeepsOpenHolds(t *testing.T) {
	t.Parallel()
	now := time.Now()
	l := NewLedger()
	l.maxEntries = 3
	c := usdCap("c", 100, 0, now.Add(-time.Hour))
	var holds []*Hold
	for i := 0; i < 5; i++ {
		holds = append(holds, l.Reserve(Request{Caps: []Cap{c}, WorstUSD: 1, Now: now}).Hold)
	}
	if l.Open() != 5 {
		t.Fatalf("open holds dropped by the bound: %d", l.Open())
	}
	for _, h := range holds[:4] {
		h.Close(Close{Outcome: reserve.OutcomeSettle, USD: 1}, now)
	}
	l.Reserve(Request{Caps: []Cap{c}, WorstUSD: 1, Now: now})
	if len(l.entries) > 3 {
		t.Fatalf("bound not applied: %d entries", len(l.entries))
	}
	if l.Open() != 2 {
		t.Fatalf("open = %d, want 2", l.Open())
	}
}

func TestListAndDefaults(t *testing.T) {
	t.Parallel()
	got := List(map[string]string{"openai": "https://api.openai.com", "anthropic": "https://api.anthropic.com"},
		map[string][]string{"openai": {"gpt-5-nano"}, AllLanesKey: {"claude-*"}}, 8820)
	if len(got) != 2 || got[0].ID != "anthropic" || got[1].ID != "openai" {
		t.Fatalf("order = %+v", got)
	}
	if got[0].ClientBaseURL != "http://127.0.0.1:8820/up/anthropic" || got[0].ModelsFrom != AllLanesKey {
		t.Fatalf("anthropic = %+v", got[0])
	}
	if got[1].ClientBaseURL != "http://127.0.0.1:8820/up/openai/v1" || got[1].ModelsFrom != "lane" || got[1].Models[0] != "gpt-5-nano" {
		t.Fatalf("openai = %+v", got[1])
	}
	if u, ok := DefaultUpstream("openrouter"); !ok || u != "https://openrouter.ai/api" {
		t.Fatalf("DefaultUpstream(openrouter) = %q %v", u, ok)
	}
	if _, ok := DefaultUpstream("mine"); ok {
		t.Fatal("an unknown id has no default")
	}
	if l := List(nil, nil, 8820); l == nil || len(l) != 0 {
		t.Fatalf("empty table = %#v, want an empty non-nil list", l)
	}
}

func TestValidateApplyRemove(t *testing.T) {
	t.Parallel()
	if _, err := ValidateAdd("Bad", "", nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad id: %v", err)
	}
	if _, err := ValidateAdd("mine", "", nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no default upstream: %v", err)
	}
	if _, err := ValidateAdd("mine", "http://example.com", nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("plain http off loopback: %v", err)
	}
	if _, err := ValidateAdd("openai", "", []string{"a b"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("spaced model: %v", err)
	}
	a, err := ValidateAdd(" openai ", "", []string{" gpt-5-nano ", ""})
	if err != nil || a.ID != "openai" || a.Upstream != "https://api.openai.com" || len(a.Models) != 1 || a.Models[0] != "gpt-5-nano" {
		t.Fatalf("add = %+v %v", a, err)
	}
	ups := map[string]string{}
	var models map[string][]string
	if err := a.Apply(ups, map[string]string{"opencode-zen": "x"}, &models); err != nil || ups["openai"] == "" || models["openai"][0] != "gpt-5-nano" {
		t.Fatalf("apply: %v %v %v", err, ups, models)
	}
	if err := a.Apply(ups, nil, &models); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate: %v", err)
	}
	agent, _ := ValidateAdd("opencode-zen", "https://opencode.ai/zen", nil)
	if err := agent.Apply(ups, map[string]string{"opencode-zen": "x"}, &models); !errors.Is(err, ErrAgentLane) {
		t.Fatalf("agent id: %v", err)
	}
	if err := Remove("openai", ups, "openai", models); !errors.Is(err, ErrAutoDefault) {
		t.Fatalf("auto default: %v", err)
	}
	if err := Remove("openai", ups, "", models); err != nil || len(ups) != 0 || len(models) != 0 {
		t.Fatalf("remove: %v %v %v", err, ups, models)
	}
	if err := Remove("openai", ups, "", models); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
}

// TestCapSpendSource: where the lanes' app caps count spend from, by
// [observability] enabled (hosted AI gateway review L5).
func TestCapSpendSource(t *testing.T) {
	if got := CapSpendSource(true); got != CapSpendRecorded {
		t.Errorf("observability on = %q", got)
	}
	if got := CapSpendSource(false); got != CapSpendProcess {
		t.Errorf("observability off = %q", got)
	}
}
