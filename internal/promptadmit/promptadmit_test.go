package promptadmit

import (
	"strconv"
	"strings"
	"testing"
	"time"

	policyfamadmission "github.com/marmutapp/superbased-observer/internal/policyfam/admission"
	"github.com/marmutapp/superbased-observer/internal/promptturn"
)

func TestParseScope(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		want    Scope
		wantErr bool
	}{
		{"", ScopeUserPrompts, false},
		{"user_prompts", ScopeUserPrompts, false},
		{"all_calls", ScopeAllCalls, false},
		{"everything", "", true},
		{"USER_PROMPTS", "", true},
	}
	for _, tc := range tests {
		got, err := ParseScope(tc.in)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("ParseScope(%q) = %q, %v; want %q, err=%v", tc.in, got, err, tc.want, tc.wantErr)
		}
	}
}

// TestPlanTurn is one row per scope x kind (plus the blank-text rows).
func TestPlanTurn(t *testing.T) {
	t.Parallel()
	prompt := promptturn.Turn{Kind: promptturn.KindUserPrompt, Text: "do it", Trailing: "do it"}
	loop := promptturn.Turn{Kind: promptturn.KindContinuation, Trailing: "tool output", Opening: "do it"}
	bareLoop := promptturn.Turn{Kind: promptturn.KindContinuation, Trailing: "tool output"}
	tests := []struct {
		name  string
		scope Scope
		turn  promptturn.Turn
		want  Plan
	}{
		{"user_prompts judges a prompt", ScopeUserPrompts, prompt, Plan{Judge: true, Text: "do it"}},
		{"user_prompts judges a continuation's opening prompt (cache reuse on a real loop)", ScopeUserPrompts, loop, Plan{Judge: true, Text: "do it", Continuation: true}},
		{"user_prompts skips a loop with no typed prompt", ScopeUserPrompts, bareLoop, Plan{Skip: SkipContinuation}},
		{"user_prompts skips an image-only prompt", ScopeUserPrompts, promptturn.Turn{Kind: promptturn.KindUserPrompt}, Plan{Skip: SkipEmptyText}},
		{"user_prompts skips a whitespace-only prompt", ScopeUserPrompts, promptturn.Turn{Kind: promptturn.KindUserPrompt, Text: " \n\t "}, Plan{Skip: SkipEmptyText}},
		{"user_prompts skips no user turn", ScopeUserPrompts, promptturn.Turn{Kind: promptturn.KindNone}, Plan{Skip: SkipNoUserTurn}},
		{"all_calls judges a prompt's trailing segment", ScopeAllCalls, prompt, Plan{Judge: true, Text: "do it"}},
		{"all_calls judges a continuation's tool results", ScopeAllCalls, loop, Plan{Judge: true, Text: "tool output", Continuation: true}},
		{"all_calls judges a tool-output-only request", ScopeAllCalls, bareLoop, Plan{Judge: true, Text: "tool output", Continuation: true}},
		{"all_calls skips an empty trailing segment", ScopeAllCalls, promptturn.Turn{Kind: promptturn.KindContinuation}, Plan{Skip: SkipEmptyText}},
		{"all_calls skips a whitespace-only trailing segment", ScopeAllCalls, promptturn.Turn{Kind: promptturn.KindContinuation, Trailing: "  "}, Plan{Skip: SkipEmptyText}},
		{"all_calls skips no user turn", ScopeAllCalls, promptturn.Turn{Kind: promptturn.KindNone, Trailing: "x"}, Plan{Skip: SkipNoUserTurn}},
	}
	for _, tc := range tests {
		if got := PlanTurn(tc.scope, tc.turn); got != tc.want {
			t.Errorf("%s: PlanTurn = %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// TestDecide is one row per mode x strict x verdict x judge-availability.
func TestDecide(t *testing.T) {
	t.Parallel()
	const (
		allow = policyfamadmission.DecisionAllow
		flag  = policyfamadmission.DecisionFlag
		ask   = policyfamadmission.DecisionAsk
		deny  = policyfamadmission.DecisionDeny
	)
	tests := []struct {
		name       string
		enforce    bool
		strict     bool
		r          EngineResult
		wantAction Action
		wantBasis  Basis
		wantCrit   string
	}{
		{"enforce allow", true, false, EngineResult{Decision: allow}, ActionAllow, BasisAllow, ""},
		{"observe allow", false, false, EngineResult{Decision: allow}, ActionAllow, BasisAllow, ""},
		{"enforce flag", true, false, EngineResult{Decision: flag, Criterion: "c1", Reason: "r"}, ActionFlag, BasisFlag, "c1"},
		{"observe flag", false, false, EngineResult{Decision: flag, Reason: "r"}, ActionFlag, BasisFlag, "flag"},
		{"enforce ask refuses", true, false, EngineResult{Decision: ask, Criterion: "c2", Reason: "r"}, ActionBlock, BasisAsk, "c2"},
		{"observe ask flags", false, false, EngineResult{Decision: ask, Reason: "r"}, ActionFlag, BasisAsk, "ask"},
		{"enforce deny refuses", true, false, EngineResult{Decision: deny, Criterion: "c3", Reason: "r"}, ActionBlock, BasisDeny, "c3"},
		{"observe deny flags", false, false, EngineResult{Decision: deny, Reason: "r"}, ActionFlag, BasisDeny, "deny"},
		{"enforce strict judge failure refuses", true, true, EngineResult{Decision: deny, Reason: "t/o", JudgeUnavailable: true}, ActionBlock, BasisJudgeUnavailable, "judge_unavailable"},
		{"enforce strict judge failure refuses even if the engine left allow", true, true, EngineResult{Decision: allow, Reason: "t/o", JudgeUnavailable: true}, ActionBlock, BasisJudgeUnavailable, "judge_unavailable"},
		{"enforce non-strict judge failure flags", true, false, EngineResult{Decision: allow, Reason: "t/o", JudgeUnavailable: true}, ActionFlag, BasisJudgeUnavailable, "judge_unavailable"},
		{"observe strict judge failure flags", false, true, EngineResult{Decision: deny, Reason: "t/o", JudgeUnavailable: true}, ActionFlag, BasisJudgeUnavailable, "judge_unavailable"},
		{"observe non-strict judge failure flags", false, false, EngineResult{Decision: allow, JudgeUnavailable: true}, ActionFlag, BasisJudgeUnavailable, "judge_unavailable"},
		// F6: a real deny that rides a degraded judge on a NON-strict policy
		// is a deny, never "judge unavailable (strict)".
		{"enforce non-strict real deny with an unavailable judge is a deny", true, false, EngineResult{Decision: deny, Criterion: "prefilter.deny", Reason: "denied phrase", JudgeUnavailable: true}, ActionBlock, BasisDeny, "prefilter.deny"},
		{"enforce non-strict real ask with an unavailable judge is an ask", true, false, EngineResult{Decision: ask, Criterion: "c4", Reason: "r", JudgeUnavailable: true}, ActionBlock, BasisAsk, "c4"},
		// N4 (fix round 2): the secret gate withheld the prompt from the judge.
		{"enforce strict secret withheld refuses", true, true, EngineResult{Decision: flag, Criterion: "secret.remote_judge", Reason: "secret", SecretWithheld: true}, ActionBlock, BasisSecretGate, "secret_gate"},
		{"enforce non-strict secret withheld flags", true, false, EngineResult{Decision: flag, Criterion: "secret.remote_judge", Reason: "secret", SecretWithheld: true}, ActionFlag, BasisFlag, "secret.remote_judge"},
		{"observe strict secret withheld flags", false, true, EngineResult{Decision: flag, Criterion: "secret.remote_judge", Reason: "secret", SecretWithheld: true}, ActionFlag, BasisFlag, "secret.remote_judge"},
		{"enforce strict secret withheld under an org deny stays a deny", true, true, EngineResult{Decision: deny, Criterion: "secret.remote_judge", Reason: "secret", SecretWithheld: true}, ActionBlock, BasisDeny, "secret.remote_judge"},
	}
	for _, tc := range tests {
		got := Decide(tc.enforce, tc.strict, tc.r)
		if got.Action != tc.wantAction || got.Basis != tc.wantBasis || got.Criterion != tc.wantCrit {
			t.Errorf("%s: Decide = %+v, want action=%s basis=%s criterion=%q", tc.name, got, tc.wantAction, tc.wantBasis, tc.wantCrit)
		}
		if got.Allowed() != (tc.wantAction != ActionBlock) {
			t.Errorf("%s: Allowed() disagrees with action", tc.name)
		}
		if tc.wantAction != ActionAllow && got.Reason == "" {
			t.Errorf("%s: a non-allow outcome must carry a reason", tc.name)
		}
		if tc.wantBasis != BasisJudgeUnavailable && strings.Contains(got.Reason, "judge unavailable") {
			t.Errorf("%s: reason %q mislabels a real verdict", tc.name, got.Reason)
		}
	}
}

// TestCacheMarkAudited pins F6: a cached verdict is audited once per entry
// life; a changed outcome or an expiry starts a new life.
func TestCacheMarkAudited(t *testing.T) {
	t.Parallel()
	now := time.Unix(1000, 0)
	c := NewCache(time.Minute, 8, func() time.Time { return now })
	deny := Outcome{Action: ActionBlock, Basis: BasisDeny, Reason: "r"}
	k := CacheKey("v1", ScopeUserPrompts, Digest("a"))
	if c.MarkAudited(k) {
		t.Fatal("an absent entry must not be audited")
	}
	c.Put(k, deny)
	if !c.MarkAudited(k) || c.MarkAudited(k) || c.MarkAudited(k) {
		t.Fatal("want exactly one audit per entry life")
	}
	c.Put(k, deny)
	if c.MarkAudited(k) {
		t.Fatal("re-putting the same outcome must not re-audit")
	}
	c.Put(k, Outcome{Action: ActionFlag, Basis: BasisFlag, Reason: "r"})
	if !c.MarkAudited(k) {
		t.Fatal("a changed outcome starts a new life")
	}
	now = now.Add(2 * time.Minute)
	if c.MarkAudited(k) {
		t.Fatal("an expired entry must not be audited")
	}
	var nilCache *Cache
	if nilCache.MarkAudited(k) {
		t.Fatal("nil cache must be inert")
	}
}

func TestCache(t *testing.T) {
	t.Parallel()
	now := time.Unix(1000, 0)
	c := NewCache(time.Minute, 2, func() time.Time { return now })
	deny := Outcome{Action: ActionBlock, Basis: BasisDeny, Reason: "r"}
	k1 := CacheKey("v1", ScopeUserPrompts, Digest("a"))
	c.Put(k1, deny)
	if got, ok := c.Get(k1); !ok || got != deny {
		t.Fatalf("Get after Put = %+v, %v", got, ok)
	}
	if _, ok := c.Get(CacheKey("v2", ScopeUserPrompts, Digest("a"))); ok {
		t.Fatal("a new policy version must not reuse an older verdict")
	}
	if _, ok := c.Get(CacheKey("v1", ScopeAllCalls, Digest("a"))); ok {
		t.Fatal("a different scope must not reuse the verdict")
	}
	// LRU bound: k1 was touched last by Get, so b then c evicts b.
	c.Put(CacheKey("v1", ScopeUserPrompts, Digest("b")), deny)
	_, _ = c.Get(k1)
	c.Put(CacheKey("v1", ScopeUserPrompts, Digest("c")), deny)
	if _, ok := c.Get(CacheKey("v1", ScopeUserPrompts, Digest("b"))); ok {
		t.Fatal("least recently used entry should have been evicted")
	}
	if _, ok := c.Get(k1); !ok {
		t.Fatal("recently used entry evicted")
	}
	now = now.Add(2 * time.Minute)
	if _, ok := c.Get(k1); ok {
		t.Fatal("expired entry returned")
	}
	var nilCache *Cache
	nilCache.Put("k", deny)
	if _, ok := nilCache.Get("k"); ok || nilCache.Len() != 0 {
		t.Fatal("nil cache must be inert")
	}
}

func TestCacheConcurrent(t *testing.T) {
	t.Parallel()
	c := NewCache(0, 64, nil)
	done := make(chan struct{})
	for g := 0; g < 8; g++ {
		go func(g int) {
			defer func() { done <- struct{}{} }()
			for i := 0; i < 500; i++ {
				k := CacheKey("v", ScopeUserPrompts, strconv.Itoa((g*7+i)%100))
				c.Put(k, Outcome{Action: ActionAllow, Basis: BasisAllow})
				_, _ = c.Get(k)
			}
		}(g)
	}
	for g := 0; g < 8; g++ {
		<-done
	}
	if c.Len() > 64 {
		t.Fatalf("cache exceeded its bound: %d", c.Len())
	}
}

// TestEngineMissing pins F7: no engine is never a silent admit.
func TestEngineMissing(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		enforce, strict bool
		want            Action
	}{
		{"enforce strict refuses", true, true, ActionBlock},
		{"enforce non-strict flags", true, false, ActionFlag},
		{"observe strict flags", false, true, ActionFlag},
		{"observe flags", false, false, ActionFlag},
	}
	for _, tc := range tests {
		o := EngineMissing(tc.enforce, tc.strict)
		if o.Action != tc.want || o.Basis != BasisEngineMissing || o.Reason == "" {
			t.Errorf("%s: %+v, want %s", tc.name, o, tc.want)
		}
	}
}

// TestCacheNegativeWindow pins N1 (fix round 2): a judge-unavailable outcome
// is reused for DefaultNegativeTTL only, audited once in that window, and
// never refreshed.
func TestCacheNegativeWindow(t *testing.T) {
	t.Parallel()
	now := time.Unix(1000, 0)
	c := NewCache(0, 0, func() time.Time { return now })
	k := CacheKey("v1", ScopeUserPrompts, Digest("down"))
	neg := Outcome{Action: ActionFlag, Basis: BasisJudgeUnavailable, Reason: "judge unavailable, not enforced: timeout"}
	c.Put(k, neg)
	if got, ok := c.Get(k); !ok || got != neg {
		t.Fatalf("negative outcome not reused: %+v %v", got, ok)
	}
	if !c.MarkAudited(k) || c.MarkAudited(k) {
		t.Fatal("want one audit row per negative window")
	}
	if c.Refresh(k) {
		t.Fatal("a judge-unavailable entry must never be refreshed")
	}
	now = now.Add(DefaultNegativeTTL - time.Second)
	if _, ok := c.Get(k); !ok {
		t.Fatal("negative entry expired early")
	}
	now = now.Add(2 * time.Second)
	if _, ok := c.Get(k); ok {
		t.Fatal("negative entry outlived DefaultNegativeTTL")
	}
	c.Put(k, neg)
	if !c.MarkAudited(k) {
		t.Fatal("a new negative window must be audited again")
	}
}

// TestCacheRefreshKeepsALoopVerdict pins N1 (fix round 2): a verdict
// refreshed while its loop is in use outlives the TTL, but never its maximum
// age.
func TestCacheRefreshKeepsALoopVerdict(t *testing.T) {
	t.Parallel()
	now := time.Unix(1000, 0)
	c := NewCache(0, 0, func() time.Time { return now })
	k := CacheKey("v1", ScopeUserPrompts, Digest("opening"))
	allow := Outcome{Action: ActionAllow, Basis: BasisAllow}
	if c.Refresh(k) {
		t.Fatal("refreshing an absent entry must report false")
	}
	c.Put(k, allow)
	for elapsed := time.Duration(0); elapsed < DefaultMaxAge-DefaultCacheTTL; elapsed += DefaultCacheTTL / 2 {
		now = now.Add(DefaultCacheTTL / 2)
		if _, ok := c.Get(k); !ok {
			t.Fatalf("verdict expired at %v despite refreshes", elapsed)
		}
		c.Refresh(k)
	}
	now = time.Unix(1000, 0).Add(DefaultMaxAge + time.Second)
	if _, ok := c.Get(k); ok {
		t.Fatal("refresh kept a verdict past DefaultMaxAge")
	}
}
