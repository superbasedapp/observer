package secfeed

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestServiceAnswer(t *testing.T) {
	now := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	var looked [][]InstallSpec
	enabled := false
	var saved, files int
	s := NewService(ServiceOptions{
		Classify: func(Scope) Classifier {
			return NewClassifier(PrivConfig{NpmScopeRegistries: map[string]string{"@corp": "https://npm.corp.example/"}})
		},
		Lookup: func(_ context.Context, specs []InstallSpec) []OnlineAnswer {
			looked = append(looked, specs)
			var out []OnlineAnswer
			for _, sp := range specs {
				out = append(out, OnlineAnswer{Eco: sp.Eco, Name: Normalize(sp.Eco, sp.Name), Version: sp.Version, Status: OnlineAnswered})
			}
			return out
		},
		Enabled:   func() bool { return enabled },
		Save:      func(_ context.Context, es []CacheEntry) { saved += len(es) },
		WriteFile: func([]byte) error { files++; return nil },
		Now:       func() time.Time { return now },
	})
	specs := []InstallSpec{ParseSpec(EcoNpm, "left-pad"), ParseSpec(EcoNpm, "@corp/ui"), ParseSpec(EcoNpm, "./x")}
	got := s.Answer(context.Background(), Scope{ProjectRoot: "/r"}, specs)
	if len(looked) != 0 || got[0].Status != OnlineNotAsked || got[0].Private || !got[1].Private || got[2].Private {
		t.Fatalf("before the disclosure nothing is looked up: %+v %d", got, len(looked))
	}
	enabled = true
	got = s.Answer(context.Background(), Scope{ProjectRoot: "/r"}, specs)
	if len(looked) != 1 || len(looked[0]) != 1 || looked[0][0].Name != "left-pad" || got[0].Status != OnlineAnswered {
		t.Fatalf("only the public name is looked up: %+v %+v", looked, got)
	}
	if saved != 1 || files != 1 || s.CacheLen() != 1 {
		t.Errorf("cache saved=%d files=%d len=%d", saved, files, s.CacheLen())
	}
	_ = s.Answer(context.Background(), Scope{ProjectRoot: "/r"}, specs[:1])
	if len(looked) != 1 {
		t.Error("a cached answer is not looked up again")
	}
	now = now.Add(25 * time.Hour)
	_ = s.Answer(context.Background(), Scope{ProjectRoot: "/r"}, specs[:1])
	if len(looked) != 2 {
		t.Error("an expired answer is looked up again")
	}
}

func TestDisclosureRecord(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 3
	if (Disclosure{}).Shown() || DecodeDisclosure([]byte("junk"), key).Shown() {
		t.Error("an empty or unreadable record is not shown")
	}
	if _, err := EncodeDisclosure(Disclosure{Version: DisclosureVersion, ShownAt: time.Now(), Surface: "dashboard"}, nil); err == nil {
		t.Error("a record with no signing key was encoded")
	}
	b, err := EncodeDisclosure(Disclosure{Version: DisclosureVersion, ShownAt: time.Now(), Surface: "dashboard"}, key)
	if err != nil || !DecodeDisclosure(b, key).Shown() {
		t.Errorf("round trip: %v", err)
	}
	other := make([]byte, 32)
	if DecodeDisclosure(b, other).Shown() || DecodeDisclosure(b, nil).Shown() {
		t.Error("a record reads shown under another key or none")
	}
	// Lane sec-deps4 audit finding 1: a hand-written record (the shape an
	// older plan-branch build wrote, with no MAC) or one changed after
	// signing is not the developer's consent.
	for name, body := range map[string]string{
		"older text version":    `{"version":0,"shown_at":"2026-01-01T00:00:00Z","surface":"cli"}`,
		"hand-written, no MAC":  `{"version":2,"shown_at":"2026-10-01T00:00:00Z","surface":"cli"}`,
		"forged MAC":            `{"version":2,"shown_at":"2026-10-01T00:00:00Z","surface":"cli","mac":"` + strings.Repeat("ab", 32) + `"}`,
		"verified in the file":  `{"version":2,"shown_at":"2026-10-01T00:00:00Z","surface":"cli","Verified":true}`,
		"changed after signing": strings.Replace(string(b), `"dashboard"`, `"cli"`, 1),
	} {
		if DecodeDisclosure([]byte(body), key).Shown() {
			t.Errorf("%s reads shown", name)
		}
	}
}

// TestServiceAnswerCommandPrivate: Service.Answer honours a spec the
// command made private (X4) even when its classifier calls the name
// public.
func TestServiceAnswerCommandPrivate(t *testing.T) {
	looked := 0
	s := NewService(ServiceOptions{
		Classify: func(Scope) Classifier { return func(InstallSpec) bool { return true } },
		Lookup:   func(context.Context, []InstallSpec) []OnlineAnswer { looked++; return nil },
		Enabled:  func() bool { return true },
	})
	sp := ParseSpec(EcoPyPI, "internal-pkg")
	sp.Private = true
	got := s.Answer(context.Background(), Scope{ProjectRoot: "/r"}, []InstallSpec{sp})
	if looked != 0 || !got[0].Private || got[0].Status != OnlineNotAsked {
		t.Errorf("looked %d, %+v", looked, got)
	}
}

// TestServiceDetachedLookup is milestone 2e: a lookup that outlives the
// ask's budget goes on and is cached, so the next install of the same name
// is answered at once; concurrent asks share one lookup; a failure is
// cached briefly.
func TestServiceDetachedLookup(t *testing.T) {
	release := make(chan struct{})
	var calls int
	var mu sync.Mutex
	s := NewService(ServiceOptions{
		Classify: func(Scope) Classifier { return func(InstallSpec) bool { return true } },
		Lookup: func(_ context.Context, specs []InstallSpec) []OnlineAnswer {
			mu.Lock()
			calls++
			mu.Unlock()
			<-release
			var out []OnlineAnswer
			for _, sp := range specs {
				st := OnlineAnswered
				if sp.Name == "flaky" {
					return append(out, OnlineAnswer{Eco: sp.Eco, Name: sp.Name, Status: OnlineFailed, Reason: "timeout"})
				}
				out = append(out, OnlineAnswer{Eco: sp.Eco, Name: Normalize(sp.Eco, sp.Name), Status: st})
			}
			return out
		},
		Enabled: func() bool { return true },
	})
	specs := []InstallSpec{ParseSpec(EcoNpm, "slow-pkg")}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	got := s.Answer(ctx, Scope{ProjectRoot: "/r"}, specs)
	cancel()
	if got[0].Status != OnlineFailed || got[0].Reason != ReasonInFlight {
		t.Fatalf("over budget: %+v", got[0])
	}
	// A second ask while the first lookup runs joins it.
	done := make(chan []OnlineAnswer)
	go func() { done <- s.Answer(context.Background(), Scope{ProjectRoot: "/r"}, specs) }()
	time.Sleep(20 * time.Millisecond)
	close(release)
	got = <-done
	if got[0].Status != OnlineAnswered {
		t.Fatalf("joined: %+v", got[0])
	}
	got = s.Answer(context.Background(), Scope{ProjectRoot: "/r"}, specs)
	mu.Lock()
	n := calls
	mu.Unlock()
	if got[0].Status != OnlineAnswered || n != 1 {
		t.Errorf("cached after landing: %+v, %d lookups", got[0], n)
	}
	// A failure is cached briefly.
	_ = s.Answer(context.Background(), Scope{ProjectRoot: "/r"}, []InstallSpec{ParseSpec(EcoNpm, "flaky")})
	got = s.Answer(context.Background(), Scope{ProjectRoot: "/r"}, []InstallSpec{ParseSpec(EcoNpm, "flaky")})
	mu.Lock()
	n = calls
	mu.Unlock()
	if got[0].Status != OnlineFailed || n != 2 {
		t.Errorf("failure cache: %+v, %d lookups", got[0], n)
	}
}

// TestSlowLookupAsksOncePerName is lane SEC-D1FIX2 milestone 2d: an ask
// that outlives its wait is answered in flight (S-748) once per install
// (name and version); a retry while that same lookup still runs reads
// not-asked, so enforce does not ask again.
func TestSlowLookupAsksOncePerName(t *testing.T) {
	// Lane SEC-DEPS3 item 1 (P-029): the quiet covers only the same name
	// AND version, only while that same lookup is in flight; it clears
	// when the lookup lands and never follows a failure.
	gate := make(chan struct{})
	s := NewService(ServiceOptions{
		Classify: func(Scope) Classifier { return func(InstallSpec) bool { return true } },
		Lookup: func(_ context.Context, specs []InstallSpec) []OnlineAnswer {
			<-gate
			return nil
		},
		Enabled: func() bool { return true },
	})
	ask := func(spec string) OnlineAnswer {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		return s.Answer(ctx, Scope{ProjectRoot: "/r"}, []InstallSpec{ParseSpec(EcoNpm, spec)})[0]
	}
	if a := ask("typescript"); a.Status != OnlineFailed || a.Reason != ReasonInFlight {
		t.Fatalf("first: %+v", a)
	}
	if a := ask("typescript@5.0.0"); a.Status != OnlineFailed || a.Reason != ReasonInFlight {
		t.Errorf("another version of the same name must still report: %+v", a)
	}
	if a := ask("typescript"); a.Status != OnlineNotAsked {
		t.Errorf("a retry of the same install while its lookup runs: %+v", a)
	}
	if a := ask("other-pkg"); a.Status != OnlineFailed {
		t.Errorf("another name still reports: %+v", a)
	}
	// Prefetch never records a quiet: a prefetch that outlives its wait
	// leaves the next real ask reporting.
	pctx, pcancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	s.Prefetch(pctx, Scope{ProjectRoot: "/r"}, []InstallSpec{ParseSpec(EcoNpm, "prefetched")})
	pcancel()
	if a := ask("prefetched"); a.Status != OnlineFailed || a.Reason != ReasonInFlight {
		t.Errorf("an ask after a prefetch must report: %+v", a)
	}
	// Land every lookup (they fail: no answer) and wait for the flights
	// to clear.
	close(gate)
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		n := len(s.inflight)
		s.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("flights never landed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// After a failed lookup the retry is never quiet: it starts a fresh
	// lookup and reports what that one says.
	if a := ask("typescript"); a.Status != OnlineFailed || a.Reason == "" {
		t.Errorf("a retry after the lookup failed must report: %+v", a)
	}
}
