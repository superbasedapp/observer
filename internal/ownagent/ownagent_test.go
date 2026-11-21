package ownagent

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNormalizeName(t *testing.T) {
	cases := []struct {
		name, in, want string
		st             Status
	}{
		{"absent", "", "", StatusAbsent},
		{"blank", "   ", "", StatusAbsent},
		{"plain", "research-bot", "research-bot", StatusOK},
		{"case and punctuation", "  My Bot! ", "my-bot", StatusOK},
		{"runs collapse", "a   /// b", "a-b", StatusOK},
		{"keeps dot and underscore", "agent_v1.2", "agent_v1.2", StatusOK},
		{"trims separators", "--bot--", "bot", StatusOK},
		{"capped", strings.Repeat("a", 80), strings.Repeat("a", MaxNameLen), StatusOK},
		{"nothing left", "!!!", "", StatusMalformed},
		{"non ascii only", "日本", "", StatusMalformed},
		{"control char", "bot\x01", "", StatusMalformed},
		{"newline", "bot\nx", "", StatusMalformed},
		{"invalid utf8", "bot\xff", "", StatusMalformed},
		{"too long raw", strings.Repeat("a", maxRawNameLen+1), "", StatusMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, st := NormalizeName(tc.in)
			if got != tc.want || st != tc.st {
				t.Fatalf("NormalizeName(%q) = %q, %v; want %q, %v", tc.in, got, st, tc.want, tc.st)
			}
		})
	}
}

func TestNormalizeSessionID(t *testing.T) {
	cases := []struct {
		name, in, want string
		st             Status
	}{
		{"absent", "", "", StatusAbsent},
		{"kept as sent", " Run-42/A ", "Run-42/A", StatusOK},
		{"too long", strings.Repeat("x", MaxSessionIDLen+1), "", StatusMalformed},
		{"control", "a\tb", "", StatusMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, st := NormalizeSessionID(tc.in)
			if got != tc.want || st != tc.st {
				t.Fatalf("NormalizeSessionID(%q) = %q, %v; want %q, %v", tc.in, got, st, tc.want, tc.st)
			}
		})
	}
}

func TestSessionIDNamespacing(t *testing.T) {
	a := SessionID("bot", "s1")
	if !strings.HasPrefix(a, sessionIDPrefix) || len(a) != len(sessionIDPrefix)+24 {
		t.Fatalf("SessionID shape = %q", a)
	}
	if a != SessionID("bot", "s1") {
		t.Fatal("SessionID is not stable")
	}
	if a == SessionID("other", "s1") {
		t.Fatal("two agents with one X-Session-Id share a session")
	}
	// Normalized names never hold a NUL, so the separator is unambiguous.
	if a == "s1" || SessionID("a-b", "c") == SessionID("a", "b-c") {
		t.Fatal("SessionID collides")
	}
}

func TestTrackerResolve(t *testing.T) {
	t0 := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	type step struct {
		agent, session string
		at             time.Duration
		wantSt         Status
		wantSame       int // index of an earlier step whose session this one continues; -1 = new
		wantExplicit   bool
	}
	cases := []struct {
		name  string
		steps []step
	}{
		{"header absent", []step{{"", "s", 0, StatusAbsent, -1, false}}},
		{"header malformed", []step{{"\x00", "s", 0, StatusMalformed, -1, false}}},
		{"explicit continues", []step{
			{"bot", "s1", 0, StatusOK, -1, true},
			{"bot", "s1", 2 * time.Hour, StatusOK, 0, true},
			{"bot", "s2", 0, StatusOK, -1, true},
		}},
		{"implicit continues within idle gap", []step{
			{"bot", "", 0, StatusOK, -1, false},
			{"bot", "", 10 * time.Minute, StatusOK, 0, false},
			{"bot", "", 35 * time.Minute, StatusOK, 0, false},
		}},
		{"implicit restarts after idle gap", []step{
			{"bot", "", 0, StatusOK, -1, false},
			{"bot", "", 31 * time.Minute, StatusOK, -1, false},
		}},
		{"malformed session falls back to implicit", []step{
			{"bot", "", 0, StatusOK, -1, false},
			{"bot", "bad\x01id", time.Minute, StatusOK, 0, false},
		}},
		{"agents are separate", []step{
			{"bot-a", "", 0, StatusOK, -1, false},
			{"bot-b", "", 0, StatusOK, -1, false},
		}},
		{"name normalizes before keying", []step{
			{"My Bot", "x", 0, StatusOK, -1, true},
			{"my-bot", "x", 0, StatusOK, 0, true},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := NewTracker(0)
			var ids []string
			for i, s := range tc.steps {
				c, st := tr.Resolve(s.agent, s.session, t0.Add(s.at))
				ids = append(ids, c.SessionID)
				if st != s.wantSt {
					t.Fatalf("step %d: status %v, want %v", i, st, s.wantSt)
				}
				if st != StatusOK {
					if c != (Claim{}) {
						t.Fatalf("step %d: non-ok status returned a claim %+v", i, c)
					}
					continue
				}
				if c.Explicit != s.wantExplicit {
					t.Fatalf("step %d: explicit=%v, want %v", i, c.Explicit, s.wantExplicit)
				}
				if s.wantSame >= 0 && c.SessionID != ids[s.wantSame] {
					t.Fatalf("step %d: session %q does not continue step %d (%q)", i, c.SessionID, s.wantSame, ids[s.wantSame])
				}
				if s.wantSame < 0 {
					for j := 0; j < i; j++ {
						if ids[j] == c.SessionID {
							t.Fatalf("step %d: expected a new session, reused step %d", i, j)
						}
					}
				}
			}
		})
	}
}

// TestTrackerEnsuredOnlyAfterMark (fix round 1, M1): resolving a claim never
// marks its session ready; only MarkEnsured does, so a request that fails
// before its row is written leaves the next request to write it.
func TestTrackerEnsuredOnlyAfterMark(t *testing.T) {
	tr := NewTracker(time.Minute)
	now := time.Now()
	c, _ := tr.Resolve("bot", "s", now)
	if tr.Ensured(c.SessionID) {
		t.Fatal("a resolved claim is ensured before any row was written")
	}
	c2, _ := tr.Resolve("bot", "s", now)
	if tr.Ensured(c2.SessionID) {
		t.Fatal("a second resolve marked the session ensured")
	}
	tr.MarkEnsured(c.SessionID)
	if !tr.Ensured(c.SessionID) {
		t.Fatal("MarkEnsured did not stick")
	}
}

func TestTrackerBounded(t *testing.T) {
	tr := NewTracker(time.Minute)
	for i := 0; i < maxTracked+10; i++ {
		tr.MarkEnsured(SessionID("bot", time.Duration(i).String()))
	}
	tr.mu.Lock()
	n := tr.ensured.Len()
	tr.mu.Unlock()
	if n > maxTracked {
		t.Fatalf("ensured set grew to %d", n)
	}
}

func TestTrackerConcurrent(t *testing.T) {
	tr := NewTracker(time.Minute)
	now := time.Now()
	var wg sync.WaitGroup
	ids := make([]string, 32)
	for i := range ids {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, _ := tr.Resolve("bot", "", now)
			ids[i] = c.SessionID
		}(i)
	}
	wg.Wait()
	for _, id := range ids {
		if id != ids[0] {
			t.Fatal("concurrent implicit requests split into several sessions")
		}
	}
}

func TestWireSurfaceHost(t *testing.T) {
	cases := []struct {
		name, stored string
		raw          bool
		want         string
		ok           bool
	}{
		{"vendor host untouched", "vscode", false, "", false},
		{"empty untouched", "", false, "", false},
		{"bare prefix is not an agent", "agent:", false, "", false},
		{"raw content ships name", "agent:my-bot", true, "agent:my-bot", true},
		{"default posture hashes", "agent:my-bot", false, "agent#" + shortHash("my-bot", 16), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := WireSurfaceHost(tc.stored, tc.raw)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("WireSurfaceHost(%q, %v) = %q, %v; want %q, %v", tc.stored, tc.raw, got, ok, tc.want, tc.ok)
			}
			if !tc.raw && strings.Contains(got, "my-bot") {
				t.Fatal("raw name leaked in the hashed posture")
			}
		})
	}
	if h := SurfaceHost("x"); h != "agent:x" {
		t.Fatalf("SurfaceHost = %q", h)
	}
	if n, ok := AgentFromSurfaceHost(SurfaceHost("x")); !ok || n != "x" {
		t.Fatal("AgentFromSurfaceHost round trip")
	}
}

// TestTrackerEvictsLeastRecentlyUsed (fix round 1): past maxTracked the
// tracker evicts the least recently used agent, so an agent that keeps
// sending keeps its implicit session while thousands of other agents come
// and go. Before the fix the whole table was cleared at 4096 entries and
// every active implicit session restarted.
func TestTrackerEvictsLeastRecentlyUsed(t *testing.T) {
	tr := NewTracker(time.Hour)
	now := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	first, _ := tr.Resolve("busy-agent", "", now)
	tr.MarkEnsured(first.SessionID)
	for i := 0; i < 3*maxTracked; i++ {
		at := now.Add(time.Duration(i) * time.Millisecond)
		tr.Resolve(fmt.Sprintf("churn-%d", i), "", at)
		if i%100 == 0 {
			c, _ := tr.Resolve("busy-agent", "", at)
			if c.SessionID != first.SessionID {
				t.Fatalf("after %d other agents the busy agent's implicit session restarted", i)
			}
			if !tr.Ensured(first.SessionID) {
				tr.MarkEnsured(c.SessionID)
			}
		}
	}
	tr.mu.Lock()
	n := tr.implicit.Len()
	tr.mu.Unlock()
	if n > maxTracked {
		t.Fatalf("implicit table grew to %d", n)
	}
	if _, ok := func() (implicitEntry, bool) { tr.mu.Lock(); defer tr.mu.Unlock(); return tr.implicit.Get("churn-0") }(); ok {
		t.Fatal("the least recently used agent was not evicted")
	}
}

func TestLRU(t *testing.T) {
	c := newLRU[int](2)
	c.Put("a", 1)
	c.Put("b", 2)
	if _, ok := c.Get("a"); !ok {
		t.Fatal("a missing")
	}
	c.Put("c", 3) // evicts b, the least recently used
	if _, ok := c.Get("b"); ok {
		t.Fatal("b survived eviction")
	}
	if v, ok := c.Get("a"); !ok || v != 1 {
		t.Fatal("a was evicted although used")
	}
	c.Put("a", 9)
	if v, _ := c.Get("a"); v != 9 || c.Len() != 2 {
		t.Fatalf("update: a=%d len=%d", v, c.Len())
	}
}
