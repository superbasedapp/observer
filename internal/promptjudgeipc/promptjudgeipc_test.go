package promptjudgeipc

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/localipc"
)

func serve(t *testing.T, answer Answerer) string {
	t.Helper()
	if !localipc.Supported() {
		t.Skip("no local IPC transport on this platform")
	}
	dir, err := os.MkdirTemp("", "pj")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ln, ep, err := Listen(filepath.Join(dir, "observer.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = Serve(ctx, ln, answer) }()
	return ep
}

func fixed(a Answer) Answerer {
	return func(context.Context, Asked) Answer { return a }
}

// TestAskRows is one row per answer shape the hook must read correctly.
func TestAskRows(t *testing.T) {
	cases := []struct {
		name      string
		answer    Answerer
		wantErr   bool
		wantBlock bool
		want      Answer
	}{
		{name: "inactive: no verdict", answer: fixed(Answer{}), want: Answer{}},
		{name: "allow", answer: fixed(Answer{Active: true, Action: "allow"}), want: Answer{Active: true, Action: "allow"}},
		{name: "flag", answer: fixed(Answer{Active: true, Action: "flag", Basis: "flag", Reason: "r"}), want: Answer{Active: true, Action: "flag", Basis: "flag", Reason: "r"}},
		{name: "block", answer: fixed(Answer{Active: true, Action: "block", Basis: "deny", Criterion: "c1", Reason: "no"}), wantBlock: true, want: Answer{Active: true, Action: "block", Basis: "deny", Criterion: "c1", Reason: "no"}},
		{name: "action outside the vocabulary is an error", answer: fixed(Answer{Active: true, Action: "maybe"}), wantErr: true},
		{name: "a panicking answerer is an error", answer: func(context.Context, Asked) Answer { panic("boom") }, wantErr: true},
		{name: "an answerer past the budget is an error", answer: func(ctx context.Context, _ Asked) Answer {
			<-ctx.Done()
			time.Sleep(50 * time.Millisecond)
			return Answer{Active: true, Action: "allow"}
		}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ep := serve(t, tc.answer)
			got, err := Ask(context.Background(), ep, Request{Tool: "cursor", SessionID: "s1", Prompt: "ship it", Budget: 300 * time.Millisecond})
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && (got != tc.want || got.Block() != tc.wantBlock) {
				t.Fatalf("answer = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestAskCarriesThePromptAndMarksOversize: the daemon sees the prompt, tool
// and session; a prompt over MaxPromptBytes is never sent, only marked.
func TestAskCarriesThePromptAndMarksOversize(t *testing.T) {
	var mu sync.Mutex
	var seen []Asked
	ep := serve(t, func(_ context.Context, a Asked) Answer {
		mu.Lock()
		seen = append(seen, a)
		mu.Unlock()
		return Answer{Active: true, Action: "allow"}
	})
	if _, err := Ask(context.Background(), ep, Request{Tool: "droid", SessionID: "s2", Prompt: "fix the bug", Budget: time.Second}); err != nil {
		t.Fatal(err)
	}
	if _, err := Ask(context.Background(), ep, Request{Tool: "droid", SessionID: "s2", Prompt: strings.Repeat("x", MaxPromptBytes+1), Budget: time.Second}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 || seen[0] != (Asked{Tool: "droid", SessionID: "s2", Prompt: "fix the bug"}) {
		t.Fatalf("seen = %+v", seen)
	}
	if !seen[1].Oversize || seen[1].Prompt != "" {
		t.Fatalf("oversize ask = %+v, want Oversize with no prompt", seen[1])
	}
}

// TestAskWithNoDaemonIsAnError: nothing listening is an error, never a
// clean answer.
func TestAskWithNoDaemonIsAnError(t *testing.T) {
	if !localipc.Supported() {
		t.Skip("no local IPC transport on this platform")
	}
	dir := t.TempDir()
	ep, err := Endpoint(filepath.Join(dir, "observer.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Ask(context.Background(), ep, Request{Prompt: "x", Budget: 200 * time.Millisecond}); err == nil {
		t.Fatal("no daemon: want an error")
	}
	if _, err := Endpoint(""); err == nil {
		t.Fatal("empty DB path: want an error")
	}
}

// TestHandleRejectsAnotherWireVersion pins the bad_request path the hook
// reads as ErrNotUnderstood.
func TestHandleRejectsAnotherWireVersion(t *testing.T) {
	resp := handle(context.Background(), []byte(`{"v":99,"prompt":"x"}`), fixed(Answer{Active: true, Action: "allow"}))
	if resp.Error != reasonBadRequest {
		t.Fatalf("resp = %+v", resp)
	}
}

// TestServeCapsConcurrentAsks pins M1 (adm-2 fixes-1): with the cap's asks
// in flight, one more is refused at once ("busy"), not queued, and the
// endpoint serves again once a slot frees.
func TestServeCapsConcurrentAsks(t *testing.T) {
	prev := maxConcurrent
	maxConcurrent = 2
	t.Cleanup(func() { maxConcurrent = prev })
	release := make(chan struct{})
	inside := make(chan struct{}, 4)
	ep := serve(t, func(ctx context.Context, a Asked) Answer {
		if a.Prompt == "hold" {
			inside <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
		return Answer{Active: true, Action: "allow"}
	})
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = Ask(context.Background(), ep, Request{Prompt: "hold", Budget: 5 * time.Second})
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-inside:
		case <-time.After(5 * time.Second):
			t.Fatal("held asks never reached the answerer")
		}
	}
	start := time.Now()
	if _, err := Ask(context.Background(), ep, Request{Prompt: "third", Budget: 5 * time.Second}); err == nil {
		t.Fatal("an ask over the cap was answered, want refused")
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Fatalf("an ask over the cap waited %v, want refused at once", waited)
	}
	close(release)
	wg.Wait()
	if a, err := Ask(context.Background(), ep, Request{Prompt: "after", Budget: 5 * time.Second}); err != nil || a.Action != "allow" {
		t.Fatalf("after the burst: answer %+v err %v, want served", a, err)
	}
}
