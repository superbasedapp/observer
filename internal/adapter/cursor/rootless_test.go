package cursor

import (
	"context"
	"errors"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestResolveSyntheticRoots(t *testing.T) {
	stored := map[string]string{"known": "/stored", "placeholder": SyntheticProjectRoot}
	lookup := func(_ context.Context, sid string) (string, error) {
		if sid == "broken" {
			return "", errors.New("db busy")
		}
		return stored[sid], nil
	}
	events := []models.ToolEvent{
		{SessionID: "batch", ProjectRoot: SyntheticProjectRoot}, // rooted later in the SAME batch
		{SessionID: "batch", ProjectRoot: "/batch"},
		{SessionID: "known", ProjectRoot: SyntheticProjectRoot},       // stored folder session
		{SessionID: "unknown", ProjectRoot: SyntheticProjectRoot},     // Cloud Agent: stays
		{SessionID: "placeholder", ProjectRoot: SyntheticProjectRoot}, // already a placeholder session
		{SessionID: "broken", ProjectRoot: SyntheticProjectRoot},      // lookup error: emptied, reported
		{SessionID: "rooted", ProjectRoot: "/own"},                    // never touched
	}
	tokens := []models.TokenEvent{
		{SessionID: "known", ProjectRoot: SyntheticProjectRoot},
		{SessionID: "batch", ProjectRoot: SyntheticProjectRoot},
	}
	err := ResolveSyntheticRoots(context.Background(), events, tokens, lookup)
	if err == nil {
		t.Fatal("lookup error not reported")
	}
	want := []string{"/batch", "/batch", "/stored", SyntheticProjectRoot, SyntheticProjectRoot, "", "/own"}
	for i, w := range want {
		if events[i].ProjectRoot != w {
			t.Errorf("event %d (%s) root = %q, want %q", i, events[i].SessionID, events[i].ProjectRoot, w)
		}
	}
	if tokens[0].ProjectRoot != "/stored" || tokens[1].ProjectRoot != "/batch" {
		t.Errorf("token roots = %q/%q, want /stored and /batch", tokens[0].ProjectRoot, tokens[1].ProjectRoot)
	}
	// nil lookup: batch-local only.
	evs := []models.ToolEvent{{SessionID: "x", ProjectRoot: SyntheticProjectRoot}}
	if err := ResolveSyntheticRoots(context.Background(), evs, nil, nil); err != nil || evs[0].ProjectRoot != SyntheticProjectRoot {
		t.Fatalf("nil lookup: root=%q err=%v", evs[0].ProjectRoot, err)
	}
}

// TestHooksLogReplayDefersToTranscriptRows pins S10-CURSOR review finding
// 3, the mirror of hookCheck: a conversation the transcript/state.vscdb
// path already captured replays ONLY its usage and outcome updates (its
// action rows would be a second, differently-keyed copy of the same
// turns); a conversation with no such rows replays everything. The
// reverse direction (transcript defers to hook rows) is pinned by
// scan_test.go's WithSessionHookChecker tests.
func TestHooksLogReplayDefersToTranscriptRows(t *testing.T) {
	const conv = "8be96a3f-5490-4d9c-bb7c-8459b183a8bf"
	for _, captured := range []bool{true, false} {
		isolateStash(t)
		root, path := placeHooksLog(t, readFixture(t))
		var asked []string
		a := NewWithOptions(nil, root).WithSessionTranscriptChecker(func(_ context.Context, sid string) (bool, error) {
			asked = append(asked, sid)
			return captured && sid == conv, nil
		})
		res, err := a.ParseSessionFile(context.Background(), path, 0)
		if err != nil {
			t.Fatal(err)
		}
		var convRows, convTokens int
		for _, ev := range res.ToolEvents {
			if ev.SessionID == conv {
				convRows++
			}
		}
		for _, tk := range res.TokenEvents {
			if tk.SessionID == conv {
				convTokens++
			}
		}
		n := 0
		for _, sid := range asked {
			if sid == conv {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("captured=%v: checker consulted %d times for %s, want once per conversation", captured, n, conv)
		}
		if convTokens == 0 || len(res.OutcomeUpdates) == 0 {
			t.Fatalf("captured=%v: tokens=%d outcomes=%d, want usage and outcomes always replayed", captured, convTokens, len(res.OutcomeUpdates))
		}
		if captured && convRows != 0 {
			t.Fatalf("captured: replay emitted %d action rows for a transcript-captured conversation", convRows)
		}
		if !captured && convRows == 0 {
			t.Fatal("not captured: replay emitted no action rows")
		}
	}
}
