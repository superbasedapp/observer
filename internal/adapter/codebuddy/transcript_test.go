package codebuddy

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/handoffsvc"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// The session-handoff tier dispatches on these interfaces by presence; the
// registry row claims TranscriptFull.
var (
	_ handoffsvc.TranscriptReader     = (*Adapter)(nil)
	_ handoffsvc.FullTranscriptReader = (*Adapter)(nil)
)

func TestReadTranscriptLiveSession(t *testing.T) {
	const sid = "01a15e5d-65aa-751d-80c7-4e7ad26233b3"
	body, err := os.ReadFile(fixturePath("windows-tool-session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	p, a := stage(t, sid, string(body))

	msgs, err := a.ReadTranscript(context.Background(), models.Session{ID: sid}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// user prompt, then ONE assistant exchange holding the three calls and
	// the closing text.
	if len(msgs) != 2 {
		t.Fatalf("messages = %d, want 2: %+v", len(msgs), msgs)
	}
	user, asst := msgs[0], msgs[1]
	if user.Role != models.TranscriptUser || !strings.Contains(user.Text, "Read notes.txt") || user.ID == "" || user.Time.IsZero() {
		t.Errorf("user = %+v", user)
	}
	if asst.Role != models.TranscriptAssistant || asst.Text != "probe done" || asst.Model != "hy3" {
		t.Errorf("assistant = %+v", asst)
	}
	if len(asst.ToolCalls) != 3 {
		t.Fatalf("tool calls = %d, want 3", len(asst.ToolCalls))
	}
	names := []string{"Read", "Bash", "Edit"}
	for i, c := range asst.ToolCalls {
		if c.Name != names[i] || !c.Resolved || c.ID != "call_probe_"+string(rune('0'+i)) {
			t.Errorf("call %d = %+v", i, c)
		}
	}
	if !strings.Contains(asst.ToolCalls[1].ResultExcerpt, "Stdout: probe") {
		t.Errorf("bash result = %q", asst.ToolCalls[1].ResultExcerpt)
	}
	if !strings.Contains(asst.ToolCalls[2].InputExcerpt, "line one edited") {
		t.Errorf("edit input = %q", asst.ToolCalls[2].InputExcerpt)
	}

	// A source hint resolves the same file without a root walk.
	other := NewWithOptions(nil, t.TempDir())
	again, err := other.ReadTranscript(context.Background(), models.Session{ID: sid}, []string{p})
	if err != nil || len(again) != 2 {
		t.Errorf("hinted read = %d msgs, err %v", len(again), err)
	}
	if _, err := other.ReadTranscript(context.Background(), models.Session{ID: sid}, nil); err == nil {
		t.Error("an unresolvable session must error, not return an empty transcript")
	}
}

// TestReadTranscriptDropsNonConversation: hook-blocked prompts, upstream
// errors, local slash-command records, reasoning and sub-agent forwards are
// not part of the conversation.
func TestReadTranscriptDropsNonConversation(t *testing.T) {
	const sid = "01a15e5b-cd73-7b3a-91eb-2d966849253e"
	body, err := os.ReadFile(fixturePath("windows-hook-blocked-session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	_, a := stage(t, sid, string(body))
	msgs, err := a.ReadTranscript(context.Background(), models.Session{ID: sid}, nil)
	if err != nil || len(msgs) != 0 {
		t.Errorf("hook-blocked session = %d msgs (err %v), want none", len(msgs), err)
	}

	const sid2 = "01a15cae-7d33-7739-8d55-8b6a3940d798"
	body, err = os.ReadFile(fixturePath("wsl-auth-error-session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	_, a = stage(t, sid2, string(body))
	msgs, err = a.ReadTranscript(context.Background(), models.Session{ID: sid2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Fatalf("auth-error session = %d msgs, want the two prompts: %+v", len(msgs), msgs)
	}
	for _, m := range msgs {
		if m.Role != models.TranscriptUser || m.Text != "hi" {
			t.Errorf("message = %+v", m)
		}
	}

	syn, err := os.ReadFile(fixturePath("synthetic-unobserved-shapes.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	const sid3 = "01a20000-0000-7000-8000-0000000000aa"
	_, a = stage(t, sid3, string(syn))
	msgs, err = a.ReadTranscript(context.Background(), models.Session{ID: sid3}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if strings.Contains(m.Text, "I should read the README first.") {
			t.Errorf("reasoning leaked into the transcript: %+v", m)
		}
		if strings.Contains(m.Text, "Read the README; one test package fails.") {
			t.Errorf("sub-agent forwarded text leaked: %+v", m)
		}
	}
}

// TestReadTranscriptFullLiftsCaps: the capped read excerpts a long tool
// result, the full read returns it whole.
func TestReadTranscriptFullLiftsCaps(t *testing.T) {
	const sid = "s1"
	long := strings.Repeat("z", 5000)
	body := `{"id":"u1","timestamp":1792600000000,"type":"message","role":"user","content":[{"type":"input_text","text":"go"}],"cwd":"/home/user/project"}` + "\n" +
		`{"id":"c1","timestamp":1792600001000,"type":"function_call","callId":"call_1","name":"Read","arguments":"{\"file_path\":\"/x\"}","providerData":{"messageId":"g1","model":"hy3"}}` + "\n" +
		`{"id":"r1","timestamp":1792600002000,"type":"function_call_result","callId":"call_1","name":"Read","status":"completed","output":{"type":"text","text":"` + long + `"}}` + "\n"
	_, a := stage(t, sid, body)
	capped, err := a.ReadTranscript(context.Background(), models.Session{ID: sid}, nil)
	if err != nil {
		t.Fatal(err)
	}
	full, err := a.ReadTranscriptFull(context.Background(), models.Session{ID: sid}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(capped) != 2 || len(full) != 2 {
		t.Fatalf("messages capped=%d full=%d", len(capped), len(full))
	}
	if got := len(capped[1].ToolCalls[0].ResultExcerpt); got >= len(long) {
		t.Errorf("capped result = %d bytes, want an excerpt", got)
	}
	if got := full[1].ToolCalls[0].ResultExcerpt; got != long {
		t.Errorf("full result = %d bytes, want the whole %d", len(got), len(long))
	}
}

func TestReadTranscriptCancelled(t *testing.T) {
	_, a := stage(t, "s1", "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.ReadTranscript(ctx, models.Session{ID: "s1"}, nil); err == nil {
		t.Error("a cancelled read must error")
	}
}

// ---- terminal resolver ----

func stageTerminal(t *testing.T, body func(time.Time) string) (*Adapter, string, time.Time) {
	t.Helper()
	p, a, home := stageLive(t, "windows-tool-session.jsonl", liveSID)
	_ = p
	now := time.Now()
	writeLog(t, home, now, "w__1.log", body(now))
	return a, home, now
}

func TestResolveTerminalSession(t *testing.T) {
	var _ adapter.TerminalSessionResolver = (*Adapter)(nil)
	ctx := context.Background()
	cases := []struct {
		name string
		pid  int
		body func(now time.Time) string
		want string
	}{
		{
			name: "one fresh session on a pid whose start is in the log",
			pid:  4242,
			body: func(now time.Time) string {
				return logLine(now.Add(-5*time.Minute), 4242, "[CliDispatcher]  [ColdStart] cli onStart pid=4242 version=2.171.0") +
					logLine(now.Add(-time.Minute), 4242, "[FinalStop] executing FinalStop hooks sessionId="+liveSID)
			},
			want: liveSID,
		},
		{
			name: "two sessions on one pid abstains",
			pid:  4242,
			body: func(now time.Time) string {
				return logLine(now.Add(-5*time.Minute), 4242, "[CliDispatcher]  [ColdStart] cli onStart pid=4242 version=2.171.0") +
					logLine(now.Add(-time.Minute), 4242, "[FinalStop] executing FinalStop hooks sessionId="+liveSID) +
					logLine(now.Add(-time.Minute), 4242, "[FinalStop] executing FinalStop hooks sessionId=01a15e5b-473e-7413-959d-4df8c15348f1")
			},
		},
		{
			name: "no start line for the pid abstains",
			pid:  4242,
			body: func(now time.Time) string {
				return logLine(now.Add(-time.Minute), 4242, "[FinalStop] executing FinalStop hooks sessionId="+liveSID)
			},
		},
		{
			name: "a stale pid abstains (it may have been recycled)",
			pid:  4242,
			body: func(now time.Time) string {
				return logLine(now.Add(-3*time.Hour), 4242, "[CliDispatcher]  [ColdStart] cli onStart pid=4242 version=2.171.0") +
					logLine(now.Add(-3*time.Hour), 4242, "[FinalStop] executing FinalStop hooks sessionId="+liveSID)
			},
		},
		{
			name: "a different pid abstains",
			pid:  99,
			body: func(now time.Time) string {
				return logLine(now.Add(-time.Minute), 4242, "[CliDispatcher]  [ColdStart] cli onStart pid=4242 version=2.171.0") +
					logLine(now.Add(-time.Minute), 4242, "[FinalStop] executing FinalStop hooks sessionId="+liveSID)
			},
		},
		{
			name: "a session with no transcript abstains",
			pid:  4242,
			body: func(now time.Time) string {
				return logLine(now.Add(-time.Minute), 4242, "[CliDispatcher]  [ColdStart] cli onStart pid=4242 version=2.171.0") +
					logLine(now.Add(-time.Minute), 4242, "[FinalStop] executing FinalStop hooks sessionId=01a15e5b-473e-7413-959d-4df8c15348f1")
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, _, _ := stageTerminal(t, tc.body)
			got, err := a.ResolveTerminalSession(ctx, adapter.TerminalProcess{PID: tc.pid})
			if err != nil {
				t.Fatal(err)
			}
			if got.SessionID != tc.want {
				t.Errorf("session = %q, want %q", got.SessionID, tc.want)
			}
			if tc.want != "" && !strings.Contains(got.Evidence, "pid=4242") {
				t.Errorf("evidence = %q", got.Evidence)
			}
		})
	}

	t.Run("pid <= 1 and a cancelled context", func(t *testing.T) {
		a, _, _ := stageTerminal(t, func(time.Time) string { return "" })
		if id, err := a.ResolveTerminalSession(ctx, adapter.TerminalProcess{PID: 1}); err != nil || id.SessionID != "" {
			t.Errorf("pid 1 = %+v %v", id, err)
		}
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := a.ResolveTerminalSession(cctx, adapter.TerminalProcess{PID: 4242}); err == nil {
			t.Error("cancelled context must error")
		}
	})

	t.Run("a foreign-side data home is never consulted", func(t *testing.T) {
		a, _, _ := stageTerminal(t, func(now time.Time) string {
			return logLine(now.Add(-time.Minute), 4242, "[CliDispatcher]  [ColdStart] cli onStart pid=4242 version=2.171.0") +
				logLine(now.Add(-time.Minute), 4242, "[FinalStop] executing FinalStop hooks sessionId="+liveSID)
		})
		other := t.TempDir()
		t.Setenv("HOME", other)
		t.Setenv("USERPROFILE", other)
		if id, _ := a.ResolveTerminalSession(ctx, adapter.TerminalProcess{PID: 4242}); id.SessionID != "" {
			t.Errorf("resolved across the OS boundary: %+v", id)
		}
	})
}
