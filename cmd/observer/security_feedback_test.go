//go:build !sbo_omit_security

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/localipc"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfeedback"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secipc"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// fakeGitHubToken is split so no scanner reads it as a committed secret.
var fakeGitHubToken = "ghp_" + "Zx9Kq2Lm8Np4Rt6Vw1Yb3Cd5Ef7Gh0Jk2Ln4"

// writeFeedbackConfig writes a config with no [components] block (or with
// one, when block is set) and returns its path.
func writeFeedbackConfig(t *testing.T, block string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "sfb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cp := filepath.Join(dir, "config.toml")
	body := "[observer]\ndb_path = \"" + filepath.ToSlash(filepath.Join(dir, "o.db")) + "\"\n" + block
	if err := os.WriteFile(cp, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cp
}

// pinHookSecurity makes currentHookSecurity(cp) read as the signed guard
// posture would: module active with packs.
func pinHookSecurity(t *testing.T, cp string, packs ...string) secposture.Layout {
	t.Helper()
	hs := &hookSecurity{config: cp, layout: secposture.LayoutFor(cp), module: secposture.ModuleActive, packs: packs}
	hs.once.Do(func() {})
	hookSecMu.Lock()
	prev := hookSecCur
	hookSecCur = hs
	hookSecMu.Unlock()
	t.Cleanup(func() {
		hookSecMu.Lock()
		hookSecCur = prev
		hookSecMu.Unlock()
	})
	return hs.layout
}

func claudePostBody(cwd, content string) []byte {
	b, _ := json.Marshal(map[string]any{
		"session_id": "s1", "cwd": cwd, "hook_event_name": "PostToolUse", "tool_name": "Write",
		"tool_input": map[string]any{"file_path": filepath.Join(cwd, "config.py"), "content": content},
	})
	return b
}

// TestFeedbackInertWithoutComponents (milestone 2d, the opt-in decision):
// with no [components] block nothing selects security.feedback, so no
// registration writer gains an event, the daemon serves no answerer and
// every post reply is the reply the handler was given.
func TestFeedbackInertWithoutComponents(t *testing.T) {
	cp := writeFeedbackConfig(t, "")
	snap := componentSnapshotFor(cp)
	if securitySelected(snap, securityFeedbackComponent) {
		t.Fatal("security.feedback is selected with no [components] block")
	}
	if registrationSelected(cp, "")(securityFeedbackComponent) {
		t.Fatal("the registration writers would write the feedback events")
	}
	if securityFeedbackAnswerer(context.Background(), cp, snap) != nil {
		t.Fatal("the daemon serves a feedback answerer")
	}
	opts, err := autoRegisterOptions(cp)
	if err != nil {
		t.Fatal(err)
	}
	if opts.Selected == nil || opts.Selected(securityFeedbackComponent) {
		t.Fatal("observer start's registration options select security.feedback")
	}
	// Even a module-active posture without the pack leaves replies alone.
	pinHookSecurity(t, cp, "security", "security.secrets")
	reply := []byte(`{"decision":"approve"}` + "\n")
	body := claudePostBody(t.TempDir(), "key = \""+fakeGitHubToken+"\"\n")
	if got := postFeedbackBytes(context.Background(), models.ToolClaudeCode, "PostToolUse", body, reply, cp); !bytes.Equal(got, reply) {
		t.Fatalf("post reply changed: %s", got)
	}
	var out bytes.Buffer
	handleClaudeCodePostTool(bytes.NewReader(body), &out, &bytes.Buffer{}, "claude-code:post-tool", cp)
	if out.String() != `{"decision":"approve"}`+"\n" {
		t.Fatalf("Claude Code PostToolUse reply = %q", out.String())
	}
	// A leftover Gemini AfterTool registration answers exactly as the
	// binding fallback always did.
	var fb, want bytes.Buffer
	if !handlePostFeedbackHook(context.Background(), "gemini-cli", "AfterTool", "gemini-cli:AfterTool", cp, bytes.NewReader(body), &fb, &bytes.Buffer{}) {
		t.Fatal("AfterTool has no feedback handler")
	}
	hook.HandleApprove("gemini-cli:AfterTool", bytes.NewReader(body), &want, &bytes.Buffer{})
	if !bytes.Equal(fb.Bytes(), want.Bytes()) {
		t.Fatalf("AfterTool reply %q, want %q", fb.String(), want.String())
	}
}

// serveFeedbackAt serves the feedback kind on the layout's endpoint.
func serveFeedbackAt(t *testing.T, layout secposture.Layout, f secipc.FeedbackAnswerer) {
	t.Helper()
	if !localipc.Supported() {
		t.Skip("no owner-only IPC transport on this platform")
	}
	ln, _, err := secipc.Listen(layout.Dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = secipc.ServeWith(ctx, ln, nil, secipc.Options{Feedback: f}) }()
}

// TestFeedbackSeamPerDialect: while the component is selected and the pack
// is signed in, the daemon's findings become templated lines in each host's
// own reply shape.
func TestFeedbackSeamPerDialect(t *testing.T) {
	cp := writeFeedbackConfig(t, feedbackSelectedBlock)
	layout := pinHookSecurity(t, cp, "security", securityFeedbackComponent)
	var asked secipc.FeedbackRequest
	serveFeedbackAt(t, layout, func(_ context.Context, r secipc.FeedbackRequest) (secipc.FeedbackOffer, error) {
		asked = r
		return secipc.FeedbackOffer{Hits: []policy.SecurityHit{{
			Category: policy.FindingSecret, Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceHigh,
			RuleID: "secret.github_pat", Path: "config.py", Line: 1,
		}}}, nil
	})
	cwd := t.TempDir()
	body := claudePostBody(cwd, "x = 1\n")
	cases := []struct {
		tool, event, reply, want string
	}{
		{models.ToolClaudeCode, "PostToolUse", `{"decision":"approve"}` + "\n", `"decision":"approve","hookSpecificOutput":{"additionalContext":"observer: found a GitHub token (high confidence) by rule secret.github_pat.`},
		{models.ToolCodex, "PostToolUse", "{}\n", `{"hookSpecificOutput":{"additionalContext":"observer: found a GitHub token (high confidence) by rule secret.github_pat`},
		{models.ToolCursor, "postToolUse", `{"permission":"allow","continue":true}` + "\n", `"additional_context":"observer: found a GitHub token (high confidence) by rule secret.github_pat`},
	}
	for _, tc := range cases {
		got := postFeedbackBytes(context.Background(), tc.tool, tc.event, body, []byte(tc.reply), cp)
		if !strings.Contains(string(got), tc.want) {
			t.Errorf("%s: %s", tc.tool, got)
		}
	}
	if asked.SessionID != "s1" || asked.ProjectRoot == "" {
		t.Fatalf("the daemon was asked %+v", asked)
	}
	var out bytes.Buffer
	if !handlePostFeedbackHook(context.Background(), "gemini-cli", "AfterTool", "gemini-cli:AfterTool", cp, bytes.NewReader(body), &out, &bytes.Buffer{}) {
		t.Fatal("no handler")
	}
	if !strings.Contains(out.String(), `"hookEventName":"AfterTool"`) || !strings.Contains(out.String(), "secret.github_pat") {
		t.Fatalf("Gemini AfterTool reply: %s", out.String())
	}
	out.Reset()
	handlePostFeedbackHook(context.Background(), "opencode", "tool.execute.after", "opencode:tool.execute.after", cp, bytes.NewReader(body), &out, &bytes.Buffer{})
	if !strings.Contains(out.String(), `"context":"observer: found a GitHub token (high confidence) by rule secret.github_pat`) {
		t.Fatalf("plugin reply: %s", out.String())
	}
}

// TestFeedbackDaemonDeclineIsAnAnswer: a daemon that answers with nothing
// (after_write off, root refused) is never second-guessed by the fallback.
func TestFeedbackDaemonDeclineIsAnAnswer(t *testing.T) {
	cp := writeFeedbackConfig(t, feedbackSelectedBlock)
	layout := pinHookSecurity(t, cp, "security", securityFeedbackComponent)
	serveFeedbackAt(t, layout, nil)
	reply := []byte(`{"decision":"approve"}` + "\n")
	body := claudePostBody(t.TempDir(), "key = \""+fakeGitHubToken+"\"\n")
	if got := postFeedbackBytes(context.Background(), models.ToolClaudeCode, "PostToolUse", body, reply, cp); !bytes.Equal(got, reply) {
		t.Fatalf("a declined answer added context: %s", got)
	}
}

// TestFeedbackFallbackWhenTheDaemonIsSilent (milestone 2b): no endpoint at
// all, so the hook's own secret rows read the written content; a decoy in
// a description field and low-confidence entropy never produce a line, and
// after_write off silences it.
func TestFeedbackFallbackWhenTheDaemonIsSilent(t *testing.T) {
	cp := writeFeedbackConfig(t, feedbackSelectedBlock)
	pinHookSecurity(t, cp, "security", securityFeedbackComponent)
	reply := []byte(`{"decision":"approve"}` + "\n")
	body := claudePostBody(t.TempDir(), "key = \""+fakeGitHubToken+"\"\n")
	got := postFeedbackBytes(context.Background(), models.ToolClaudeCode, "PostToolUse", body, reply, cp)
	if !strings.Contains(string(got), "found a GitHub token (high confidence) by rule secret.github_pat.") || strings.Contains(string(got), fakeGitHubToken) {
		t.Fatalf("fallback reply: %s", got)
	}
	clean := claudePostBody(t.TempDir(), "x = 1\n")
	if got := postFeedbackBytes(context.Background(), models.ToolClaudeCode, "PostToolUse", clean, reply, cp); !bytes.Equal(got, reply) {
		t.Fatalf("a clean write added context: %s", got)
	}
	off := writeFeedbackConfig(t, feedbackSelectedBlock+"[security.feedback]\nafter_write = false\n")
	pinHookSecurity(t, off, "security", securityFeedbackComponent)
	if got := postFeedbackBytes(context.Background(), models.ToolClaudeCode, "PostToolUse", body, reply, off); !bytes.Equal(got, reply) {
		t.Fatalf("after_write off still added context: %s", got)
	}
}

// postFeedbackBytes is securityPostFeedback into a buffer.
func postFeedbackBytes(ctx context.Context, tool, event string, body, reply []byte, configPath string) []byte {
	var b bytes.Buffer
	securityPostFeedback(ctx, &b, tool, event, body, reply, configPath)
	return b.Bytes()
}

// feedbackStoreFinding stores one open, new, high-confidence finding of
// session s1 under root and returns its id.
func feedbackStoreFinding(t *testing.T, st *store.Store, root, key string) string {
	t.Helper()
	f := secfinding.Normalize(secfinding.Finding{
		LocalKey: key, Rule: secfinding.Rule{ID: "secret.github_pat", Pack: "security.secrets"}, Category: policy.FindingSecret,
		Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceHigh, Baseline: policy.FindingBaselineNew,
		Project: secfinding.Project{RootHash: secposture.ProjectRootHash(root)}, Location: secfinding.Location{RelPath: "a.py", StartLine: 3},
		Lineage: secfinding.Lineage{SessionID: "s1"}, Message: "never forwarded",
	})
	id, _, err := st.UpsertSecFinding(context.Background(), f, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestOfferSecurityFeedbackLeases (lane sec-polish, audit finding F3): the
// daemon's answerer offers each finding as rule data under a lease; while
// leased no other reply gets it; unacknowledged it is offered again after
// the lease; acknowledged it is recorded and never offered again; and a
// finding closed meanwhile is neither offered again nor recorded.
func TestOfferSecurityFeedbackLeases(t *testing.T) {
	dir := t.TempDir()
	database, err := db.Open(context.Background(), db.Options{Path: filepath.Join(dir, "o.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	ctx := context.Background()
	st := store.New(database)
	root := filepath.Join(dir, "repo")
	id := feedbackStoreFinding(t, st, root, "k1")
	req := secipc.FeedbackRequest{ProjectRoot: root, SessionID: "s1"}
	var o feedbackOffers
	t0 := time.Now()

	first, err := o.offer(ctx, st, req, t0)
	if err != nil || len(first.Hits) != 1 || first.Hits[0].RuleID != "secret.github_pat" || first.Hits[0].Path != "a.py" || first.Hits[0].Line != 3 {
		t.Fatalf("offer = %+v, %v", first, err)
	}
	if again, _ := o.offer(ctx, st, req, t0.Add(time.Second)); len(again.Hits) != 0 {
		t.Fatalf("a leased finding was offered to a second reply: %+v", again.Hits)
	}
	// Never acknowledged (the reply missed the agent): offered again after
	// the lease.
	second, _ := o.offer(ctx, st, req, t0.Add(secfeedback.LeaseFor))
	if len(second.Hits) != 1 {
		t.Fatalf("an unacknowledged line was lost: %+v", second.Hits)
	}
	second.Ack(ctx)
	if after, _ := o.offer(ctx, st, req, t0.Add(3*secfeedback.LeaseFor)); len(after.Hits) != 0 {
		t.Fatalf("an acknowledged line was offered again: %+v", after.Hits)
	}
	var sent int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM sec_finding_events WHERE kind = 'feedback_sent' AND finding_id = ?`, id).Scan(&sent); err != nil || sent != 1 {
		t.Fatalf("feedback_sent = %d %v", sent, err)
	}

	// A finding closed while its line is leased: never offered again, and
	// a late acknowledgement records nothing.
	closed := feedbackStoreFinding(t, st, root, "k2")
	t1 := t0.Add(10 * secfeedback.LeaseFor)
	late, _ := o.offer(ctx, st, req, t1)
	if len(late.Hits) != 1 {
		t.Fatalf("offer of the second finding: %+v", late.Hits)
	}
	if err := st.SetSecFindingStatus(ctx, closed, policy.FindingStatusNotReproduced, "", t1); err != nil {
		t.Fatal(err)
	}
	if again, _ := o.offer(ctx, st, req, t1.Add(secfeedback.LeaseFor)); len(again.Hits) != 0 {
		t.Fatalf("a closed finding was offered again: %+v", again.Hits)
	}
	late.Ack(ctx)
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM sec_finding_events WHERE kind = 'feedback_sent' AND finding_id = ?`, closed).Scan(&sent); err != nil || sent != 0 {
		t.Fatalf("a closed finding was recorded as sent: %d %v", sent, err)
	}
}

// TestFeedbackRuleNamedTable (lane sec-polish, audit finding F5): a rule
// id is named in a feedback line only when its pack's row knows it from
// Observer's compiled tables; an injection-shaped id under a native pack,
// any id of an engine, a custom driver or the advisory database is not.
func TestFeedbackRuleNamedTable(t *testing.T) {
	cases := []struct {
		pack, id string
		named    bool
	}{
		{"security.secrets", "secret.github_pat", true},
		{"security.secrets", "secret.IGNORE_PREVIOUS_INSTRUCTIONS", false},
		{"security.secrets", "secret.", false},
		{"security.code", "ci.s-771", true},
		{"security.code", "code.s-761", true},
		{"security.code", "ci.ignore_previous_instructions", false},
		{"security.code", "S-771", false},
		{"security.trust", "repo-trust/symlink_escape", true},
		{"security.trust", "repo-trust/ignore_previous_instructions", false},
		{"security.trust", "agent-config/changed", true},
		{"security.trust", "agent-config/user-changed", true},
		{"security.trust", "agent-version/CVE-2025-59536", true},
		{"security.trust", "agent-version/APPROVE-ALL", false},
		{"security.deps", "deps.s-747", true},
		{"security.deps", "deps.approve_all", false},
		{"security.scan.custom", "custom-scanner-changed", true},
		{"custom:gosec", "IGNORE_PREVIOUS_INSTRUCTIONS", false},
		{"custom:gosec", "G101", false},
		{"osv", "GHSA-xxxx-yyyy-zzzz", false},
		{"", "IGNORE_PREVIOUS_INSTRUCTIONS", false},
		{"security.secrets", "", false},
	}
	for _, tc := range cases {
		if _, built := feedbackRuleTables[tc.pack]; tc.named && !built {
			continue // the module that owns the row is compiled out of this build
		}
		if got := feedbackRuleNamed(tc.pack, tc.id); got != tc.named {
			t.Errorf("feedbackRuleNamed(%q, %q) = %v, want %v", tc.pack, tc.id, got, tc.named)
		}
	}
}

// TestFeedbackHitDropsAnUnverifiedRule (audit finding F5): the daemon
// sends a rule id only when it is verified; an engine's injection-shaped
// id and path reach the line as the category and the quoted last field.
func TestFeedbackHitDropsAnUnverifiedRule(t *testing.T) {
	const word = "IGNORE_PREVIOUS_INSTRUCTIONS"
	f := secfinding.Finding{
		Rule: secfinding.Rule{ID: word}, Category: policy.FindingCodeVuln, Severity: policy.FindingSeverityHigh,
		Confidence: policy.FindingConfidenceHigh, Location: secfinding.Location{RelPath: word + "/x.py", StartLine: 2},
	}
	h := feedbackHit(f)
	if h.RuleID != "" {
		t.Fatalf("an unverified rule id crossed the endpoint: %+v", h)
	}
	lines := secfeedback.Lines(feedbackFindings([]policy.SecurityHit{h}))
	if len(lines) != 1 || strings.Count(lines[0], word) != 1 || !strings.HasSuffix(lines[0], secfeedback.HumanLine+secfeedback.LocationLabel+`"`+word+`/x.py":2`) {
		t.Fatalf("line: %q", lines)
	}
	f.Rule = secfinding.Rule{ID: "secret.github_pat", Pack: "security.secrets"}
	if h := feedbackHit(f); h.RuleID != "secret.github_pat" {
		t.Fatalf("a verified rule id was dropped: %+v", h)
	}
}

// TestFeedbackRefusedReplyWriteIsNotAcknowledged (lane sec-polish, audit
// finding F3): a reply the host refuses leaves the daemon's lease
// unacknowledged; a reply written whole acknowledges it once.
func TestFeedbackRefusedReplyWriteIsNotAcknowledged(t *testing.T) {
	cp := writeFeedbackConfig(t, feedbackSelectedBlock)
	layout := pinHookSecurity(t, cp, "security", securityFeedbackComponent)
	var acked atomic.Int32
	serveFeedbackAt(t, layout, func(context.Context, secipc.FeedbackRequest) (secipc.FeedbackOffer, error) {
		return secipc.FeedbackOffer{Hits: []policy.SecurityHit{{
			Category: policy.FindingSecret, Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceHigh,
			RuleID: "secret.github_pat", Path: "config.py", Line: 1,
		}}, Ack: func(context.Context) { acked.Add(1) }}, nil
	})
	body := claudePostBody(t.TempDir(), "x = 1\n")
	reply := []byte(`{"decision":"approve"}` + "\n")
	securityPostFeedback(context.Background(), failingWriter{}, models.ToolClaudeCode, "PostToolUse", body, reply, cp)
	w := securityPostFeedbackWriter(context.Background(), failingWriter{}, models.ToolCodex, "PostToolUse", body, cp)
	if _, err := w.Write([]byte("{}\n")); err == nil {
		t.Fatal("the refused write reported success")
	}
	time.Sleep(100 * time.Millisecond)
	if acked.Load() != 0 {
		t.Fatalf("a refused reply was acknowledged %d times", acked.Load())
	}
	if got := postFeedbackBytes(context.Background(), models.ToolClaudeCode, "PostToolUse", body, reply, cp); !strings.Contains(string(got), "secret.github_pat") {
		t.Fatalf("reply: %s", got)
	}
	for end := time.Now().Add(3 * time.Second); acked.Load() == 0 && time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
	}
	if acked.Load() != 1 {
		t.Fatalf("the written reply was acknowledged %d times, want 1", acked.Load())
	}
}

// failingWriter refuses every write, as a host that closed its end does.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// TestFeedbackAnswererNeedsSelectionAndAfterWrite: the daemon serves an
// answerer only while a [components] block selects the child and
// after_write is on.
func TestFeedbackAnswererNeedsSelectionAndAfterWrite(t *testing.T) {
	block := "[components]\nadd = [\"security.feedback\"]\n"
	on := writeFeedbackConfig(t, block)
	snap := componentSnapshotFor(on)
	if !securitySelected(snap, securityFeedbackComponent) {
		t.Fatalf("security.feedback not selected by %q: %+v", block, snap.Selected)
	}
	if securityFeedbackAnswerer(context.Background(), on, snap) == nil {
		t.Fatal("no answerer while selected")
	}
	if !registrationSelected(on, "")(securityFeedbackComponent) {
		t.Fatal("the registration writers would not write the feedback events")
	}
	off := writeFeedbackConfig(t, block+"[security.feedback]\nafter_write = false\n")
	if securityFeedbackAnswerer(context.Background(), off, componentSnapshotFor(off)) != nil {
		t.Fatal("an answerer with after_write off")
	}
}

// TestFeedbackSelectedNeedsAComponentsBlock: the opt-in rule itself.
func TestFeedbackSelectedNeedsAComponentsBlock(t *testing.T) {
	if securitySelected(componentstate.Legacy(), securityFeedbackComponent) {
		t.Fatal("legacy install: feedback switched itself on")
	}
	added := componentstate.Resolve(config.ComponentsConfig{Add: []string{securityFeedbackComponent}}, nil)
	if !securitySelected(added, securityFeedbackComponent) || !registrationSelectedFor(added)(securityFeedbackComponent) {
		t.Fatal("selected in [components]: still off")
	}
	if !slices.Contains(securityActivePacks(added), securityFeedbackComponent) {
		t.Fatal("the signed pack set does not carry security.feedback while selected")
	}
	if slices.Contains(securityActivePacks(componentstate.Legacy()), securityFeedbackComponent) {
		t.Fatal("the legacy pack set carries security.feedback")
	}
}

// TestFeedbackPendingSurvivesRestartAndLateAck (lane SEC-H2, audit finding
// F3): once an answer is written (Pending), its finding stays out of other
// replies past the short lease and across a daemon restart (the pending
// offers are reloaded from disk); a late acknowledgement by token records
// it exactly once, after which it is never offered again; an unknown token
// records nothing.
func TestFeedbackPendingSurvivesRestartAndLateAck(t *testing.T) {
	dir := t.TempDir()
	database, err := db.Open(context.Background(), db.Options{Path: filepath.Join(dir, "o.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	ctx := context.Background()
	st := store.New(database)
	root := filepath.Join(dir, "repo")
	id := feedbackStoreFinding(t, st, root, "k1")
	req := secipc.FeedbackRequest{ProjectRoot: root, SessionID: "s1"}
	path := filepath.Join(dir, feedbackPendingFile)
	daemon := func() *feedbackOffers {
		return &feedbackOffers{
			load: func() []secfeedback.PendingOffer {
				b, err := readFeedbackPending(path)
				if err != nil {
					return nil
				}
				return secfeedback.DecodePending(b)
			},
			persist: func(p []secfeedback.PendingOffer) { writeFeedbackPending(path, p) },
		}
	}
	o := daemon()
	now := time.Now()
	first, err := o.offer(ctx, st, req, now)
	if err != nil || len(first.Hits) != 1 || first.Token == "" || first.Pending == nil {
		t.Fatalf("offer %+v %v", first, err)
	}
	first.Pending(ctx)
	if again, _ := o.offer(ctx, st, req, now.Add(2*secfeedback.LeaseFor)); len(again.Hits) != 0 {
		t.Fatalf("a pending line was offered again after the short lease: %+v", again.Hits)
	}
	// A daemon restart: a fresh owner reloads the pending offer.
	o = daemon()
	if again, _ := o.offer(ctx, st, req, time.Now()); len(again.Hits) != 0 {
		t.Fatalf("a pending line was offered again after a restart: %+v", again.Hits)
	}
	o.ackToken(ctx, st, "ffffffffffffffffffffffffffffffff", time.Now())
	sent := func() int {
		var n int
		if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM sec_finding_events WHERE kind = 'feedback_sent' AND finding_id = ?`, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if sent() != 0 {
		t.Fatal("an unknown token recorded")
	}
	o.ackToken(ctx, st, first.Token, time.Now())
	o.ackToken(ctx, st, first.Token, time.Now())
	if sent() != 1 {
		t.Fatalf("feedback_sent = %d, want exactly 1", sent())
	}
	if after, _ := o.offer(ctx, st, req, time.Now().Add(secfeedback.PendingFor)); len(after.Hits) != 0 {
		t.Fatalf("an acknowledged line was offered again: %+v", after.Hits)
	}
	if b, err := readFeedbackPending(path); err != nil || len(secfeedback.DecodePending(b)) != 0 {
		t.Fatalf("the settled offer is still on disk: %s %v", b, err)
	}
}
