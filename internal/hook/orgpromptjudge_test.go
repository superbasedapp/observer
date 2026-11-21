package hook

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// judgingEvaluator is a stubPromptEvaluator that also has the OrgPromptJudge
// capability.
type judgingEvaluator struct {
	stubPromptEvaluator
	judgement OrgPromptJudgement
	asked     []string
	queries   []OrgPromptQuery
}

func (j *judgingEvaluator) JudgeOrgPrompt(q OrgPromptQuery) OrgPromptJudgement {
	j.asked = append(j.asked, q.Prompt)
	j.queries = append(j.queries, q)
	return j.judgement
}

// judgeOnly is an OrgPromptJudge with no guard (the judge-only path).
type judgeOnly struct {
	judgement OrgPromptJudgement
	queries   []OrgPromptQuery
}

func (j *judgeOnly) JudgeOrgPrompt(q OrgPromptQuery) OrgPromptJudgement {
	j.queries = append(j.queries, q)
	return j.judgement
}

// TestOrgPromptJudgeRows is one row per dialect x judgement (lane adm-2): the
// organization's judge is consulted only after the guard lets the prompt
// through; its block replies through the dialect's own block (or, on a
// warn-only seam, a warning), and an evaluator without the capability is
// never asked anything.
func TestOrgPromptJudgeRows(t *testing.T) {
	const reason = "Prompt refused by your organization's coding-agent admission policy: off-topic"
	claude := `{"session_id":"s1","prompt":"build the release"}`
	kiro := `{"hook_event_name":"userPromptSubmit","cwd":"/w","session_id":"k1","prompt":"build the release"}`
	cases := []struct {
		name       string
		dialect    string
		event      string
		body       string
		guard      guard.PromptVerdict
		judgement  OrgPromptJudgement
		capability bool
		wantAsked  bool
		wantCode   int
		wantInOut  string
		wantNotOut string
	}{
		{
			name: "claude-code: judge block exits 2 with the reason on stderr", dialect: PromptDialectClaudeCode, event: "UserPromptSubmit", body: claude,
			guard: allowVerdict(), judgement: OrgPromptJudgement{Block: true, Reason: reason}, capability: true, wantAsked: true, wantCode: 2, wantInOut: reason,
		},
		{
			name: "claude-code: judge allow replies allow", dialect: PromptDialectClaudeCode, event: "UserPromptSubmit", body: claude,
			guard: allowVerdict(), judgement: OrgPromptJudgement{}, capability: true, wantAsked: true, wantNotOut: reason,
		},
		{
			name: "claude-code: a guard block is never sent to the judge", dialect: PromptDialectClaudeCode, event: "UserPromptSubmit", body: claude,
			guard: denyVerdict("secret"), judgement: OrgPromptJudgement{Block: true, Reason: reason}, capability: true, wantCode: 2,
		},
		{
			name: "claude-code: no capability, nothing asked", dialect: PromptDialectClaudeCode, event: "UserPromptSubmit", body: claude,
			guard: allowVerdict(), wantNotOut: reason,
		},
		{
			name: "top-level-block: judge block is a decision block", dialect: PromptDialectTopLevelBlock, event: "UserPromptSubmit", body: claude,
			guard: allowVerdict(), judgement: OrgPromptJudgement{Block: true, Reason: reason}, capability: true, wantAsked: true, wantCode: 2, wantInOut: `"decision":"block"`,
		},
		{
			name: "kiro-cli (warn-only seam): judge block is a warning, never a fake block", dialect: PromptDialectKiroCLI, event: "userPromptSubmit", body: kiro,
			guard: allowVerdict(), judgement: OrgPromptJudgement{Block: true, Reason: reason}, capability: true, wantAsked: true, wantInOut: "off-topic",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := stubPromptEvaluator{verdict: tc.guard}
			var ge PromptEvaluator = &stub
			jev := &judgingEvaluator{stubPromptEvaluator: stub, judgement: tc.judgement}
			if tc.capability {
				ge = jev
			}
			var out, errOut bytes.Buffer
			handled, _, code := HandlePromptSubmitGuarded("tool", tc.dialect, tc.event, []byte(tc.body), false, ge, nil, &out, &errOut)
			if !handled {
				t.Fatal("not handled")
			}
			if code != tc.wantCode {
				t.Fatalf("exit code %d, want %d (stdout %q stderr %q)", code, tc.wantCode, out.String(), errOut.String())
			}
			both := out.String() + errOut.String()
			if tc.wantInOut != "" && !strings.Contains(both, tc.wantInOut) {
				t.Fatalf("output lacks %q:\nstdout %q\nstderr %q", tc.wantInOut, out.String(), errOut.String())
			}
			if tc.wantNotOut != "" && strings.Contains(both, tc.wantNotOut) {
				t.Fatalf("output carries %q unexpectedly", tc.wantNotOut)
			}
			if asked := len(jev.asked) > 0; asked != tc.wantAsked {
				t.Fatalf("judge asked=%v, want %v", asked, tc.wantAsked)
			}
			if tc.wantAsked && jev.asked[0] != "build the release" {
				t.Fatalf("judge saw %q", jev.asked[0])
			}
		})
	}
}

// TestOrgPromptJudgeBlockKeepsTheGuardsOwnRecord: when the judge refuses a
// prompt the guard only warned on, the hook persists the GUARD's own verdict
// (the daemon audits the judge's), never the judge's block.
func TestOrgPromptJudgeBlockKeepsTheGuardsOwnRecord(t *testing.T) {
	jev := &judgingEvaluator{stubPromptEvaluator: stubPromptEvaluator{verdict: warnVerdict("pii")}, judgement: OrgPromptJudgement{Block: true, Reason: "no"}}
	var persisted []guard.PromptVerdict
	persist := func(pv guard.PromptVerdict, _ guard.Emission, _ string) { persisted = append(persisted, pv) }
	_, after, code := HandlePromptSubmitGuarded("tool", PromptDialectClaudeCode, "UserPromptSubmit", []byte(`{"session_id":"s1","prompt":"build"}`), false, jev, persist, io.Discard, io.Discard)
	if code != 2 {
		t.Fatalf("code %d, want the judge's block", code)
	}
	if after != nil {
		after()
	}
	if len(persisted) != 1 || persisted[0].Verdict.RuleID == guard.OrgPromptJudgeRuleID {
		t.Fatalf("persisted %+v, want only the guard's own warn", persisted)
	}
}

func denyVerdict(reason string) guard.PromptVerdict {
	return guard.PromptVerdict{
		Verdict: policy.Verdict{Decision: policy.DecisionDeny, RuleID: "R-172", Reason: reason},
		Outcome: guard.PromptOutcomeBlocked,
	}
}

// TestOrgPromptJudgeAsksAboutAPartialPrompt (adm-2 fixes-1, H2): a prompt
// the guard could not read whole (the payload cut at the read bound, or the
// guard's scan stopped at its size bound) is still asked about, as Partial
// with no text, so a strict policy refuses it instead of skipping the judge.
func TestOrgPromptJudgeAsksAboutAPartialPrompt(t *testing.T) {
	const reason = "too large to judge"
	claude := `{"session_id":"s1","prompt":"build the release"}`
	cases := []struct {
		name          string
		body          string
		bodyTruncated bool
		scanTruncated bool
	}{
		{"payload cut at the read bound", `{"session_id":"s1","prompt":"build the rel`, true, false},
		{"guard scan stopped at its size bound", claude, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			jev := &judgingEvaluator{
				stubPromptEvaluator: stubPromptEvaluator{verdict: warnVerdict("partial scan"), truncated: tc.scanTruncated},
				judgement:           OrgPromptJudgement{Block: true, Reason: reason},
			}
			var out, errOut bytes.Buffer
			handled, _, code := HandlePromptSubmitGuarded("tool", PromptDialectClaudeCode, "UserPromptSubmit", []byte(tc.body), tc.bodyTruncated, jev, nil, &out, &errOut)
			if !handled || code != 2 {
				t.Fatalf("handled=%v code=%d, want the judge's block (stderr %q)", handled, code, errOut.String())
			}
			if len(jev.queries) != 1 || !jev.queries[0].Partial || jev.queries[0].Prompt != "" {
				t.Fatalf("queries %+v, want one Partial ask with no text", jev.queries)
			}
		})
	}
}

// TestHandlePromptSubmitOrgJudgeRows is the judge-only path (adm-2 fixes-1,
// H3): with the local prompt guard not evaluating, the organization's judge
// still runs on every prompt-gate dialect.
func TestHandlePromptSubmitOrgJudgeRows(t *testing.T) {
	const reason = "Prompt refused by your organization's coding-agent admission policy: off-topic"
	claude := `{"session_id":"s1","prompt":"build the release"}`
	kiro := `{"hook_event_name":"userPromptSubmit","cwd":"/w","session_id":"k1","prompt":"build the release"}`
	block := OrgPromptJudgement{Block: true, Reason: reason}
	cases := []struct {
		name          string
		dialect       string
		event         string
		body          string
		truncated     bool
		judge         *judgeOnly
		wantHandled   bool
		wantCode      int
		wantInOut     string
		wantAsked     bool
		wantPartial   bool
		wantPromptSet bool
	}{
		{name: "no judge: not handled", dialect: PromptDialectClaudeCode, event: "UserPromptSubmit", body: claude},
		{name: "judge allows: not handled, asked", dialect: PromptDialectClaudeCode, event: "UserPromptSubmit", body: claude, judge: &judgeOnly{}, wantAsked: true, wantPromptSet: true},
		{name: "judge blocks: claude-code exits 2 with the reason", dialect: PromptDialectClaudeCode, event: "UserPromptSubmit", body: claude, judge: &judgeOnly{judgement: block}, wantHandled: true, wantCode: 2, wantInOut: reason, wantAsked: true, wantPromptSet: true},
		{name: "judge blocks: top-level-block dialect", dialect: PromptDialectTopLevelBlock, event: "UserPromptSubmit", body: claude, judge: &judgeOnly{judgement: block}, wantHandled: true, wantCode: 2, wantInOut: `"decision":"block"`, wantAsked: true, wantPromptSet: true},
		{name: "judge blocks: cursor", dialect: PromptDialectCursor, event: "beforeSubmitPrompt", body: `{"conversation_id":"c1","prompt":"build the release"}`, judge: &judgeOnly{judgement: block}, wantHandled: true, wantInOut: `"continue":false`, wantAsked: true, wantPromptSet: true},
		{name: "warn-only seam: a warning, never a fake block", dialect: PromptDialectKiroCLI, event: "userPromptSubmit", body: kiro, judge: &judgeOnly{judgement: block}, wantHandled: true, wantInOut: "off-topic", wantAsked: true, wantPromptSet: true},
		{name: "payload cut at the read bound: asked as Partial", dialect: PromptDialectClaudeCode, event: "UserPromptSubmit", body: `{"session_id":"s1","prompt":"bu`, truncated: true, judge: &judgeOnly{judgement: block}, wantHandled: true, wantCode: 2, wantAsked: true, wantPartial: true},
		{name: "undecodable payload, not truncated: nothing asked", dialect: PromptDialectClaudeCode, event: "UserPromptSubmit", body: `not json`, judge: &judgeOnly{judgement: block}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var j OrgPromptJudge
			if tc.judge != nil {
				j = tc.judge
			}
			var out, errOut bytes.Buffer
			handled, _, code := HandlePromptSubmitOrgJudge("tool", tc.dialect, tc.event, []byte(tc.body), tc.truncated, j, &out, &errOut)
			if handled != tc.wantHandled || code != tc.wantCode {
				t.Fatalf("handled=%v code=%d, want %v %d (stdout %q stderr %q)", handled, code, tc.wantHandled, tc.wantCode, out.String(), errOut.String())
			}
			if tc.wantInOut != "" && !strings.Contains(out.String()+errOut.String(), tc.wantInOut) {
				t.Fatalf("output lacks %q: stdout %q stderr %q", tc.wantInOut, out.String(), errOut.String())
			}
			if tc.judge == nil {
				return
			}
			if asked := len(tc.judge.queries) > 0; asked != tc.wantAsked {
				t.Fatalf("asked=%v, want %v", asked, tc.wantAsked)
			}
			if !tc.wantAsked {
				return
			}
			q := tc.judge.queries[0]
			if q.Partial != tc.wantPartial || (q.Prompt == "build the release") != tc.wantPromptSet {
				t.Fatalf("query %+v, want partial=%v prompt set=%v", q, tc.wantPartial, tc.wantPromptSet)
			}
		})
	}
}
