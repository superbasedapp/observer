package promptreg

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// refInCohort is the bucket formula of contract section 9.2 written out, so
// this package's tests need no repository import; promptstore's tests prove
// rolloutcore.InCohort gives the same answers.
func refInCohort(salt, subject string, pct int) bool {
	sum := sha256.Sum256([]byte(salt + "|" + subject))
	return int(binary.BigEndian.Uint32(sum[:4])%100) < pct
}

func TestPlanRollout(t *testing.T) {
	labels := LabelState{LabelProduction: 3}
	active := Rollouts{LabelProduction: {Version: 4, Percent: 20}}
	for _, tc := range []struct {
		name      string
		rollouts  Rollouts
		label     string
		candidate int
		pct       int
		err       error
		want      Move
	}{
		{"start", nil, LabelProduction, 4, 20, nil, Move{Label: LabelProduction, From: 3, To: 3, Rollout: true, RolloutVersion: 4, RolloutPercent: 20}},
		{"raise", active, LabelProduction, 4, 50, nil, Move{Label: LabelProduction, From: 3, To: 3, Rollout: true, RolloutVersion: 4, RolloutPercent: 50}},
		{"same", active, LabelProduction, 4, 20, ErrNoChange, Move{}},
		{"promote", active, LabelProduction, 4, 100, nil, Move{Label: LabelProduction, From: 3, To: 4}},
		{"end", active, LabelProduction, 0, 0, nil, Move{Label: LabelProduction, From: 3, To: 3, Rollout: true}},
		{"end nothing", nil, LabelProduction, 0, 0, ErrNoChange, Move{}},
		{"candidate is base", nil, LabelProduction, 3, 20, ErrBadRequest, Move{}},
		{"candidate missing", nil, LabelProduction, 9, 20, ErrVersionNotFound, Move{}},
		{"unset label", nil, LabelStaging, 4, 20, ErrLabelNotSet, Move{}},
		{"bad percent", nil, LabelProduction, 4, 101, ErrBadRequest, Move{}},
		{"bad label", nil, "latest", 4, 20, ErrBadRequest, Move{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := PlanRollout(labels, tc.rollouts, 5, tc.label, tc.candidate, tc.pct, "", t0)
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Fatalf("err = %v, want %v", err, tc.err)
				}
				return
			}
			tc.want.At = t0
			if err != nil || !reflect.DeepEqual(m, tc.want) {
				t.Fatalf("move = %+v, %v; want %+v", m, err, tc.want)
			}
		})
	}
	if _, err := PlanRollout(labels, nil, 0, LabelProduction, 4, 20, "", t0); !errors.Is(err, ErrPromptNotFound) {
		t.Fatalf("no prompt: %v", err)
	}
}

// TestRollbackMeansZeroPercent pins section 9.1: a rollback of a label with
// a rollout ends the rollout first; a rollout step is never a promotion; a
// promotion at 100% is one.
func TestRollbackMeansZeroPercent(t *testing.T) {
	labels, ro := LabelState{}, Rollouts{}
	var hist []Move
	apply := func(m Move, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		hist = append(hist, m)
		labels, ro = labels.Apply(m), ro.Apply(m)
	}
	apply(PlanMove(labels, 9, LabelProduction, 1, "", t0))
	apply(PlanMove(labels, 9, LabelProduction, 2, "", t0))
	apply(PlanRollout(labels, ro, 9, LabelProduction, 3, 10, "", t0))
	apply(PlanRollout(labels, ro, 9, LabelProduction, 3, 40, "", t0))
	m, err := PlanRollback(labels, ro, hist, LabelProduction, "", t0)
	if err != nil || !m.Rollback || !m.Rollout || m.To != 2 || m.RolloutPercent != 0 {
		t.Fatalf("rollback with a rollout = %+v, %v", m, err)
	}
	apply(m, nil)
	if ro.Active(LabelProduction) || labels[LabelProduction] != 2 {
		t.Fatalf("after: %v %v", labels, ro)
	}
	// The rollout steps are skipped: the next rollback walks back to 1.
	apply(PlanRollback(labels, ro, hist, LabelProduction, "", t0))
	if labels[LabelProduction] != 1 {
		t.Fatalf("walked back to %d", labels[LabelProduction])
	}
	// Promotion through 100% is a promotion rollback can undo.
	apply(PlanRollout(labels, ro, 9, LabelProduction, 5, 30, "", t0))
	apply(PlanRollout(labels, ro, 9, LabelProduction, 5, 100, "", t0))
	if labels[LabelProduction] != 5 || ro.Active(LabelProduction) {
		t.Fatalf("promote: %v %v", labels, ro)
	}
	apply(PlanRollback(labels, ro, hist, LabelProduction, "", t0))
	if labels[LabelProduction] != 1 {
		t.Fatalf("rollback of a promotion = %d", labels[LabelProduction])
	}
	// A move ends a rollout; moving to the base is no change.
	apply(PlanRollout(labels, ro, 9, LabelProduction, 6, 30, "", t0))
	if _, err := PlanMove(labels, 9, LabelProduction, 1, "", t0); !errors.Is(err, ErrNoChange) {
		t.Fatalf("move to base: %v", err)
	}
	apply(PlanMove(labels, 9, LabelProduction, 7, "", t0))
	if ro.Active(LabelProduction) {
		t.Fatal("a move must end the rollout")
	}
}

func TestParseCohortKey(t *testing.T) {
	u, s := strings.Repeat("a", 64), strings.Repeat("0", 64)
	for _, tc := range []struct {
		user, session string
		want          CohortKey
		bad           bool
	}{
		{"", "", CohortKey{}, false},
		{u, "", CohortKey{CohortKeyUser, u}, false},
		{"", s, CohortKey{CohortKeySession, s}, false},
		{u, s, CohortKey{CohortKeyUser, u}, false},
		{"abc", "", CohortKey{}, true},
		{strings.Repeat("A", 64), "", CohortKey{}, true},
		{"", strings.Repeat("g", 64), CohortKey{}, true},
	} {
		got, err := ParseCohortKey(tc.user, tc.session)
		if tc.bad != errors.Is(err, ErrBadRequest) || got != tc.want {
			t.Errorf("ParseCohortKey(%q, %q) = %+v, %v", tc.user, tc.session, got, err)
		}
	}
	if (CohortKey{}).Subject() != "" || (CohortKey{CohortKeyUser, u}).Subject() != "user:"+u {
		t.Fatal("subject")
	}
}

func TestResolveServed(t *testing.T) {
	labels := LabelState{LabelProduction: 3, LabelStaging: 4}
	ro := Rollouts{LabelProduction: {Version: 4, Percent: 50}}
	always := func(string, string, int) bool { return true }
	never := func(string, string, int) bool { return false }
	key := CohortKey{CohortKeyUser, strings.Repeat("b", 64)}
	prod := Selector{Label: LabelProduction}
	for _, tc := range []struct {
		name   string
		sel    Selector
		key    CohortKey
		in     CohortFunc
		want   int
		cohort string
	}{
		{"candidate", prod, key, always, 4, CohortCandidate},
		{"base", prod, key, never, 3, CohortBase},
		{"unkeyed", prod, CohortKey{}, always, 3, CohortUnkeyed},
		{"no engine", prod, key, nil, 3, CohortBase},
		{"no rollout", Selector{Label: LabelStaging}, key, always, 4, ""},
		{"version fetch", Selector{Version: 1}, key, always, 1, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, s, err := ResolveServed("p", tc.sel, 5, labels, ro, tc.key, tc.in)
			if err != nil || v != tc.want {
				t.Fatalf("served %d %v; want %d", v, err, tc.want)
			}
			if tc.cohort == "" {
				if s != nil {
					t.Fatalf("served record %+v for a fetch without a rollout", s)
				}
				return
			}
			if s == nil || s.Cohort != tc.cohort || s.BaseVersion != 3 || s.CandidateVersion != 4 || s.Percent != 50 || s.Salt != "prompt|p|production|4" {
				t.Fatalf("served record %+v", s)
			}
		})
	}
}

// TestRolloutCases runs the normative bucket fixture the SDKs share.
func TestRolloutCases(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "sdk", "contract", "prompt-rollout-cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			Salt, ID, Key, Hash, Subject string
			Percent, Bucket              int
			Candidate                    bool
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Cases) == 0 {
		t.Fatalf("fixture: %v", err)
	}
	for _, c := range doc.Cases {
		sum := sha256.Sum256([]byte(c.ID))
		if hex.EncodeToString(sum[:]) != c.Hash {
			t.Errorf("%s: hash", c.ID)
		}
		k, err := ParseCohortKey(map[bool]string{true: c.Hash}[c.Key == CohortKeyUser], map[bool]string{true: c.Hash}[c.Key == CohortKeySession])
		if err != nil || k.Subject() != c.Subject {
			t.Errorf("%s: subject %q, %v", c.ID, k.Subject(), err)
		}
		if got := refInCohort(c.Salt, c.Subject, c.Percent); got != c.Candidate {
			t.Errorf("%s at %d%%: in cohort %v, fixture %v", c.ID, c.Percent, got, c.Candidate)
		}
	}
}

func TestFetchServedKeepsV1Bytes(t *testing.T) {
	v, _ := NewVersion("p", 3, "", Draft{Prompt: json.RawMessage(`"hi"`)}, "u", t0)
	sel := Selector{Label: LabelProduction}
	a, err := Fetch(v, LabelState{LabelProduction: 3}, sel)
	if err != nil {
		t.Fatal(err)
	}
	b, err := FetchServed(v, LabelState{LabelProduction: 3}, sel, nil)
	if err != nil || string(a.Body) != string(b.Body) || strings.Contains(string(a.Body), "rollout") {
		t.Fatalf("nil served must keep the v1 body: %s", b.Body)
	}
	c, err := FetchServed(v, LabelState{LabelProduction: 3}, sel, &Served{BaseVersion: 3, CandidateVersion: 4, Percent: 20, Cohort: CohortBase, Key: CohortKeyUser, Salt: "s"})
	if err != nil || !strings.Contains(string(c.Body), `"rollout":{"base_version":3,"candidate_version":4,"percent":20,"cohort":"base","key":"user","salt":"s"}`) || c.ETag == a.ETag {
		t.Fatalf("served body %s", c.Body)
	}
}

func TestApprovalRows(t *testing.T) {
	on := Settings{RequireProductionApproval: true}
	cur := Rollouts{LabelProduction: {Version: 4, Percent: 40}}
	for _, tc := range []struct {
		name string
		s    Settings
		m    Move
		want bool
	}{
		{"staging never", on, Move{Label: LabelStaging, From: 1, To: 2}, false},
		{"setting off", Settings{}, Move{Label: LabelProduction, From: 1, To: 2}, false},
		{"rollback", on, Move{Label: LabelProduction, From: 2, To: 1, Rollback: true}, false},
		{"end rollout", on, Move{Label: LabelProduction, From: 3, To: 3, Rollout: true}, false},
		{"lower rollout", on, Move{Label: LabelProduction, From: 3, To: 3, Rollout: true, RolloutVersion: 4, RolloutPercent: 10}, false},
		{"raise rollout", on, Move{Label: LabelProduction, From: 3, To: 3, Rollout: true, RolloutVersion: 4, RolloutPercent: 60}, true},
		{"other candidate", on, Move{Label: LabelProduction, From: 3, To: 3, Rollout: true, RolloutVersion: 5, RolloutPercent: 10}, true},
		{"move", on, Move{Label: LabelProduction, From: 1, To: 2}, true},
		{"promote", on, Move{Label: LabelProduction, From: 3, To: 4}, true},
	} {
		if got := NeedsApproval(tc.s, cur, tc.m); got != tc.want {
			t.Errorf("%s: NeedsApproval = %v, want %v", tc.name, got, tc.want)
		}
	}
	if len(approvalRows) != 6 {
		t.Fatalf("one case per row: %d rows", len(approvalRows))
	}
}

func TestProposalLifecycle(t *testing.T) {
	labels := LabelState{LabelProduction: 2}
	p, err := NewProposal("id1", "p", labels, nil, 3, ChangeMove, LabelProduction, 3, 0, "ship it", "alice", t0)
	if err != nil || p.Status != ProposalPending || p.BaseVersion != 2 || p.ProposedBy != "alice" {
		t.Fatalf("proposal %+v, %v", p, err)
	}
	if _, err := NewProposal("id2", "p", labels, nil, 3, ChangeMove, LabelProduction, 2, 0, "", "alice", t0); !errors.Is(err, ErrNoChange) {
		t.Fatalf("a no-change proposal must be refused: %v", err)
	}
	if _, err := NewProposal("id2", "p", labels, nil, 3, "delete", LabelProduction, 2, 0, "", "alice", t0); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("bad kind: %v", err)
	}
	if _, err := PlanApprove(p, labels, nil, 3, "alice", "", t0); !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("self approval: %v", err)
	}
	if _, err := PlanApprove(p, labels, nil, 3, "", "", t0); !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("anonymous approval: %v", err)
	}
	d, err := PlanApprove(p, labels, nil, 3, "bob", "ok", t0)
	if err != nil || !d.Apply || d.Proposal.Status != ProposalApproved || d.Move.To != 3 || d.Move.Actor != "bob" || d.Proposal.DecidedBy != "bob" {
		t.Fatalf("approve %+v, %v", d, err)
	}
	if _, err := PlanApprove(d.Proposal, labels, nil, 3, "carol", "", t0); !errors.Is(err, ErrProposalClosed) {
		t.Fatalf("approve twice: %v", err)
	}
	// Stale: the label moved since.
	d, err = PlanApprove(p, LabelState{LabelProduction: 1}, nil, 3, "bob", "", t0)
	if err != nil || d.Apply || d.Proposal.Status != ProposalStale {
		t.Fatalf("stale %+v, %v", d, err)
	}
	// A rollout proposal snapshots the rollout; a percent change is stale.
	ro := Rollouts{LabelProduction: {Version: 3, Percent: 10}}
	rp, err := NewProposal("id3", "p", labels, ro, 3, ChangeRollout, LabelProduction, 3, 50, "", "alice", t0)
	if err != nil || rp.BaseRolloutVersion != 3 || rp.BaseRolloutPercent != 10 {
		t.Fatalf("rollout proposal %+v, %v", rp, err)
	}
	if d, _ := PlanApprove(rp, labels, Rollouts{LabelProduction: {Version: 3, Percent: 20}}, 3, "bob", "", t0); d.Apply || d.Proposal.Status != ProposalStale {
		t.Fatalf("rollout stale %+v", d)
	}
	if d, _ := PlanApprove(rp, labels, ro, 3, "bob", "", t0); !d.Apply || d.Move.RolloutPercent != 50 {
		t.Fatalf("rollout approve %+v", d)
	}
	r, err := PlanReject(p, "alice", "withdrawn", t0)
	if err != nil || r.Status != ProposalRejected || r.DecidedBy != "alice" {
		t.Fatalf("reject %+v, %v", r, err)
	}
	if _, err := PlanReject(r, "bob", "", t0); !errors.Is(err, ErrProposalClosed) {
		t.Fatalf("reject twice: %v", err)
	}
	if _, err := PlanReject(p, "bob", strings.Repeat("x", MaxNoteBytes+1), t0); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("long note: %v", err)
	}
	if v := rp.View(); v.Summary != "production: 50% on version 3" || v.ProposedAt != "2026-11-19T10:00:00Z" {
		t.Fatalf("view %+v", v)
	}
	for _, tc := range []struct {
		kind         string
		version, pct int
		want         string
	}{
		{ChangeMove, 4, 0, "production -> version 4"},
		{ChangeRollout, 4, 100, "production: promote version 4"},
		{ChangeRollout, 0, 0, "production: end the rollout"},
	} {
		if got := ChangeSummary(LabelProduction, tc.kind, tc.version, tc.pct); got != tc.want {
			t.Errorf("summary %q, want %q", got, tc.want)
		}
	}
}

func TestDiffText(t *testing.T) {
	ops := func(ls []DiffLine) string {
		var b strings.Builder
		for _, l := range ls {
			b.WriteString(map[string]string{DiffEqual: " ", DiffAdd: "+", DiffRemove: "-"}[l.Op] + l.Text + ";")
		}
		return b.String()
	}
	for _, tc := range []struct{ a, b, want string }{
		{"", "", ""},
		{"a", "a", " a;"},
		{"a\nb\nc", "a\nx\nc", " a;-b;+x; c;"},
		{"a\nb", "a\nb\nc", " a; b;+c;"},
		{"x\na\nb", "a\nb", "-x; a; b;"},
		{"", "new", "+new;"},
		{"a\nb\nc\nd", "a\nc\nb\nd", " a;-b; c;+b; d;"},
	} {
		got, approx := DiffText(tc.a, tc.b)
		if ops(got) != tc.want || approx {
			t.Errorf("DiffText(%q, %q) = %q (approx %v), want %q", tc.a, tc.b, ops(got), approx, tc.want)
		}
	}
	// Past the cell bound the middle is replaced whole, the ends stay exact.
	big := func(p string) string {
		ls := make([]string, 1100)
		for i := range ls {
			ls[i] = p + itoa(i)
		}
		return "head\n" + strings.Join(ls, "\n") + "\ntail"
	}
	got, approx := DiffText(big("a"), big("b"))
	if !approx || got[0] != (DiffLine{DiffEqual, "head"}) || got[len(got)-1] != (DiffLine{DiffEqual, "tail"}) || len(got) != 2202 {
		t.Fatalf("approximate diff: %v, %d lines", approx, len(got))
	}
}

func TestDiffVersions(t *testing.T) {
	mk := func(n int, typ Type, body, config string) Version {
		v, err := NewVersion("p", n, "", Draft{Type: typ, Prompt: json.RawMessage(body), Config: json.RawMessage(config)}, "u", t0)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	a := mk(1, TypeText, `"Hi {{name}}\nBye"`, `{"model":"m1","temperature":0.2,"stop":["x"]}`)
	b := mk(2, TypeText, `"Hi {{name}}, {{topic}}\nBye"`, `{"model":"m2","stop":["x"],"top_p":1}`)
	d, err := Diff(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if d.Identical || d.FromVersion != 1 || d.ToVersion != 2 || len(d.Lines) != 3 || d.Lines[0].Op != DiffRemove {
		t.Fatalf("text diff %+v", d)
	}
	if !reflect.DeepEqual(d.VariablesAdded, []string{"topic"}) || len(d.VariablesRemoved) != 0 {
		t.Fatalf("variables %+v / %+v", d.VariablesAdded, d.VariablesRemoved)
	}
	var keys []string
	for _, c := range d.Config {
		keys = append(keys, c.Key+":"+c.Status)
	}
	if !reflect.DeepEqual(keys, []string{"model:changed", "temperature:removed", "top_p:added"}) {
		t.Fatalf("config %v", keys)
	}
	same, err := Diff(a, mk(3, TypeText, `"Hi {{name}}\nBye"`, `{"model":"m1","temperature":0.2,"stop":["x"]}`))
	if err != nil || !same.Identical || len(same.Config) != 0 {
		t.Fatalf("identical %+v, %v", same, err)
	}
	c1 := mk(1, TypeChat, `[{"role":"system","content":"S"},{"role":"user","content":"{{q}}"}]`, "")
	c2 := mk(2, TypeChat, `[{"role":"developer","content":"S"},{"role":"user","content":"{{q}}"},{"role":"assistant","content":"ok"}]`, "")
	cd, err := Diff(c1, c2)
	if err != nil || len(cd.Messages) != 3 || cd.Messages[0].Status != "changed" || cd.Messages[0].FromRole != "system" ||
		cd.Messages[1].Status != "same" || cd.Messages[2].Status != "added" {
		t.Fatalf("chat diff %+v, %v", cd, err)
	}
	if _, err := Diff(a, c2); !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("type mismatch: %v", err)
	}
	for _, tc := range []struct {
		from, to string
		f, t     int
		bad      bool
	}{
		{"", "3", 2, 3, false}, {"1", "3", 1, 3, false}, {"", "1", 0, 0, true}, {"x", "2", 0, 0, true}, {"1", "", 0, 0, true},
	} {
		f, to, err := ParseDiffQuery(tc.from, tc.to)
		if tc.bad != (err != nil) || f != tc.f || to != tc.t {
			t.Errorf("ParseDiffQuery(%q, %q) = %d %d %v", tc.from, tc.to, f, to, err)
		}
	}
}

func TestRolloutsApplyAndSummaries(t *testing.T) {
	ro := Rollouts{}.Apply(Move{Label: LabelProduction, Rollout: true, RolloutVersion: 4, RolloutPercent: 20})
	if !ro.Active(LabelProduction) {
		t.Fatal("apply start")
	}
	if ro.Apply(Move{Label: LabelProduction, From: 3, To: 5}).Active(LabelProduction) {
		t.Fatal("a move ends it")
	}
	b, err := List([]Summary{{Name: "a", Rollouts: ro}, {Name: "b", Rollouts: Rollouts{}}}, ListQuery{Limit: 10})
	if err != nil || !strings.Contains(string(b), `"rollouts":{"production":{"version":4,"percent":20}}`) || strings.Count(string(b), "rollouts") != 1 {
		t.Fatalf("list %s", b)
	}
	v, _ := NewVersion("p", 1, "", Draft{Prompt: json.RawMessage(`"x"`)}, "u", t0)
	v2, _ := NewVersion("p", 2, TypeText, Draft{Prompt: json.RawMessage(`"y"`)}, "u", t0)
	d, err := Detail("p", []Version{v, v2}, LabelState{LabelProduction: 1}, Rollouts{LabelProduction: {2, 30}}, nil)
	if err != nil || d.Rollouts[LabelProduction].Percent != 30 || d.RollbackTargets[LabelProduction] != 1 {
		t.Fatalf("detail %+v, %v", d, err)
	}
}
