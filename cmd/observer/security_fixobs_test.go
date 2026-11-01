//go:build !sbo_omit_security

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitlog"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestFixObsNeedsAComponentsBlock: an install with no [components] block
// (the legacy snapshot resolves security.code active) never starts the
// loop; a block selecting security.code does.
func TestFixObsNeedsAComponentsBlock(t *testing.T) {
	if fixObsSelected(componentstate.Legacy()) {
		t.Fatal("started with no [components] block")
	}
	if !fixObsSelected(componentstate.Resolve(config.ComponentsConfig{Add: []string{"security.code"}}, nil)) {
		t.Fatal("not started although security.code is selected")
	}
}

// fixObsSeed is one project with one session.
type fixObsSeed struct {
	st   *store.Store
	root string
	pid  int64
	sid  string
}

func newFixObsSeed(t *testing.T) *fixObsSeed {
	t.Helper()
	st, _ := openTestStore(t)
	root := t.TempDir()
	pid, err := st.UpsertProject(context.Background(), root, "")
	if err != nil {
		t.Fatal(err)
	}
	s := &fixObsSeed{st: st, root: root, pid: pid, sid: "s-fix"}
	if err := st.UpsertSession(context.Background(), models.Session{ID: s.sid, ProjectID: pid, Tool: models.ToolClaudeCode, StartedAt: time.Now().Add(-2 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	return s
}

// action stores one action and returns its id.
func (s *fixObsSeed) action(t *testing.T, kind, target, raw string, at time.Time, ok bool) int64 {
	t.Helper()
	ctx := context.Background()
	before, _ := s.st.MaxActionID(ctx)
	if _, err := s.st.InsertActions(ctx, []models.Action{{
		SessionID: s.sid, ProjectID: s.pid, Timestamp: at, ActionType: kind, Target: target, RawToolInput: raw,
		Success: ok, Tool: models.ToolClaudeCode, SourceFile: "f.jsonl", SourceEventID: kind + target + at.Format(time.RFC3339Nano),
	}}); err != nil {
		t.Fatal(err)
	}
	id, _ := s.st.MaxActionID(ctx)
	if id == before {
		t.Fatal("action not stored")
	}
	return id
}

// aiEdit stores an AI edit of rel with its file_changes row.
func (s *fixObsSeed) aiEdit(t *testing.T, rel string, at time.Time) {
	t.Helper()
	id := s.action(t, models.ActionEditFile, rel, `{"file_path":"`+rel+`","old_string":"a","new_string":"b"}`, at, true)
	if _, err := s.st.InsertFileChanges(context.Background(), []store.FileChangeRow{{
		SessionID: s.sid, ProjectID: s.pid, ActionID: id, FilePathHash: loc.PathHash(s.root, rel),
		Category: string(loc.CategoryCode), Actor: store.LOCActorAI, Confidence: string(loc.ConfidenceHigh),
		Source: store.LOCSourceEdit, Stats: loc.Stats{AddedCode: 1}, Version: loc.Version, SavedAt: at,
	}}); err != nil {
		t.Fatal(err)
	}
}

// TestInferEditRaisesFlagOnlyInferences: an agent edit adding a CSRF
// exemption in an auth file, under a prompt about the navbar, raises S-764
// and S-770, low confidence, never the prompt text.
func TestInferEditRaisesFlagOnlyInferences(t *testing.T) {
	s := newFixObsSeed(t)
	ctx := context.Background()
	now := time.Now().UTC()
	s.action(t, models.ActionUserPrompt, "make the NAVBARWORD blue", "", now.Add(-time.Minute), true)
	l := &fixObsLoop{st: s.st, logger: discardLogger(), started: now}
	l.inferNewEdits(ctx) // primes the watermark
	s.action(t, models.ActionEditFile, "auth/views.py", `{"file_path":"auth/views.py","old_string":"def login(r):","new_string":"@csrf_exempt\ndef login(r):"}`, now, true)
	l.inferNewEdits(ctx)
	got, err := s.st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: secposture.ProjectRootHash(s.root)})
	if err != nil {
		t.Fatal(err)
	}
	rules := map[string]secfinding.Finding{}
	for _, f := range got {
		rules[f.Rule.ID] = f
	}
	for _, want := range []string{"code.s-764", "code.s-770"} {
		f, ok := rules[want]
		if !ok {
			t.Fatalf("missing %s in %v", want, rules)
		}
		if f.Confidence != policy.FindingConfidenceLow || !strings.Contains(f.Message, "inference") || f.Lineage.SessionID != s.sid {
			t.Errorf("%s: %+v", want, f)
		}
		if strings.Contains(f.Message, "NAVBARWORD") {
			t.Errorf("prompt text stored: %q", f.Message)
		}
	}
	if rules["code.s-770"].Category != policy.FindingScopeDrift {
		t.Errorf("scope drift category: %s", rules["code.s-770"].Category)
	}
}

// closedFinding stores one finding at rel and closes it as not_reproduced
// at closedAt.
func (s *fixObsSeed) closedFinding(t *testing.T, rel string, closedAt time.Time) string {
	t.Helper()
	ctx := context.Background()
	f := secfinding.Normalize(secfinding.Finding{
		LocalKey: "k-" + rel, Rule: secfinding.Rule{ID: "python.sqli", Pack: "observer-code"}, Category: policy.FindingCodeVuln,
		Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceMedium, Baseline: policy.FindingBaselineNew,
		Project: secfinding.Project{RootHash: secposture.ProjectRootHash(s.root)}, Location: secfinding.Location{RelPath: rel, StartLine: 3},
		Message: "x", Status: policy.FindingStatusOpen,
	})
	id, _, err := s.st.UpsertSecFinding(ctx, f, closedAt.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := s.st.CloseSecFindingNotReproduced(ctx, id, closedAt); err != nil || !ok {
		t.Fatalf("close: %v %v", ok, err)
	}
	return id
}

func findingStatus(t *testing.T, st *store.Store, id string) secfinding.Status {
	t.Helper()
	got, err := st.ListSecFindings(context.Background(), store.SecFindingFilter{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range got {
		if f.ID == id {
			return f.Status
		}
	}
	t.Fatalf("no finding %s", id)
	return ""
}

// TestVerifyFixesMovesOnlyOnEvidence: an observed `go test` with exit 0
// after the last edit moves the not_reproduced finding to fixed_verified;
// a session that also edited a test file, and one with no test command,
// leave theirs not_reproduced.
func TestVerifyFixesMovesOnlyOnEvidence(t *testing.T) {
	now := time.Now().UTC()
	ctx := context.Background()

	s := newFixObsSeed(t)
	s.aiEdit(t, "app/db.py", now.Add(-30*time.Minute))
	s.action(t, models.ActionRunCommand, "go test ./...", "", now.Add(-20*time.Minute), true)
	id := s.closedFinding(t, "app/db.py", now.Add(-10*time.Minute))
	l := &fixObsLoop{st: s.st, logger: discardLogger(), started: now}
	l.verifyFixes(ctx, now)
	if got := findingStatus(t, s.st, id); got != policy.FindingStatusFixedVerified {
		t.Fatalf("status %s, want fixed_verified", got)
	}

	tampered := newFixObsSeed(t)
	tampered.aiEdit(t, "app/db.py", now.Add(-30*time.Minute))
	tampered.aiEdit(t, "tests/test_db.py", now.Add(-29*time.Minute))
	tampered.action(t, models.ActionRunCommand, "pytest -q", "", now.Add(-20*time.Minute), true)
	id2 := tampered.closedFinding(t, "app/db.py", now.Add(-10*time.Minute))
	(&fixObsLoop{st: tampered.st, logger: discardLogger(), started: now}).verifyFixes(ctx, now)
	if got := findingStatus(t, tampered.st, id2); got != policy.FindingStatusNotReproduced {
		t.Fatalf("test file edited: status %s", got)
	}

	silent := newFixObsSeed(t)
	silent.aiEdit(t, "app/db.py", now.Add(-30*time.Minute))
	silent.action(t, models.ActionRunCommand, "go build ./...", "", now.Add(-20*time.Minute), true)
	id3 := silent.closedFinding(t, "app/db.py", now.Add(-10*time.Minute))
	(&fixObsLoop{st: silent.st, logger: discardLogger(), started: now}).verifyFixes(ctx, now)
	if got := findingStatus(t, silent.st, id3); got != policy.FindingStatusNotReproduced {
		t.Fatalf("no test command: status %s", got)
	}
}

// TestFlagFixClaimsRaisesUnverifiedFix: a new commit whose subject claims
// a security fix for a file that still holds a finding raises one
// flag-only unverified_fix finding; a plain commit raises nothing.
func TestFlagFixClaimsRaisesUnverifiedFix(t *testing.T) {
	now := time.Now().UTC()
	ctx := context.Background()
	s := newFixObsSeed(t)
	s.closedFinding(t, "app/db.py", now.Add(-10*time.Minute))
	if _, err := s.st.UpsertCommits(ctx, s.pid, []commitlog.Commit{
		{SHA: strings.Repeat("a", 40), CommittedAt: now.Add(-5 * time.Minute), AuthoredAt: now.Add(-5 * time.Minute), Subject: "fix SQL injection in search", Files: []commitlog.CommitFile{{RelPath: "app/db.py", Added: 1}}},
		{SHA: strings.Repeat("b", 40), CommittedAt: now.Add(-4 * time.Minute), AuthoredAt: now.Add(-4 * time.Minute), Subject: "fix typo in README", Files: []commitlog.CommitFile{{RelPath: "app/db.py", Added: 1}}},
	}, now); err != nil {
		t.Fatal(err)
	}
	l := &fixObsLoop{st: s.st, logger: discardLogger(), started: now}
	l.flagFixClaims(ctx, now)
	l.flagFixClaims(ctx, now) // a second pass adds nothing
	got, _ := s.st.ListSecFindings(ctx, store.SecFindingFilter{Status: policy.FindingStatusOpen})
	var n int
	for _, f := range got {
		if f.Rule.ID == unverifiedFixRule {
			n++
			if f.Confidence != policy.FindingConfidenceLow || f.Severity != policy.FindingSeverityInfo || strings.Contains(f.Message, "injection") {
				t.Errorf("%+v", f)
			}
		}
	}
	if n != 1 {
		t.Fatalf("unverified_fix findings: %d, want 1", n)
	}
}

// TestUnverifiedFixWordingAndClosure: the unverified_fix message says only
// what the code checks (the claim and a finding still held at the file,
// never that no test ran), and the flag closes once the file holds no open
// or not_reproduced finding any more (audit finding 6), its own unpushed
// commit no longer holding it (lane SEC-P4 decision 13).
func TestUnverifiedFixWordingAndClosure(t *testing.T) {
	now := time.Now().UTC()
	ctx := context.Background()
	s := newFixObsSeed(t)
	held := s.closedFinding(t, "app/db.py", now.Add(-10*time.Minute))
	if _, err := s.st.UpsertCommits(ctx, s.pid, []commitlog.Commit{
		{SHA: strings.Repeat("c", 40), CommittedAt: now.Add(-5 * time.Minute), AuthoredAt: now.Add(-5 * time.Minute), Subject: "fix SQL injection in search", Files: []commitlog.CommitFile{{RelPath: "app/db.py", Added: 1}}},
	}, now); err != nil {
		t.Fatal(err)
	}
	l := &fixObsLoop{st: s.st, logger: discardLogger(), started: now}
	l.flagFixClaims(ctx, now)
	flagID := ""
	got, _ := s.st.ListSecFindings(ctx, store.SecFindingFilter{Status: policy.FindingStatusOpen})
	for _, f := range got {
		if f.Rule.ID == unverifiedFixRule {
			flagID = f.ID
			if strings.Contains(f.Message, "test command") || !strings.Contains(f.Message, "still holds a finding") {
				t.Errorf("message claims an unchecked fact: %q", f.Message)
			}
		}
	}
	if flagID == "" {
		t.Fatal("no unverified_fix finding")
	}
	l.settleFixClaims(ctx, now)
	if got := findingStatus(t, s.st, flagID); got != policy.FindingStatusOpen {
		t.Fatalf("closed while the file still holds a finding: %s", got)
	}
	if _, err := s.st.MarkSecFindingFixedVerified(ctx, held, "observed test command", secfinding.FixObservations{RuleNoLongerFires: true, TestCommandObserved: true}, now); err != nil {
		t.Fatal(err)
	}
	// A flag-only, non-secret finding is not held by its commit (lane
	// SEC-P4 decision 13): with the commit still unpushed, the settle step
	// closes it once the held finding gained its evidence.
	l.settleFixClaims(ctx, now)
	if got := findingStatus(t, s.st, flagID); got != policy.FindingStatusNotReproduced {
		t.Fatalf("flag not closed once the held finding gained its evidence: %s", got)
	}
	// A closed flag is never verified as a fix itself.
	l.verifyFixes(ctx, now)
	if got := findingStatus(t, s.st, flagID); got != policy.FindingStatusNotReproduced {
		t.Fatalf("a flag moved to %s", got)
	}
}

// TestVerifyFixesRecordsHostSuccessAsSuch: a test command recorded only as
// a successful action is "host reported success" in the closed event, never
// "exit code 0" (audit finding 5).
func TestVerifyFixesRecordsHostSuccessAsSuch(t *testing.T) {
	now := time.Now().UTC()
	ctx := context.Background()
	s := newFixObsSeed(t)
	s.aiEdit(t, "app/db.py", now.Add(-30*time.Minute))
	s.action(t, models.ActionRunCommand, "go test ./...", "", now.Add(-20*time.Minute), true)
	id := s.closedFinding(t, "app/db.py", now.Add(-10*time.Minute))
	root := s.root
	f := secfinding.Finding{ID: id, Location: secfinding.Location{RelPath: "app/db.py"}, ClosedAt: now.Add(-10 * time.Minute)}
	v, err := fixVerdict(ctx, s.st, root, f)
	if err != nil || !v.Verified || !v.HostReportedSuccess {
		t.Fatalf("verdict %+v %v", v, err)
	}
	if !strings.Contains(v.Detail(), "host reported success") || strings.Contains(v.Detail(), "exit code 0") {
		t.Fatalf("detail %q", v.Detail())
	}
}

func TestEditPairs(t *testing.T) {
	for raw, want := range map[string]int{
		`{"old_string":"a","new_string":"b"}`: 1,
		`{"content":"x"}`:                     1,
		`{"edits":[{"old_string":"a","new_string":"b"},{"old_str":"c","new_str":"d"}]}`: 2,
		`{"command":"ls"}`: 0,
		`not json`:         0,
	} {
		if got := len(editPairs(raw)); got != want {
			t.Errorf("%s: %d, want %d", raw, got, want)
		}
	}
}
