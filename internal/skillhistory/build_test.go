package skillhistory

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guidance"
)

const (
	cc    = "claude-code"
	codex = "codex"
	blobA = "aaaaaaaa11111111111111111111111111111111"
	blobB = "bbbbbbbb22222222222222222222222222222222"
	blobC = "cccccccc33333333333333333333333333333333"
	sha1c = "1111111111111111111111111111111111111111"
	sha2c = "2222222222222222222222222222222222222222"
	sha3c = "3333333333333333333333333333333333333333"
	sha4c = "4444444444444444444444444444444444444444"
	skMD  = ".claude/skills/deploy/SKILL.md"
	skKey = "project:.claude/skills/deploy"
)

var t0 = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

func at(min int) time.Time { return t0.Add(time.Duration(min) * time.Minute) }

// base returns an Input with the real discovery table, claude-code as the
// snapshot-capable and invocation-measurable tool, a scanned git state,
// one present project skill, and HEAD at sha1c whose tree holds blobA.
func base() Input {
	return Input{
		Rules:                guidance.Rules(),
		SnapshotEmitters:     map[string]bool{cc: true},
		InvocationMeasurable: map[string]bool{cc: true},
		Git:                  GitState{Scanned: true, HeadSHA: sha1c, ReflogSince: at(-1000)},
		Inventory:            []InventoryFile{{Scope: ScopeProject, RelPath: skMD, Name: "deploy", Present: true}},
		Trees:                []Tree{{SHA: sha1c, State: TreeOK, Files: map[string]TreeFile{skMD: {Mode: "100644", BlobOID: blobA}}}},
		HeadMoves:            []HeadMove{{MovedAt: at(-500), SHA: sha1c, Kind: "commit"}},
	}
}

func snap(session string, min int, members ...Member) Snapshot {
	return Snapshot{
		SessionID: session, Tool: cc, Event: EventSessionStart, Source: "startup",
		ObservedAt: at(min), Complete: true, HomeResolved: true, Members: members,
	}
}

func mem(blob string) Member {
	return Member{Scope: ScopeProject, RelPath: skMD, Name: "deploy", State: MemberPresent, BlobOID: blob}
}

func findSkill(t *testing.T, r Result, key string) Skill {
	t.Helper()
	for _, s := range r.Skills {
		if s.Key == key {
			return s
		}
	}
	t.Fatalf("skill %q not in result: %+v", key, r.Skills)
	return Skill{}
}

// spanFor returns the span covering session id for skill key.
func spanFor(t *testing.T, r Result, key, session string) Span {
	t.Helper()
	ids := map[string]time.Time{}
	for _, s := range r.Sessions {
		ids[s.ID] = s.StartedAt
	}
	st := ids[session]
	for _, sp := range r.Spans {
		if sp.SkillKey == key && !st.Before(sp.From) && !st.After(sp.To) {
			return sp
		}
	}
	t.Fatalf("no span for %s/%s in %+v", key, session, r.Spans)
	return Span{}
}

func TestPathspecsAndToolsReading(t *testing.T) {
	rules := guidance.Rules()
	if got := Pathspecs(rules); !reflect.DeepEqual(got, []string{".claude/skills"}) {
		t.Errorf("Pathspecs = %v, want [.claude/skills]", got)
	}
	cases := []struct {
		rel       string
		wantTools []string
		isSkill   bool
	}{
		{skMD, []string{cc}, true},
		{".claude/skills/deploy/scripts/run.sh", []string{cc}, true},
		{"~/.claude/skills/x/SKILL.md", []string{cc}, false},
		{".claude/skills/SKILL.md", nil, false},
		{"src/main.go", nil, false},
	}
	for _, c := range cases {
		if got := ToolsReading(c.rel, rules); !reflect.DeepEqual(got, c.wantTools) {
			t.Errorf("ToolsReading(%q) = %v, want %v", c.rel, got, c.wantTools)
		}
		if got := IsSkillPath(c.rel, rules); got != c.isSkill {
			t.Errorf("IsSkillPath(%q) = %v, want %v", c.rel, got, c.isSkill)
		}
	}
}

// TestObservedRules has one case per row of observedRules plus each
// branch of the snapshot-resolution row.
func TestObservedRules(t *testing.T) {
	cases := []struct {
		name    string
		tool    string
		mutate  func(*Input)
		want    string
		version string
		changed []string
	}{
		{"n/a: tool does not read the path", codex, nil, ObsNotApplicable, "", nil},
		{"not measurable: no snapshot capability", cc, func(in *Input) { in.SnapshotEmitters = nil }, ObsNotMeasurable, "", nil},
		{"not captured: no snapshot", cc, nil, ObsNotCaptured, "", nil},
		{"observed", cc, func(in *Input) { in.Snapshots = []Snapshot{snap("s1", 0, mem(blobA))} }, ObsObserved, "aaaaaaaa", nil},
		{"absent from a complete snapshot", cc, func(in *Input) { in.Snapshots = []Snapshot{snap("s1", 0)} }, ObsAbsent, "", nil},
		{"unknown: incomplete snapshot without the file", cc, func(in *Input) {
			sn := snap("s1", 0)
			sn.Complete = false
			in.Snapshots = []Snapshot{sn}
		}, ObsUnknown, "", nil},
		{"unknown: unreadable member", cc, func(in *Input) {
			m := mem("")
			m.State = MemberUnreadable
			in.Snapshots = []Snapshot{snap("s1", 0, m)}
		}, ObsUnknown, "", nil},
		{"not captured: sub-agent (never fires SessionStart)", cc, func(in *Input) {
			in.Sessions[0].Relation = RelationSubagent
		}, ObsNotCaptured, "", nil},
		{"first snapshot is a resume long after the start", cc, func(in *Input) {
			sn := snap("s1", 90, mem(blobA))
			sn.Source = "resume"
			in.Snapshots = []Snapshot{sn}
		}, ObsAfterStart, "aaaaaaaa", nil},
		{"compact snapshot within the margin still counts as the start", cc, func(in *Input) {
			sn := snap("s1", 1, mem(blobA))
			sn.Source = "compact"
			in.Snapshots = []Snapshot{sn}
		}, ObsObserved, "aaaaaaaa", nil},
		{"changed during session (resume)", cc, func(in *Input) {
			in.Snapshots = []Snapshot{snap("s1", 0, mem(blobA)), snap("s1", 30, mem(blobB))}
		}, ObsChanged, "aaaaaaaa", []string{"aaaaaaaa", "bbbbbbbb"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := base()
			in.Sessions = []Session{{ID: "s1", Tool: c.tool, StartedAt: at(0)}}
			if c.mutate != nil {
				c.mutate(&in)
			}
			r := Build(in)
			if c.want == ObsNotCaptured && in.Sessions[0].Relation == RelationSubagent {
				if sp := spanFor(t, r, skKey, "s1"); sp.Observed.Reason != ObsReasonSubagent {
					t.Errorf("sub-agent observed = %+v, want reason %s", sp.Observed, ObsReasonSubagent)
				}
			}
			if c.want == ObsAfterStart {
				if sp := spanFor(t, r, skKey, "s1"); sp.Observed.Source != "resume" {
					t.Errorf("after-start observed = %+v, want source resume", sp.Observed)
				}
				for _, v := range findSkill(t, r, skKey).Versions {
					if v.SessionsAvailable != 0 {
						t.Errorf("after-start snapshot counted as available at start: %+v", v)
					}
				}
			}
			if c.want == ObsNotApplicable {
				// A tool that does not read the skill says nothing about
				// it: its sessions neither join nor break a span.
				if len(r.Spans) != 0 || len(r.Sessions) != 1 {
					t.Errorf("n/a session: spans=%+v sessions=%+v, want no span and the session listed", r.Spans, r.Sessions)
				}
				return
			}
			sp := spanFor(t, r, skKey, "s1")
			if sp.Observed.State != c.want || sp.Observed.Version != c.version || !reflect.DeepEqual(sp.Observed.Changed, c.changed) {
				t.Errorf("observed = %+v, want state=%s version=%s changed=%v", sp.Observed, c.want, c.version, c.changed)
			}
		})
	}
}

func TestObservedHomeUnresolved(t *testing.T) {
	in := base()
	in.Inventory = append(in.Inventory, InventoryFile{Scope: ScopeUser, RelPath: "~/.claude/skills/tidy/SKILL.md", Name: "tidy", Present: true})
	sn := snap("s1", 0, mem(blobA))
	sn.HomeResolved = false
	in.Snapshots = []Snapshot{sn}
	in.Sessions = []Session{{ID: "s1", Tool: cc, StartedAt: at(0)}}
	r := Build(in)
	sp := spanFor(t, r, "user:~/.claude/skills/tidy", "s1")
	if sp.Observed.State != ObsHomeUnresolved {
		t.Errorf("home skill with unresolved home = %+v, want %s", sp.Observed, ObsHomeUnresolved)
	}
	if sp.Head.State != HeadNotInProjectGit {
		t.Errorf("home skill head = %+v, want %s", sp.Head, HeadNotInProjectGit)
	}
}

// TestHeadRules has one case per row of headRules plus each branch of
// the tree-resolution row.
func TestHeadRules(t *testing.T) {
	cases := []struct {
		name    string
		tool    string
		mutate  func(*Input)
		want    string
		version string
		reason  string
	}{
		{"n/a: tool does not read the path", codex, nil, HeadNotApplicable, "", ""},
		{"git not scanned", cc, func(in *Input) { in.Git.Scanned = false }, HeadGitUnavailable, "", "not_scanned"},
		{"a later step failure does not blank captured history", cc, func(in *Input) { in.Git.LastError = "reflog: timeout" }, HeadCommitted, "aaaaaaaa", ""},
		{"reflog has nothing before the start", cc, func(in *Input) {
			in.HeadMoves = []HeadMove{{MovedAt: at(60), SHA: sha1c}}
		}, HeadReflogUnavailable, "", ""},
		{"head moved near the start", cc, func(in *Input) {
			in.HeadMoves = append(in.HeadMoves, HeadMove{MovedAt: at(1), SHA: sha2c})
		}, HeadMovedNearStart, "", HeadReasonSkew},
		{"checkout within the margin BEFORE the start", cc, func(in *Input) {
			in.HeadMoves = append(in.HeadMoves, HeadMove{MovedAt: at(0).Add(-30 * time.Second), SHA: sha2c, Kind: "checkout"})
		}, HeadMovedNearStart, "", HeadReasonSkew},
		{"several shas in the chosen reflog second", cc, func(in *Input) {
			in.HeadMoves = []HeadMove{
				{MovedAt: at(-100), SHA: sha1c, Kind: "rebase", Seq: 1},
				{MovedAt: at(-100), SHA: sha2c, Kind: "rebase", Seq: 2},
			}
		}, HeadMovedNearStart, "", HeadReasonSameSecond},
		{"tree pending", cc, func(in *Input) { in.Trees = nil }, HeadPending, "", ""},
		{"commit unavailable", cc, func(in *Input) { in.Trees = []Tree{{SHA: sha1c, State: TreeMissing}} }, HeadCommitUnavailable, "", ""},
		{"absent in the commit", cc, func(in *Input) {
			in.Trees = []Tree{{SHA: sha1c, State: TreeOK, Files: map[string]TreeFile{}}}
		}, HeadAbsentInCommit, "", ""},
		{"committed", cc, nil, HeadCommitted, "aaaaaaaa", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := base()
			in.Sessions = []Session{{ID: "s1", Tool: c.tool, StartedAt: at(0)}}
			if c.mutate != nil {
				c.mutate(&in)
			}
			r := Build(in)
			if c.want == HeadNotApplicable {
				if len(r.Spans) != 0 {
					t.Errorf("n/a session: spans=%+v, want none", r.Spans)
				}
				return
			}
			sp := spanFor(t, r, skKey, "s1")
			if sp.Head.State != c.want || sp.Head.Version != c.version || sp.Head.Reason != c.reason {
				t.Errorf("head = %+v, want state=%s version=%s reason=%s", sp.Head, c.want, c.version, c.reason)
			}
		})
	}
}

func TestHeadMovedNearStartCellCarriesCandidates(t *testing.T) {
	in := base()
	in.HeadMoves = append(in.HeadMoves, HeadMove{MovedAt: at(1), SHA: sha2c})
	in.Sessions = []Session{{ID: "s1", Tool: cc, StartedAt: at(0)}}
	r := Build(in)
	if len(r.Cells) != 1 || !reflect.DeepEqual(r.Cells[0].Head.Candidates, []string{"11111111", "22222222"}) {
		t.Fatalf("cells = %+v, want one head_moved_near_start cell with both candidates", r.Cells)
	}
}

func TestTimelineChain(t *testing.T) {
	in := base()
	sib := ".claude/skills/deploy/ref.md"
	in.Timeline = []TimelineCommit{
		{SHA: sha1c, CommittedAt: at(-400), Subject: "add", Reachable: true, Files: []string{skMD, sib}},
		{SHA: sha2c, CommittedAt: at(-300), Subject: "edit", Reachable: true, Files: []string{skMD}},
		{SHA: "5555555555555555555555555555555555555555", CommittedAt: at(-250), Subject: "rebased away", Reachable: false, Files: []string{skMD}},
		{SHA: sha3c, CommittedAt: at(-200), Subject: "sibling only", Reachable: true, Files: []string{sib}},
		{SHA: sha4c, CommittedAt: at(-100), Subject: "revert", Reachable: true, Files: []string{skMD}},
		{SHA: "6666666666666666666666666666666666666666", CommittedAt: at(-50), Subject: "unresolved", Reachable: true, Files: []string{skMD}},
	}
	in.Trees = []Tree{
		{SHA: sha1c, State: TreeOK, Files: map[string]TreeFile{skMD: {BlobOID: blobA}}},
		{SHA: sha2c, State: TreeOK, Files: map[string]TreeFile{skMD: {BlobOID: blobB}}},
		{SHA: "5555555555555555555555555555555555555555", State: TreeOK, Files: map[string]TreeFile{skMD: {BlobOID: blobC}}},
		{SHA: sha3c, State: TreeOK, Files: map[string]TreeFile{skMD: {BlobOID: blobB}}},
		{SHA: sha4c, State: TreeOK, Files: map[string]TreeFile{skMD: {BlobOID: blobA}}},
	}
	in.Git.HeadSHA = sha4c
	r := Build(in)
	sk := findSkill(t, r, skKey)
	var statuses []string
	for _, c := range sk.Commits {
		statuses = append(statuses, c.Status+"/"+c.Version)
	}
	want := []string{"A/aaaaaaaa", "M/bbbbbbbb", "M/cccccccc", "/", "M/aaaaaaaa", "?/"}
	if !reflect.DeepEqual(statuses, want) {
		t.Errorf("commit statuses = %v, want %v", statuses, want)
	}
	if sk.Commits[3].SkillMDChanged || sk.Commits[3].Files != 1 {
		t.Errorf("sibling-only commit = %+v, want SkillMDChanged=false Files=1", sk.Commits[3])
	}
	byID := map[string]Version{}
	for _, v := range sk.Versions {
		byID[v.ID] = v
	}
	if v := byID["aaaaaaaa"]; v.IntroducedBy == nil || v.IntroducedBy.SHA != sha1c || !reflect.DeepEqual(v.ReintroducedIn, []string{sha4c}) || v.Ordinal != 1 {
		t.Errorf("version A = %+v, want introduced by sha1c, reintroduced in sha4c, ordinal 1", v)
	}
	if v := byID["cccccccc"]; v.IntroducedBy != nil {
		t.Errorf("unreachable-only version = %+v, want no introducing commit", v)
	}
	if sk.Current.InGit != GitCommitted || sk.Current.HeadVersion != "aaaaaaaa" {
		t.Errorf("current = %+v, want committed at aaaaaaaa", sk.Current)
	}
}

func TestExactContentMove(t *testing.T) {
	in := base()
	newMD := ".claude/skills/ship/SKILL.md"
	in.Inventory = []InventoryFile{{Scope: ScopeProject, RelPath: newMD, Name: "ship", Present: true}}
	in.Timeline = []TimelineCommit{
		{SHA: sha1c, CommittedAt: at(-400), Reachable: true, Files: []string{skMD}},
		{SHA: sha2c, CommittedAt: at(-300), Reachable: true, Files: []string{skMD, newMD}},
	}
	in.Trees = []Tree{
		{SHA: sha1c, State: TreeOK, Files: map[string]TreeFile{skMD: {BlobOID: blobA}}},
		{SHA: sha2c, State: TreeOK, Files: map[string]TreeFile{newMD: {BlobOID: blobA}}},
	}
	in.Git.HeadSHA = sha2c
	r := Build(in)
	ship := findSkill(t, r, "project:.claude/skills/ship")
	if ship.MovedFrom == nil || ship.MovedFrom.FromDir != ".claude/skills/deploy" || ship.MovedFrom.SHA != sha2c {
		t.Errorf("MovedFrom = %+v, want from .claude/skills/deploy in sha2c", ship.MovedFrom)
	}
	old := findSkill(t, r, skKey)
	if old.Current.InGit != GitRemoved || old.Commits[1].Status != "D" {
		t.Errorf("old skill = current %+v, commits %+v; want removed + D", old.Current, old.Commits)
	}
}

func TestMoveNeedsIdenticalBlob(t *testing.T) {
	in := base()
	newMD := ".claude/skills/ship/SKILL.md"
	in.Timeline = []TimelineCommit{
		{SHA: sha1c, CommittedAt: at(-400), Reachable: true, Files: []string{skMD}},
		{SHA: sha2c, CommittedAt: at(-300), Reachable: true, Files: []string{skMD, newMD}},
	}
	in.Trees = []Tree{
		{SHA: sha1c, State: TreeOK, Files: map[string]TreeFile{skMD: {BlobOID: blobA}}},
		{SHA: sha2c, State: TreeOK, Files: map[string]TreeFile{newMD: {BlobOID: blobB}}},
	}
	r := Build(in)
	if ship := findSkill(t, r, "project:.claude/skills/ship"); ship.MovedFrom != nil {
		t.Errorf("a different-content add must not be linked as a move: %+v", ship.MovedFrom)
	}
}

func TestCRLFMatchesCommittedContent(t *testing.T) {
	in := base()
	m := mem("dddddddd44444444444444444444444444444444")
	m.BlobOIDLF = blobA
	in.Snapshots = []Snapshot{snap("s1", 0, m)}
	in.Sessions = []Session{{ID: "s1", Tool: cc, StartedAt: at(0)}}
	r := Build(in)
	sp := spanFor(t, r, skKey, "s1")
	if sp.Observed.Version != "aaaaaaaa" || !sp.Observed.LineEndings {
		t.Errorf("observed = %+v, want the LF blob with LineEndings", sp.Observed)
	}
	sk := findSkill(t, r, skKey)
	if len(sk.Versions) != 1 {
		t.Errorf("versions = %+v, want the CRLF copy folded onto the committed version", sk.Versions)
	}
}

func TestContentNotInAnyCommit(t *testing.T) {
	in := base()
	in.Snapshots = []Snapshot{snap("s1", 0, mem(blobC))}
	in.Sessions = []Session{{ID: "s1", Tool: cc, StartedAt: at(0)}}
	r := Build(in)
	sk := findSkill(t, r, skKey)
	for _, v := range sk.Versions {
		if v.BlobOID == blobC && v.InCommits {
			t.Errorf("observed-only version marked InCommits: %+v", v)
		}
	}
	// observed != head -> the cell is emitted individually.
	if len(r.Cells) != 1 || r.Cells[0].Observed.Version != "cccccccc" || r.Cells[0].Head.Version != "aaaaaaaa" {
		t.Errorf("cells = %+v, want one cell showing observed cccccccc vs HEAD aaaaaaaa", r.Cells)
	}
}

func TestInvocations(t *testing.T) {
	in := base()
	in.Inventory = append(in.Inventory, InventoryFile{Scope: ScopeUser, RelPath: "~/.claude/skills/deploy/SKILL.md", Name: "deploy", Present: true},
		InventoryFile{Scope: ScopeProject, RelPath: ".claude/skills/lint/SKILL.md", Name: "lint", Present: true})
	lintMD := ".claude/skills/lint/SKILL.md"
	invSnap := Snapshot{
		SessionID: "s1", Tool: cc, Event: EventSkillInvoke, ToolUseID: "tu1", ObservedAt: at(5), Complete: true, HomeResolved: true,
		Members: []Member{{Scope: ScopeProject, RelPath: lintMD, State: MemberPresent, BlobOID: blobB}},
	}
	in.Snapshots = []Snapshot{invSnap}
	in.Sessions = []Session{{ID: "s1", Tool: cc, StartedAt: at(0)}, {ID: "s2", Tool: codex, StartedAt: at(10)}}
	in.Invocations = []Invocation{
		{SessionID: "s1", Tool: cc, Name: "lint", ToolUseID: "tu1", At: at(5)},
		{SessionID: "s1", Tool: cc, Name: "lint", ToolUseID: "tu2", At: at(6)},
		{SessionID: "s1", Tool: cc, Name: "deploy", ToolUseID: "tu3", At: at(7)},
		{SessionID: "s1", Tool: cc, Name: "superpowers:brainstorm", ToolUseID: "tu4", At: at(8)},
	}
	r := Build(in)
	lint := findSkill(t, r, "project:.claude/skills/lint")
	if lint.Invocations.Count != 2 || !lint.Invocations.Measurable {
		t.Errorf("lint invocations = %+v, want 2 measurable", lint.Invocations)
	}
	var cell *Cell
	for i := range r.Cells {
		if r.Cells[i].SkillKey == lint.Key && r.Cells[i].SessionID == "s1" {
			cell = &r.Cells[i]
		}
	}
	if cell == nil || len(cell.Invoked) != 2 ||
		cell.Invoked[0].State != InvVersion || cell.Invoked[0].Version != "bbbbbbbb" ||
		cell.Invoked[1].State != InvVersionNotCaptured {
		t.Fatalf("lint cell = %+v, want [version bbbbbbbb, version_not_captured]", cell)
	}
	if len(r.Ambiguous) != 1 || r.Ambiguous[0].Name != "deploy" || len(r.Ambiguous[0].Candidates) != 2 {
		t.Errorf("ambiguous = %+v, want deploy with project+home candidates", r.Ambiguous)
	}
	if len(r.Unmatched) != 1 || r.Unmatched[0].Name != "superpowers:brainstorm" {
		t.Errorf("unmatched = %+v, want the plugin skill", r.Unmatched)
	}
	if d := findSkill(t, r, skKey); d.Invocations.Count != 0 {
		t.Errorf("ambiguous invocation was attributed: %+v", d.Invocations)
	}
	if v := findVersion(lint, "bbbbbbbb"); v == nil || v.Invocations != 1 {
		t.Errorf("lint version bbbbbbbb invocations = %+v, want 1", v)
	}
}

func findVersion(s Skill, id string) *Version {
	for i := range s.Versions {
		if s.Versions[i].ID == id {
			return &s.Versions[i]
		}
	}
	return nil
}

func TestInvocationNotMeasurable(t *testing.T) {
	in := base()
	in.InvocationMeasurable = map[string]bool{}
	in.Sessions = []Session{{ID: "s1", Tool: cc, StartedAt: at(0)}}
	in.Invocations = []Invocation{{SessionID: "s1", Tool: cc, Name: "deploy", ToolUseID: "tu1", At: at(1)}}
	r := Build(in)
	sk := findSkill(t, r, skKey)
	if sk.Invocations.Measurable {
		t.Errorf("Measurable = true with an empty measurability table")
	}
	if len(r.Cells) != 1 || r.Cells[0].Invoked[0].State != InvNotMeasurable {
		t.Errorf("cells = %+v, want one not_measurable invocation", r.Cells)
	}
}

func TestCurrentStates(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*Input)
		inGit    string
		worktree string
		cannot   string
	}{
		{"committed clean", nil, GitCommitted, "", ""},
		{"committed with uncommitted edits", func(in *Input) { in.Worktree = []WorktreeEntry{{RelPath: skMD, State: "modified"}} }, GitCommitted, "modified", ""},
		{"untracked", func(in *Input) {
			in.Trees[0].Files = map[string]TreeFile{}
			in.Worktree = []WorktreeEntry{{RelPath: skMD, State: "untracked"}}
		}, GitNotCommitted, "untracked", ""},
		{"ignored", func(in *Input) {
			in.Trees[0].Files = map[string]TreeFile{}
			in.Worktree = []WorktreeEntry{{RelPath: skMD, State: "ignored"}}
		}, GitNotCommitted, "ignored", ""},
		{"staged rename target was never committed", func(in *Input) {
			in.Trees[0].Files = map[string]TreeFile{}
			in.Worktree = []WorktreeEntry{{RelPath: skMD, State: "renamed"}}
		}, GitNotCommitted, "renamed", ""},
		{"staged rename origin is committed, staged away", func(in *Input) {
			in.Worktree = []WorktreeEntry{{RelPath: skMD, State: "renamed_away"}}
		}, GitCommitted, "renamed_away", ""},
		{"HEAD tree overrides a porcelain state for a path HEAD lacks", func(in *Input) {
			in.Trees[0].Files = map[string]TreeFile{}
			in.Worktree = []WorktreeEntry{{RelPath: skMD, State: "deleted"}}
		}, GitNotCommitted, "deleted", ""},
		{"staged, never committed", func(in *Input) {
			in.Trees[0].Files = map[string]TreeFile{}
			in.Worktree = []WorktreeEntry{{RelPath: skMD, State: "added"}}
		}, GitNotCommitted, "added", ""},
		{"ignored directory entry covers the file", func(in *Input) {
			in.Trees[0].Files = map[string]TreeFile{}
			in.Worktree = []WorktreeEntry{{RelPath: ".claude/skills/", State: "ignored"}}
		}, GitNotCommitted, "ignored", ""},
		{"git never scanned", func(in *Input) { in.Git.Scanned = false }, GitUnknown, "", ""},
		{"head tree pending", func(in *Input) { in.Trees = nil }, GitUnknown, "", ""},
		{"on disk, not at HEAD, not in status", func(in *Input) { in.Trees[0].Files = map[string]TreeFile{} }, GitUnknown, "", ""},
		{"symlink", func(in *Input) { in.Trees[0].Files = map[string]TreeFile{skMD: {Mode: "120000", BlobOID: blobA}} }, GitCommitted, "", "symlink"},
		{"sha256 repo", func(in *Input) { in.Git.ObjectFormat = "sha256" }, GitCommitted, "", "sha256_repo"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := base()
			if c.mutate != nil {
				c.mutate(&in)
			}
			sk := findSkill(t, Build(in), skKey)
			if sk.Current.InGit != c.inGit || sk.Current.Worktree != c.worktree || sk.Current.CannotMatch != c.cannot {
				t.Errorf("current = %+v, want in_git=%s worktree=%s cannot=%s", sk.Current, c.inGit, c.worktree, c.cannot)
			}
		})
	}
	in := base()
	in.Inventory = []InventoryFile{{Scope: ScopeUser, RelPath: "~/.claude/skills/x/SKILL.md", Name: "x", Present: true}}
	if sk := findSkill(t, Build(in), "user:~/.claude/skills/x"); sk.Current.InGit != GitNotInProjectGit {
		t.Errorf("home skill current = %+v, want %s", sk.Current, GitNotInProjectGit)
	}
}

func TestCaseInsensitiveCheckout(t *testing.T) {
	in := base()
	in.Git.IgnoreCase = true
	in.Trees = []Tree{{SHA: sha1c, State: TreeOK, Files: map[string]TreeFile{".Claude/Skills/Deploy/SKILL.md": {BlobOID: blobA}}}}
	in.Sessions = []Session{{ID: "s1", Tool: cc, StartedAt: at(0)}}
	r := Build(in)
	if len(r.Skills) != 1 {
		t.Fatalf("skills = %+v, want the two spellings folded onto one skill", r.Skills)
	}
	if sp := spanFor(t, r, r.Skills[0].Key, "s1"); sp.Head.State != HeadCommitted || sp.Head.Version != "aaaaaaaa" {
		t.Errorf("head = %+v, want committed aaaaaaaa via the case-folded tree", sp.Head)
	}
}

func TestSpansFoldAndCaps(t *testing.T) {
	in := base()
	for i := 0; i < 5; i++ {
		id := string(rune('a' + i))
		in.Sessions = append(in.Sessions, Session{ID: id, Tool: cc, StartedAt: at(i * 10)})
		in.Snapshots = append(in.Snapshots, snap(id, i*10, mem(blobA)))
	}
	r := Build(in)
	if len(r.Spans) != 1 || r.Spans[0].Sessions != 5 || r.Spans[0].FromSession != "a" || r.Spans[0].ToSession != "e" {
		t.Fatalf("spans = %+v, want one span of 5 sessions a..e", r.Spans)
	}
	if len(r.Cells) != 0 {
		t.Errorf("cells = %+v, want none (nothing interesting)", r.Cells)
	}
	if r.Sessions[0].ID != "e" {
		t.Errorf("sessions not newest first: %+v", r.Sessions)
	}
	if v := findVersion(findSkill(t, r, skKey), "aaaaaaaa"); v == nil || v.SessionsAvailable != 5 {
		t.Errorf("SessionsAvailable = %+v, want 5", v)
	}

	in.MaxSessions = 2
	r = Build(in)
	if !r.Truncated || len(r.Sessions) != 2 || r.Sessions[0].ID != "e" || r.Sessions[1].ID != "d" {
		t.Errorf("capped sessions = %+v truncated=%v, want newest two and truncated", r.Sessions, r.Truncated)
	}

	in = base()
	in.MaxCells = 1
	in.Sessions = []Session{{ID: "a", Tool: cc, StartedAt: at(0)}, {ID: "b", Tool: cc, StartedAt: at(10)}}
	in.Invocations = []Invocation{{SessionID: "a", Tool: cc, Name: "deploy", At: at(1)}, {SessionID: "b", Tool: cc, Name: "deploy", At: at(11)}}
	r = Build(in)
	if len(r.Cells) != 1 || !r.Truncated {
		t.Errorf("cells = %d truncated=%v, want 1 and truncated", len(r.Cells), r.Truncated)
	}
}

func TestSessionRelations(t *testing.T) {
	in := base()
	in.Sessions = []Session{
		{ID: "p", Tool: cc, StartedAt: at(0)},
		{ID: "c", Tool: cc, StartedAt: at(5), Relation: RelationSubagent, ParentID: "p"},
		{ID: "f", Tool: cc, StartedAt: at(9), Relation: RelationFork, ParentID: "outside"},
	}
	r := Build(in)
	got := map[string]SessionRow{}
	for _, s := range r.Sessions {
		got[s.ID] = s
	}
	if !got["c"].ParentInWindow || got["c"].Relation != RelationSubagent {
		t.Errorf("subagent row = %+v, want parent in window", got["c"])
	}
	if got["f"].ParentInWindow || got["f"].Relation != RelationFork {
		t.Errorf("fork row = %+v, want parent outside the window", got["f"])
	}
}

func TestEmptyInputIsNonNil(t *testing.T) {
	r := Build(Input{Rules: guidance.Rules()})
	if r.Skills == nil || r.Sessions == nil || r.Spans == nil || r.Cells == nil || r.Unmatched == nil || r.Ambiguous == nil {
		t.Errorf("empty Build has nil slices: %+v", r)
	}
	if !r.ObservedSince.IsZero() || r.Truncated {
		t.Errorf("empty Build = %+v, want zero ObservedSince and not truncated", r)
	}
}

func TestSnapshotOnlySkillGetsARow(t *testing.T) {
	in := base()
	in.Inventory = nil
	gone := ".claude/skills/old/SKILL.md"
	in.Snapshots = []Snapshot{snap("s1", 0, Member{Scope: ScopeProject, RelPath: gone, Name: "old", State: MemberPresent, BlobOID: blobC})}
	r := Build(in)
	sk := findSkill(t, r, "project:.claude/skills/old")
	if sk.Present || len(sk.Versions) != 1 || !strings.EqualFold(sk.Name, "old") {
		t.Errorf("snapshot-only skill = %+v", sk)
	}
}

// TestHeadSameSecondPicksBySequence pins that the chosen move among
// same-second entries is the reflog's newest (highest Seq), whatever order
// the rows arrive in, and that the cell names every candidate.
func TestHeadSameSecondPicksBySequence(t *testing.T) {
	for _, order := range [][]HeadMove{
		{{MovedAt: at(-100), SHA: sha2c, Seq: 2}, {MovedAt: at(-100), SHA: sha1c, Seq: 1}},
		{{MovedAt: at(-100), SHA: sha1c, Seq: 1}, {MovedAt: at(-100), SHA: sha2c, Seq: 2}},
	} {
		in := base()
		in.HeadMoves = order
		in.Sessions = []Session{{ID: "s1", Tool: cc, StartedAt: at(0)}}
		r := Build(in)
		if len(r.Cells) != 1 {
			t.Fatalf("cells = %+v, want the near-start cell", r.Cells)
		}
		h := r.Cells[0].Head
		if h.SHA != sha2c || !reflect.DeepEqual(h.Candidates, []string{"22222222", "11111111"}) || h.Reason != HeadReasonSameSecond {
			t.Errorf("head = %+v, want chosen sha2c (highest seq) with both candidates, reason same_second", h)
		}
	}
}

// TestTimelineSameSecondOrderedByAncestry pins that commits sharing one
// committer second are ordered parent-first (a rebase), never by sha, and
// that unrelated same-second commits touching the skill read "?".
func TestTimelineSameSecondOrderedByAncestry(t *testing.T) {
	in := base()
	// sha2c (adds A) is the parent of sha1c (edits to B); sha order would
	// put sha1c first.
	in.Timeline = []TimelineCommit{
		{SHA: sha1c, CommittedAt: at(-10), Reachable: true, Files: []string{skMD}, Parents: []string{sha2c}},
		{SHA: sha2c, CommittedAt: at(-10), Reachable: true, Files: []string{skMD}, Parents: []string{sha3c}},
	}
	in.Trees = []Tree{
		{SHA: sha1c, State: TreeOK, Files: map[string]TreeFile{skMD: {BlobOID: blobB}}},
		{SHA: sha2c, State: TreeOK, Files: map[string]TreeFile{skMD: {BlobOID: blobA}}},
	}
	sk := findSkill(t, Build(in), skKey)
	var got []string
	for _, c := range sk.Commits {
		got = append(got, c.SHA[:1]+c.Status)
	}
	if !reflect.DeepEqual(got, []string{"2A", "1M"}) {
		t.Errorf("same-second rebase chain = %v, want [2A 1M] (parent first)", got)
	}

	// Chain through a same-second commit that touched no skill: the
	// ancestry map carries it.
	in.Timeline[0].Parents = []string{sha4c}
	in.Ancestry = map[string][]string{sha4c: {sha2c}}
	sk = findSkill(t, Build(in), skKey)
	got = got[:0]
	for _, c := range sk.Commits {
		got = append(got, c.SHA[:1]+c.Status)
	}
	if !reflect.DeepEqual(got, []string{"2A", "1M"}) {
		t.Errorf("chain through an untracked same-second commit = %v, want [2A 1M]", got)
	}

	// Unrelated by ancestry (two branches, same second): order unknown.
	in.Timeline[0].Parents = []string{sha3c}
	in.Ancestry = nil
	sk = findSkill(t, Build(in), skKey)
	for _, c := range sk.Commits {
		if c.Status != "?" {
			t.Errorf("unrelated same-second commit %s status = %q, want ?", c.SHA[:8], c.Status)
		}
	}
	for _, v := range sk.Versions {
		if v.IntroducedBy != nil {
			t.Errorf("version %s claims introduced-by %s under an unknown order", v.ID, v.IntroducedBy.SHA[:8])
		}
	}
}

// TestTimelineWhileTreeMemoFills pins that a commit whose predecessor's
// tree is not resolved yet claims neither added nor introduced-by.
func TestTimelineWhileTreeMemoFills(t *testing.T) {
	in := base()
	in.Timeline = []TimelineCommit{
		{SHA: sha1c, CommittedAt: at(-400), Reachable: true, Files: []string{skMD}},
		{SHA: sha2c, CommittedAt: at(-300), Reachable: true, Files: []string{skMD}},
		{SHA: sha3c, CommittedAt: at(-200), Reachable: true, Files: []string{skMD}},
	}
	// Only the newest tree is memoised so far (the memo fills newest first).
	in.Trees = []Tree{{SHA: sha3c, State: TreeOK, Files: map[string]TreeFile{skMD: {BlobOID: blobB}}}}
	in.Git.HeadSHA = sha3c
	sk := findSkill(t, Build(in), skKey)
	var got []string
	for _, c := range sk.Commits {
		got = append(got, c.Status)
	}
	if !reflect.DeepEqual(got, []string{"?", "?", "?"}) {
		t.Errorf("statuses while the memo fills = %v, want [? ? ?]", got)
	}
	for _, v := range sk.Versions {
		if v.IntroducedBy != nil {
			t.Errorf("version %s introduced-by %s while its predecessors are unresolved", v.ID, v.IntroducedBy.SHA[:8])
		}
		if v.ID == "bbbbbbbb" && !v.InCommits {
			t.Errorf("version B = %+v, want in_commits (it is in a recorded tree)", v)
		}
	}
}

// TestSpansIgnoreNonReadingSessions pins that a session of a tool that
// does not read the skill neither splits nor joins a span.
func TestSpansIgnoreNonReadingSessions(t *testing.T) {
	in := base()
	in.Sessions = []Session{
		{ID: "a", Tool: cc, StartedAt: at(0)},
		{ID: "b", Tool: codex, StartedAt: at(10)},
		{ID: "c", Tool: cc, StartedAt: at(20)},
	}
	r := Build(in)
	if len(r.Spans) != 1 || r.Spans[0].Sessions != 2 {
		t.Errorf("spans = %+v, want one span of the two claude-code sessions", r.Spans)
	}
}
