package skillhistory

import (
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guidance"
)

// skillAcc accumulates one skill while Build walks its inputs.
type skillAcc struct {
	skill      Skill
	folded     string
	versionRel string // the SKILL.md rel path (original case) last seen
	versions   map[string]*Version
	// chain state for the reachable-commit walk
	lastBlob  string
	lastState string // "" (never touched) | "present" | "absent" | chainUnknown
	seenBlobs map[string]bool
}

// builder holds the per-call indexes.
type builder struct {
	in       Input
	patterns []skillPattern
	skills   map[string]*skillAcc
	trees    map[string]*Tree
	gitBlobs map[string]bool
	moves    []HeadMove // ascending by (MovedAt, Seq)
	headMemo map[string]*headLookup
}

// chainUnknown is the chain state after a SKILL.md-touching commit whose
// tree is not resolved (memo still filling, object missing) or whose
// order among same-second commits is not known: the next commit cannot
// claim added-vs-modified or introduced-by.
const chainUnknown = "unknown"

// Build derives the skills history. It never reads a clock: every time it
// reports comes from its inputs, so the same Input always yields the same
// Result.
func Build(in Input) Result {
	if in.SkewMargin <= 0 {
		in.SkewMargin = DefaultSkewMargin
	}
	if in.MaxSessions <= 0 {
		in.MaxSessions = DefaultMaxSessions
	}
	if in.MaxCells <= 0 {
		in.MaxCells = DefaultMaxCells
	}
	b := &builder{
		in:       in,
		patterns: skillPatterns(in.Rules),
		skills:   map[string]*skillAcc{},
		trees:    map[string]*Tree{},
		gitBlobs: map[string]bool{},
	}
	b.indexTrees()
	b.moves = append([]HeadMove(nil), in.HeadMoves...)
	sort.SliceStable(b.moves, func(i, j int) bool {
		if !b.moves[i].MovedAt.Equal(b.moves[j].MovedAt) {
			return b.moves[i].MovedAt.Before(b.moves[j].MovedAt)
		}
		return b.moves[i].Seq < b.moves[j].Seq
	})

	b.addInventory()
	b.walkTimeline()
	b.addSnapshotSkills()

	res := Result{
		Skills:               []Skill{},
		Sessions:             []SessionRow{},
		Spans:                []Span{},
		Cells:                []Cell{},
		Unmatched:            []NamedCount{},
		Ambiguous:            []AmbiguousInvocation{},
		SnapshotCapabilities: map[string]bool{},
	}
	for _, sn := range in.Snapshots {
		if res.ObservedSince.IsZero() || sn.ObservedAt.Before(res.ObservedSince) {
			res.ObservedSince = sn.ObservedAt
		}
	}

	accs := b.sortedSkills()
	sessions, truncated := b.windowSessions()
	res.Truncated = truncated || in.TimelineTruncated
	for _, s := range sessions {
		res.SnapshotCapabilities[s.Tool] = in.SnapshotEmitters[s.Tool]
	}
	res.Sessions = sessionRows(sessions)

	attributed := b.attributeInvocations(accs, &res)
	b.resolveCells(accs, sessions, attributed, &res)

	for _, acc := range accs {
		b.finishCurrent(acc)
		acc.skill.Versions = orderVersions(acc.versions)
		res.Skills = append(res.Skills, acc.skill)
	}
	return res
}

func (b *builder) fold(scope, dir string) string {
	if scope == ScopeProject && b.in.Git.IgnoreCase {
		return strings.ToLower(dir)
	}
	return dir
}

// match resolves a path against the skill patterns, case-insensitively
// for project scope when the checkout is case-insensitive.
func (b *builder) match(rel string) (dirMatch, bool) {
	return matchSkillPathFold(rel, b.patterns, b.in.Git.IgnoreCase)
}

func (b *builder) indexTrees() {
	for i := range b.in.Trees {
		t := b.in.Trees[i]
		folded := make(map[string]TreeFile, len(t.Files))
		for p, f := range t.Files {
			folded[b.fold(ScopeProject, p)] = f
			if t.State == TreeOK {
				if m, ok := b.match(p); ok && m.IsVersion {
					b.gitBlobs[f.BlobOID] = true
				}
			}
		}
		t.Files = folded
		b.trees[t.SHA] = &t
	}
}

// acc returns (creating) the accumulator for a skill directory.
func (b *builder) acc(m dirMatch, versionRel string) *skillAcc {
	key := m.Scope + ":" + b.fold(m.Scope, m.Dir)
	a := b.skills[key]
	if a == nil {
		a = &skillAcc{
			skill: Skill{
				Key: key, Scope: m.Scope, Dir: m.Dir, Tools: m.Tools,
				Names: []string{}, Commits: []SkillCommit{},
			},
			folded:     b.fold(m.Scope, m.Dir),
			versionRel: m.Dir + "/" + m.File,
			versions:   map[string]*Version{},
			seenBlobs:  map[string]bool{},
		}
		b.skills[key] = a
	} else if a.skill.Dir != m.Dir {
		// Two spellings of one directory folded onto one key (a
		// case-insensitive checkout): report it, never pick one.
		a.skill.Ambiguous = true
	}
	if versionRel != "" && m.IsVersion {
		a.versionRel = versionRel
	}
	return a
}

func (b *builder) addInventory() {
	for _, f := range b.in.Inventory {
		m, ok := b.match(f.RelPath)
		if !ok || !m.IsVersion {
			continue
		}
		a := b.acc(m, f.RelPath)
		if f.Present {
			a.skill.Present = true
			if f.Name != "" {
				a.skill.Name = f.Name
			}
		}
		addName(a, f.Name)
	}
}

func addName(a *skillAcc, name string) {
	if name == "" {
		return
	}
	a.skill.Names = appendUnique(a.skill.Names, name)
}

// sighting records that a blob was seen at time t.
func (b *builder) sighting(a *skillAcc, blob string, t time.Time) *Version {
	if blob == "" {
		return nil
	}
	v := a.versions[blob]
	if v == nil {
		v = &Version{ID: shortID(blob), BlobOID: blob, FirstSeen: t}
		a.versions[blob] = v
	}
	if !t.IsZero() && (v.FirstSeen.IsZero() || t.Before(v.FirstSeen)) {
		v.FirstSeen = t
	}
	if b.gitBlobs[blob] {
		v.InCommits = true
	}
	return v
}

func shortID(blob string) string {
	if len(blob) > 8 {
		return blob[:8]
	}
	return blob
}

// touchedDir is one skill directory a commit touched.
type touchedDir struct {
	m          dirMatch
	versionRel string
	files      int
}

// addedBlob is a SKILL.md a reachable commit added ("A"), the move
// candidate R9 pairs with a same-commit deletion.
type addedBlob struct {
	acc  *skillAcc
	blob string
}

// walkTimeline builds every skill's commit list and the version chain.
// Reachable commits are walked oldest first and drive the chain
// (added / modified / deleted, introduced-by, reintroduced, moves);
// unreachable ones are listed against the chain state at their position
// but never advance it.
func (b *builder) walkTimeline() {
	commits, unordered := orderTimeline(b.in.Timeline, b.in.Ancestry)
	dirsOf := map[string]map[string]bool{}
	for _, c := range commits {
		ds := map[string]bool{}
		for _, f := range c.Files {
			if m, ok := b.match(f); ok && m.Scope == ScopeProject {
				ds[b.fold(m.Scope, m.Dir)] = true
			}
		}
		dirsOf[c.SHA] = ds
	}
	// orderUnknown: another same-second commit, unrelated by ancestry,
	// touched the same skill directory - their relative order (and so
	// added-vs-modified between them) is not known.
	orderUnknown := func(sha, dir string) bool {
		for other := range unordered[sha] {
			if dirsOf[other][dir] {
				return true
			}
		}
		return false
	}
	for _, c := range commits {
		byDir, dirOrder := b.touchedDirs(c)
		tree := b.trees[c.SHA]
		deleted := map[string]string{} // dir -> blob before deletion
		var adds []addedBlob
		for _, k := range dirOrder {
			t := byDir[k]
			a := b.acc(t.m, t.versionRel)
			sc := SkillCommit{
				SHA: c.SHA, CommittedAt: c.CommittedAt, Subject: c.Subject,
				Reachable: c.Reachable, IsMerge: c.IsMerge, Files: t.files,
				SkillMDChanged: t.versionRel != "",
			}
			if sc.SkillMDChanged {
				if ad, ok := b.chainStep(c, tree, t.versionRel, a, &sc, orderUnknown(c.SHA, k), deleted); ok {
					adds = append(adds, ad)
				}
			}
			a.skill.Commits = append(a.skill.Commits, sc)
		}
		recordMoves(c.SHA, adds, deleted)
	}
}

// touchedDirs groups a commit's project-scope files by folded skill
// directory, in first-touched order.
func (b *builder) touchedDirs(c TimelineCommit) (map[string]*touchedDir, []string) {
	byDir := map[string]*touchedDir{}
	var dirOrder []string
	for _, f := range c.Files {
		m, ok := b.match(f)
		if !ok || m.Scope != ScopeProject {
			continue
		}
		k := b.fold(m.Scope, m.Dir)
		t := byDir[k]
		if t == nil {
			t = &touchedDir{m: m}
			byDir[k] = t
			dirOrder = append(dirOrder, k)
		}
		t.files++
		if m.IsVersion {
			t.versionRel = f
			t.m.IsVersion = true
		}
	}
	return byDir, dirOrder
}

// chainStep sets sc.Status / sc.Version for a commit that changed the
// skill's SKILL.md and, for a reachable commit, advances the version
// chain. A reachable delete of a present SKILL.md records the prior blob
// in deleted; a reachable add is returned (ok) as a move candidate.
func (b *builder) chainStep(c TimelineCommit, tree *Tree, versionRel string, a *skillAcc, sc *SkillCommit, unknownOrder bool, deleted map[string]string) (addedBlob, bool) {
	if tree == nil || tree.State != TreeOK {
		sc.Status = "?"
		if c.Reachable {
			a.lastBlob, a.lastState = "", chainUnknown
		}
		return addedBlob{}, false
	}
	tf, present := tree.Files[b.fold(ScopeProject, versionRel)]
	prior := a.lastState
	switch {
	case !present:
		// Touched and gone from the tree: deleted here,
		// whatever came before.
		sc.Status = "D"
	case prior == chainUnknown || unknownOrder:
		sc.Status = "?"
	case prior == "present":
		sc.Status = "M"
	default:
		sc.Status = "A"
	}
	if !present {
		if c.Reachable {
			if a.lastState == "present" && !unknownOrder {
				deleted[a.skill.Dir] = a.lastBlob
			}
			a.lastBlob, a.lastState = "", "absent"
			if unknownOrder {
				a.lastState = chainUnknown
			}
		}
		return addedBlob{}, false
	}
	v := b.sighting(a, tf.BlobOID, c.CommittedAt)
	sc.Version = v.ID
	if !c.Reachable {
		return addedBlob{}, false
	}
	// No introduced-by / reintroduced claim when what came before is
	// unknown ("?"); a blob first seen at a "?" commit is never later
	// "introduced".
	switch {
	case sc.Status == "?":
	case v.IntroducedBy == nil && !a.seenBlobs[tf.BlobOID]:
		v.IntroducedBy = &CommitRef{SHA: c.SHA, CommittedAt: c.CommittedAt, Subject: c.Subject, Reachable: true}
	case a.seenBlobs[tf.BlobOID] && a.lastBlob != tf.BlobOID:
		v.ReintroducedIn = append(v.ReintroducedIn, c.SHA)
	}
	var ad addedBlob
	isAdd := sc.Status == "A"
	if isAdd {
		ad = addedBlob{acc: a, blob: tf.BlobOID}
	}
	a.lastBlob, a.lastState = tf.BlobOID, "present"
	if unknownOrder {
		a.lastBlob, a.lastState = "", chainUnknown
	}
	a.seenBlobs[tf.BlobOID] = true
	return ad, isAdd
}

// recordMoves applies R9: an exact-content move is one deleted SKILL.md
// and one added SKILL.md with the IDENTICAL blob in the same commit.
// Anything else stays "removed" + "added".
func recordMoves(sha string, adds []addedBlob, deleted map[string]string) {
	for _, ad := range adds {
		var from string
		n := 0
		for dir, blob := range deleted {
			if blob != "" && blob == ad.blob {
				from = dir
				n++
			}
		}
		if n == 1 {
			ad.acc.skill.MovedFrom = &Move{FromDir: from, SHA: sha}
		}
	}
}

// addSnapshotSkills makes sure a skill that only a hook snapshot saw
// (deleted since, never committed) still gets a row, and records each
// observation as a version sighting.
func (b *builder) addSnapshotSkills() {
	for _, sn := range b.in.Snapshots {
		for _, mem := range sn.Members {
			m, ok := b.match(mem.RelPath)
			if !ok || !m.IsVersion || m.Scope != mem.Scope {
				continue
			}
			a := b.acc(m, mem.RelPath)
			addName(a, mem.Name)
			if mem.State != MemberPresent {
				continue
			}
			blob, _ := b.memberBlob(mem)
			v := b.sighting(a, blob, sn.ObservedAt)
			if v == nil {
				continue
			}
			if v.ObservedFirst.IsZero() || sn.ObservedAt.Before(v.ObservedFirst) {
				v.ObservedFirst = sn.ObservedAt
			}
			if sn.ObservedAt.After(v.ObservedLast) {
				v.ObservedLast = sn.ObservedAt
			}
		}
	}
}

// memberBlob resolves a snapshot member to its version blob: the raw
// blob when a recorded commit has it, else the LF-normalised blob when a
// recorded commit has THAT (a CRLF working copy of committed content),
// else the raw blob (content found in no recorded commit).
func (b *builder) memberBlob(mem Member) (blob string, lineEndings bool) {
	if b.gitBlobs[mem.BlobOID] {
		return mem.BlobOID, false
	}
	if mem.BlobOIDLF != "" && b.gitBlobs[mem.BlobOIDLF] {
		return mem.BlobOIDLF, true
	}
	return mem.BlobOID, false
}

func (b *builder) sortedSkills() []*skillAcc {
	out := make([]*skillAcc, 0, len(b.skills))
	for _, a := range b.skills {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].skill.Scope != out[j].skill.Scope {
			return out[i].skill.Scope == ScopeProject
		}
		return out[i].skill.Key < out[j].skill.Key
	})
	for _, a := range out {
		if a.skill.Name == "" {
			a.skill.Name = dirBase(a.skill.Dir)
		}
		sort.Strings(a.skill.Names)
	}
	return out
}

func dirBase(dir string) string {
	if i := strings.LastIndex(dir, "/"); i >= 0 {
		return dir[i+1:]
	}
	return dir
}

// windowSessions keeps the newest MaxSessions sessions and returns them
// oldest first.
func (b *builder) windowSessions() ([]Session, bool) {
	s := append([]Session(nil), b.in.Sessions...)
	sort.SliceStable(s, func(i, j int) bool {
		if !s[i].StartedAt.Equal(s[j].StartedAt) {
			return s[i].StartedAt.After(s[j].StartedAt)
		}
		return s[i].ID > s[j].ID
	})
	truncated := false
	if len(s) > b.in.MaxSessions {
		s = s[:b.in.MaxSessions]
		truncated = true
	}
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s, truncated
}

func sessionRows(sessions []Session) []SessionRow {
	ids := make(map[string]bool, len(sessions))
	for _, s := range sessions {
		ids[s.ID] = true
	}
	out := make([]SessionRow, 0, len(sessions))
	for i := len(sessions) - 1; i >= 0; i-- { // newest first
		s := sessions[i]
		out = append(out, SessionRow{
			ID: s.ID, Tool: s.Tool, StartedAt: s.StartedAt, Relation: s.Relation,
			ParentID: s.ParentID, ParentInWindow: s.ParentID != "" && ids[s.ParentID],
		})
	}
	return out
}

// invocationKey identifies one invocation for the per-session join.
type attributedInvocation struct {
	inv Invocation
	acc *skillAcc
}

// attributeInvocations maps every invocation name to at most one skill.
// A name no skill carries is "unmatched" (plugin skills land here); a
// name two skills carry (a project skill and a home skill of the same
// name) is "ambiguous" and is attributed to neither - never double
// counted, never assigned by an ungrounded precedence rule.
func (b *builder) attributeInvocations(accs []*skillAcc, res *Result) map[string][]attributedInvocation {
	index := map[string][]*skillAcc{}
	for _, a := range accs {
		names := append([]string{dirBase(a.skill.Dir)}, a.skill.Names...)
		seen := map[string]bool{}
		for _, tool := range a.skill.Tools {
			for _, n := range names {
				k := guidance.SkillKey(tool, guidance.KindSkill, n)
				if seen[k] {
					continue
				}
				seen[k] = true
				index[k] = append(index[k], a)
			}
		}
		a.skill.Invocations.Measurable = anyMeasurable(a.skill.Tools, b.in.InvocationMeasurable)
	}
	unmatched := map[[2]string]int{}
	ambiguous := map[[2]string]*AmbiguousInvocation{}
	bySession := map[string][]attributedInvocation{}
	for _, inv := range b.in.Invocations {
		cands := index[guidance.SkillKey(inv.Tool, guidance.KindSkill, inv.Name)]
		switch len(cands) {
		case 0:
			unmatched[[2]string{inv.Tool, inv.Name}]++
		case 1:
			a := cands[0]
			a.skill.Invocations.Count++
			if inv.At.After(a.skill.Invocations.Last) {
				a.skill.Invocations.Last = inv.At
			}
			bySession[inv.SessionID] = append(bySession[inv.SessionID], attributedInvocation{inv: inv, acc: a})
		default:
			k := [2]string{inv.Tool, inv.Name}
			if ambiguous[k] == nil {
				amb := &AmbiguousInvocation{Tool: inv.Tool, Name: inv.Name}
				for _, c := range cands {
					amb.Candidates = append(amb.Candidates, c.skill.Key)
				}
				sort.Strings(amb.Candidates)
				ambiguous[k] = amb
			}
			ambiguous[k].Count++
		}
	}
	for k, n := range unmatched {
		res.Unmatched = append(res.Unmatched, NamedCount{Tool: k[0], Name: k[1], Count: n})
	}
	sort.Slice(res.Unmatched, func(i, j int) bool {
		if res.Unmatched[i].Count != res.Unmatched[j].Count {
			return res.Unmatched[i].Count > res.Unmatched[j].Count
		}
		return res.Unmatched[i].Tool+res.Unmatched[i].Name < res.Unmatched[j].Tool+res.Unmatched[j].Name
	})
	for _, a := range ambiguous {
		res.Ambiguous = append(res.Ambiguous, *a)
	}
	sort.Slice(res.Ambiguous, func(i, j int) bool {
		return res.Ambiguous[i].Tool+res.Ambiguous[i].Name < res.Ambiguous[j].Tool+res.Ambiguous[j].Name
	})
	return bySession
}

func anyMeasurable(tools []string, table map[string]bool) bool {
	for _, t := range tools {
		if table[t] {
			return true
		}
	}
	return false
}

// resolveCells resolves every (session, skill) pair, folds consecutive
// identical resolutions into spans, and keeps only the interesting cells.
func (b *builder) resolveCells(accs []*skillAcc, sessions []Session, invs map[string][]attributedInvocation, res *Result) {
	startSnaps := map[string][]Snapshot{}
	invokeSnaps := map[string]Snapshot{}
	for _, sn := range b.in.Snapshots {
		switch sn.Event {
		case EventSessionStart:
			startSnaps[sn.SessionID] = append(startSnaps[sn.SessionID], sn)
		case EventSkillInvoke:
			if sn.ToolUseID != "" {
				if prev, ok := invokeSnaps[sn.ToolUseID]; !ok || sn.ObservedAt.Before(prev.ObservedAt) {
					invokeSnaps[sn.ToolUseID] = sn
				}
			}
		}
	}
	for id := range startSnaps {
		ss := startSnaps[id]
		sort.SliceStable(ss, func(i, j int) bool { return ss[i].ObservedAt.Before(ss[j].ObservedAt) })
	}

	for _, a := range accs {
		var span *Span
		flush := func() {
			if span != nil {
				if len(res.Spans) >= b.in.MaxCells {
					res.Truncated = true
				} else {
					res.Spans = append(res.Spans, *span)
				}
				span = nil
			}
		}
		for _, s := range sessions {
			c := &cellCtx{b: b, acc: a, session: s, snaps: startSnaps[s.ID]}
			obs := resolveObserved(c)
			head := resolveHead(c)
			var invoked []InvokedEntry
			for _, ai := range invs[s.ID] {
				if ai.acc != a {
					continue
				}
				invoked = append(invoked, b.resolveInvoked(c, ai.inv, invokeSnaps))
			}
			if obs.State == ObsObserved || obs.State == ObsChanged {
				if v := a.versionByID(obs.Version); v != nil {
					v.SessionsAvailable++
				}
			}
			if obs.State == ObsNotApplicable && head.State == HeadNotApplicable && len(invoked) == 0 {
				// A session of a tool that does not read this skill says
				// nothing about it: it neither joins nor breaks a span.
				continue
			}
			spanHead := head
			spanHead.SHA = ""
			spanHead.Candidates = nil
			if span != nil && sameCell(span.Observed, span.Head, obs, spanHead) {
				span.ToSession, span.To = s.ID, s.StartedAt
				span.Sessions++
			} else {
				flush()
				span = &Span{
					SkillKey: a.skill.Key, FromSession: s.ID, ToSession: s.ID,
					From: s.StartedAt, To: s.StartedAt, Sessions: 1,
					Observed: obs, Head: spanHead,
				}
			}
			if interesting(obs, head, invoked) {
				if len(res.Cells) >= b.in.MaxCells {
					res.Truncated = true
					continue
				}
				res.Cells = append(res.Cells, Cell{
					SkillKey: a.skill.Key, SessionID: s.ID,
					Observed: obs, Head: head, Invoked: invoked,
				})
			}
		}
		flush()
	}
}

func (a *skillAcc) versionByID(id string) *Version {
	if id == "" {
		return nil
	}
	for _, v := range a.versions {
		if v.ID == id {
			return v
		}
	}
	return nil
}

func sameCell(o1 ObservedCell, h1 HeadCell, o2 ObservedCell, h2 HeadCell) bool {
	return o1.State == o2.State && o1.Version == o2.Version && o1.LineEndings == o2.LineEndings &&
		o1.Source == o2.Source && o1.Reason == o2.Reason &&
		strings.Join(o1.Changed, ",") == strings.Join(o2.Changed, ",") &&
		h1.State == h2.State && h1.Version == h2.Version && h1.Reason == h2.Reason
}

// interesting decides which cells are emitted individually. The spans
// already carry every cell's resolution; a cell is worth its own row only
// when it has something the span cannot show.
func interesting(obs ObservedCell, head HeadCell, invoked []InvokedEntry) bool {
	switch {
	case len(invoked) > 0:
		return true
	case obs.State == ObsChanged:
		return true
	case obs.LineEndings:
		return true
	case obs.State == ObsObserved && head.State == HeadCommitted && obs.Version != head.Version:
		return true
	case head.State == HeadMovedNearStart:
		return true
	}
	return false
}

func (b *builder) resolveInvoked(c *cellCtx, inv Invocation, invokeSnaps map[string]Snapshot) InvokedEntry {
	e := InvokedEntry{At: inv.At}
	if !b.in.InvocationMeasurable[inv.Tool] {
		e.State = InvNotMeasurable
		return e
	}
	sn, ok := invokeSnaps[inv.ToolUseID]
	if inv.ToolUseID == "" || !ok {
		e.State = InvVersionNotCaptured
		return e
	}
	state, ver, _ := c.memberVersion(sn)
	switch state {
	case MemberPresent:
		e.State, e.Version = InvVersion, ver
		if v := c.acc.versionByID(ver); v != nil {
			v.Invocations++
		}
	default:
		e.State = InvUnknown
	}
	return e
}

// finishCurrent resolves the skill's current git state from the status
// porcelain (the VCS's own answer), HEAD's tree, and the inventory.
func (b *builder) finishCurrent(a *skillAcc) {
	cur := Current{}
	g := b.in.Git
	switch {
	case a.skill.Scope == ScopeUser:
		cur.InGit = GitNotInProjectGit
	case !g.Scanned:
		cur.InGit = GitUnknown
	default:
		cur.InGit = b.currentFromGit(a, &cur)
	}
	if g.ObjectFormat == "sha256" && a.skill.Scope == ScopeProject {
		cur.CannotMatch = "sha256_repo"
	}
	a.skill.Current = cur
}

// worktreeStates maps a status state to (in-git answer, worktree label).
// Ordered data, not a ladder: "added" means staged but never committed.
// A staged rename's NEW path ("renamed") was never committed; its origin
// ("renamed_away") was, and is now staged for removal.
var worktreeStates = map[string][2]string{
	"untracked":    {GitNotCommitted, "untracked"},
	"ignored":      {GitNotCommitted, "ignored"},
	"added":        {GitNotCommitted, "added"},
	"renamed":      {GitNotCommitted, "renamed"},
	"modified":     {GitCommitted, "modified"},
	"deleted":      {GitCommitted, "deleted"},
	"renamed_away": {GitCommitted, "renamed_away"},
	"unmerged":     {GitCommitted, "unmerged"},
}

func (b *builder) currentFromGit(a *skillAcc, cur *Current) string {
	key := b.fold(ScopeProject, a.versionRel)
	var wtState string
	for _, w := range b.in.Worktree {
		wk := b.fold(ScopeProject, w.RelPath)
		// A whole ignored/untracked directory is reported once with a
		// trailing slash; it covers every path beneath it.
		if wk == key || (strings.HasSuffix(wk, "/") && strings.HasPrefix(key, wk)) {
			wtState = w.State
		}
	}
	tree := b.trees[b.in.Git.HeadSHA]
	var headFile *TreeFile
	if tree != nil && tree.State == TreeOK {
		if tf, ok := tree.Files[key]; ok {
			headFile = &tf
		}
	}
	if headFile != nil {
		if v := b.sighting(a, headFile.BlobOID, time.Time{}); v != nil {
			cur.HeadVersion = v.ID
		}
		switch headFile.Mode {
		case "120000":
			cur.CannotMatch = "symlink"
		case "160000":
			cur.CannotMatch = "submodule"
		}
	}
	if wtState != "" {
		cur.Worktree = wtState
		m, ok := worktreeStates[wtState]
		if !ok {
			return GitUnknown
		}
		cur.Worktree = m[1]
		// HEAD's own tree, when resolved, is the final word on whether the
		// path is committed; the porcelain only adds the uncommitted part.
		if tree != nil && tree.State == TreeOK {
			if headFile != nil {
				return GitCommitted
			}
			return GitNotCommitted
		}
		return m[0]
	}
	switch {
	case tree == nil || tree.State != TreeOK:
		return GitUnknown
	case headFile != nil:
		return GitCommitted
	case !a.skill.Present:
		return GitRemoved
	default:
		return GitUnknown
	}
}

func orderVersions(m map[string]*Version) []Version {
	out := make([]Version, 0, len(m))
	for _, v := range m {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		zi, zj := out[i].FirstSeen.IsZero(), out[j].FirstSeen.IsZero()
		if zi != zj {
			return !zi
		}
		if !out[i].FirstSeen.Equal(out[j].FirstSeen) {
			return out[i].FirstSeen.Before(out[j].FirstSeen)
		}
		return out[i].BlobOID < out[j].BlobOID
	})
	for i := range out {
		out[i].Ordinal = i + 1
	}
	return out
}

// maxOrderGroup bounds the ancestry work for one same-second group; a
// larger group keeps the loader's order and is reported order-unknown.
const maxOrderGroup = 200

// orderTimeline sorts commits oldest first. Commits that share one
// committer second (a rebase, a cherry-pick run) are ordered by ancestry
// (parent before child), never by sha; within that, the loader's order is
// kept. It also returns, per sha, the same-second commits unrelated to it
// by ancestry: their relative order is not a fact.
func orderTimeline(in []TimelineCommit, ancestry map[string][]string) ([]TimelineCommit, map[string]map[string]bool) {
	commits := append([]TimelineCommit(nil), in...)
	sort.SliceStable(commits, func(i, j int) bool { return commits[i].CommittedAt.Before(commits[j].CommittedAt) })
	parents := map[string][]string{}
	for sha, ps := range ancestry {
		parents[sha] = ps
	}
	for _, c := range commits {
		if len(c.Parents) > 0 {
			parents[c.SHA] = c.Parents
		}
	}
	unordered := map[string]map[string]bool{}
	for lo := 0; lo < len(commits); {
		hi := lo + 1
		for hi < len(commits) && commits[hi].CommittedAt.Equal(commits[lo].CommittedAt) {
			hi++
		}
		if hi-lo > 1 {
			orderGroup(commits[lo:hi], parents, unordered)
		}
		lo = hi
	}
	return commits, unordered
}

// orderGroup reorders one same-second group in place (Kahn's algorithm,
// the current order as priority) and records unrelated pairs.
func orderGroup(group []TimelineCommit, parents map[string][]string, unordered map[string]map[string]bool) {
	n := len(group)
	mark := func(a, b string) {
		if unordered[a] == nil {
			unordered[a] = map[string]bool{}
		}
		unordered[a][b] = true
	}
	if n > maxOrderGroup {
		for i := range group {
			for j := range group {
				if i != j {
					mark(group[i].SHA, group[j].SHA)
				}
			}
		}
		return
	}
	// anc[i][j]: group[j] is an ancestor of group[i].
	anc := make([][]bool, n)
	idx := map[string]int{}
	for i, c := range group {
		idx[c.SHA] = i
	}
	for i := range group {
		anc[i] = make([]bool, n)
		seen := map[string]bool{}
		stack := append([]string(nil), parents[group[i].SHA]...)
		for len(stack) > 0 {
			sha := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if seen[sha] {
				continue
			}
			seen[sha] = true
			if j, ok := idx[sha]; ok {
				anc[i][j] = true
			}
			stack = append(stack, parents[sha]...)
		}
	}
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i != j && !anc[i][j] && !anc[j][i] {
				mark(group[i].SHA, group[j].SHA)
			}
		}
	}
	out := make([]TimelineCommit, 0, n)
	done := make([]bool, n)
	for len(out) < n {
		picked := -1
		for i := 0; i < n && picked < 0; i++ {
			if done[i] {
				continue
			}
			ready := true
			for j := 0; j < n; j++ {
				if !done[j] && j != i && anc[i][j] {
					ready = false
					break
				}
			}
			if ready {
				picked = i
			}
		}
		if picked < 0 { // a cycle cannot happen in git; keep the rest as-is
			for i := 0; i < n; i++ {
				if !done[i] {
					out = append(out, group[i])
					done[i] = true
				}
			}
			break
		}
		done[picked] = true
		out = append(out, group[picked])
	}
	copy(group, out)
}
