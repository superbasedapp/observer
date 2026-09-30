package skillhistory

import (
	"sort"
	"time"
)

// cellCtx is one (session, skill) resolution in progress.
type cellCtx struct {
	b       *builder
	acc     *skillAcc
	session Session
	snaps   []Snapshot // the session's session_start snapshots, oldest first
}

func (c *cellCtx) toolReads() bool {
	for _, t := range c.acc.skill.Tools {
		if t == c.session.Tool {
			return true
		}
	}
	return false
}

// memberVersion reports what one snapshot says about this skill:
// MemberPresent + version id, MemberUnreadable, ObsAbsent (a complete
// snapshot without the file), ObsHomeUnresolved, or ObsUnknown (an
// incomplete snapshot without the file).
func (c *cellCtx) memberVersion(sn Snapshot) (state, version string, lineEndings bool) {
	for _, m := range sn.Members {
		if m.Scope != c.acc.skill.Scope {
			continue
		}
		mm, ok := c.b.match(m.RelPath)
		if !ok || !mm.IsVersion || c.b.fold(mm.Scope, mm.Dir) != c.acc.folded {
			continue
		}
		if m.State != MemberPresent {
			return MemberUnreadable, "", false
		}
		blob, le := c.b.memberBlob(m)
		v := c.b.sighting(c.acc, blob, time.Time{})
		if v == nil {
			return MemberUnreadable, "", false
		}
		return MemberPresent, v.ID, le
	}
	switch {
	case c.acc.skill.Scope == ScopeUser && !sn.HomeResolved:
		return ObsHomeUnresolved, "", false
	case !sn.Complete:
		return ObsUnknown, "", false
	default:
		return ObsAbsent, "", false
	}
}

// observedRule is one row of the Observed rule table.
type observedRule struct {
	name  string
	match func(c *cellCtx) bool
	out   func(c *cellCtx) ObservedCell
}

// observedRules is walked top-down; the first matching row decides.
var observedRules = []observedRule{
	{
		name:  "tool does not read this path",
		match: func(c *cellCtx) bool { return !c.toolReads() },
		out:   func(*cellCtx) ObservedCell { return ObservedCell{State: ObsNotApplicable} },
	},
	{
		name:  "tool has no snapshot capability",
		match: func(c *cellCtx) bool { return !c.b.in.SnapshotEmitters[c.session.Tool] },
		out:   func(*cellCtx) ObservedCell { return ObservedCell{State: ObsNotMeasurable} },
	},
	{
		// A sub-agent never fires SessionStart: "not captured" is right,
		// but its reason is not "before capture / hooks missing".
		name: "sub-agent session without a snapshot",
		match: func(c *cellCtx) bool {
			return len(c.snaps) == 0 && c.session.Relation == RelationSubagent
		},
		out: func(*cellCtx) ObservedCell {
			return ObservedCell{State: ObsNotCaptured, Reason: ObsReasonSubagent}
		},
	},
	{
		name:  "no session-start snapshot (before capture, or hooks not registered)",
		match: func(c *cellCtx) bool { return len(c.snaps) == 0 },
		out:   func(*cellCtx) ObservedCell { return ObservedCell{State: ObsNotCaptured} },
	},
	{
		name:  "snapshot resolution",
		match: func(*cellCtx) bool { return true },
		out:   observedFromSnapshots,
	},
}

func resolveObserved(c *cellCtx) ObservedCell {
	for _, r := range observedRules {
		if r.match(c) {
			return r.out(c)
		}
	}
	return ObservedCell{State: ObsUnknown}
}

// snapshotLabel renders one snapshot's answer as a comparable label.
func snapshotLabel(state, version string) string {
	if state == MemberPresent {
		return version
	}
	return state
}

// atStart reports whether a snapshot describes the session's START: a
// startup/clear SessionStart, or any snapshot taken within the skew margin
// of the recorded start. A resume/compact re-fire later on describes the
// disk at that moment, never what was available at the start.
func (c *cellCtx) atStart(sn Snapshot) bool {
	if startSources[sn.Source] {
		return true
	}
	d := sn.ObservedAt.Sub(c.session.StartedAt)
	if d < 0 {
		d = -d
	}
	return d <= c.b.in.SkewMargin
}

func observedFromSnapshots(c *cellCtx) ObservedCell {
	state, version, le := c.memberVersion(c.snaps[0])
	cell := ObservedCell{LineEndings: le}
	switch state {
	case MemberPresent:
		cell.State, cell.Version = ObsObserved, version
	case MemberUnreadable, ObsUnknown:
		cell.State = ObsUnknown
	case ObsHomeUnresolved:
		cell.State = ObsHomeUnresolved
	case ObsAbsent:
		cell.State = ObsAbsent
	}
	// Resume / clear / compact re-fire SessionStart: a later snapshot
	// that disagrees means the skill changed during the session.
	labels := []string{snapshotLabel(state, version)}
	for _, sn := range c.snaps[1:] {
		st, v, _ := c.memberVersion(sn)
		l := snapshotLabel(st, v)
		if l != labels[len(labels)-1] {
			labels = append(labels, l)
		}
	}
	if len(labels) > 1 {
		cell.State = ObsChanged
		cell.Changed = labels
	}
	if !c.atStart(c.snaps[0]) {
		// Keep what was seen (version, chain) but never call it "at start".
		cell.State, cell.Source = ObsAfterStart, c.snaps[0].Source
		if state != MemberPresent {
			cell.Version = ""
		}
	}
	return cell
}

// headRule is one row of the HEAD-at-session-start rule table.
type headRule struct {
	name  string
	match func(c *cellCtx, h *headLookup) bool
	out   func(c *cellCtx, h *headLookup) HeadCell
}

// headLookup is the reflog position for one session start. It depends
// only on the session, so the builder memoises it per session.
type headLookup struct {
	chosen     *HeadMove
	near       []HeadMove
	sameSecond bool
}

// lookupHead picks the newest move at or before the session start (moves
// are ordered by time, then by reflog sequence) and collects the moves
// that make that pick uncertain:
//   - other shas in the chosen move's own second (1-second reflog
//     resolution: which of them was last is not a fact we can promise);
//   - when the chosen move is itself within the skew margin BEFORE the
//     start, the position HEAD held just before it;
//   - any other move within the margin on either side of the start.
func (b *builder) lookupHead(s Session) *headLookup {
	if h, ok := b.headMemo[s.ID]; ok {
		return h
	}
	h := &headLookup{}
	t := s.StartedAt
	moves := b.moves
	margin := b.in.SkewMargin
	i := sort.Search(len(moves), func(k int) bool { return moves[k].MovedAt.After(t) })
	if i > 0 {
		m := moves[i-1]
		h.chosen = &m
		j := i - 2
		for ; j >= 0 && moves[j].MovedAt.Equal(m.MovedAt); j-- {
			if moves[j].SHA != m.SHA {
				h.near = append(h.near, moves[j])
				h.sameSecond = true
			}
		}
		if t.Sub(m.MovedAt) <= margin {
			for k := i - 2; k >= 0; k-- {
				if moves[k].SHA != m.SHA {
					h.near = append(h.near, moves[k])
					break
				}
			}
		}
	}
	lo := sort.Search(len(moves), func(k int) bool { return !moves[k].MovedAt.Before(t.Add(-margin)) })
	for k := lo; k < len(moves) && !moves[k].MovedAt.After(t.Add(margin)); k++ {
		if h.chosen == nil || moves[k].SHA != h.chosen.SHA {
			h.near = append(h.near, moves[k])
		}
	}
	if b.headMemo == nil {
		b.headMemo = map[string]*headLookup{}
	}
	b.headMemo[s.ID] = h
	return h
}

var headRules = []headRule{
	{
		name:  "tool does not read this path",
		match: func(c *cellCtx, _ *headLookup) bool { return !c.toolReads() },
		out:   func(*cellCtx, *headLookup) HeadCell { return HeadCell{State: HeadNotApplicable} },
	},
	{
		name:  "home-directory skill",
		match: func(c *cellCtx, _ *headLookup) bool { return c.acc.skill.Scope == ScopeUser },
		out:   func(*cellCtx, *headLookup) HeadCell { return HeadCell{State: HeadNotInProjectGit} },
	},
	{
		// The git step runs only after a successful commit scan, so "never
		// scanned" covers not-a-repo, git missing and not-yet-reached. A
		// LATER step failure (GitState.LastError) does not blank captured
		// history: it is reported on the capture strip, and what it could
		// not refresh resolves as pending/reflog_unavailable on its own.
		name:  "git step never completed",
		match: func(c *cellCtx, _ *headLookup) bool { return !c.b.in.Git.Scanned },
		out: func(*cellCtx, *headLookup) HeadCell {
			return HeadCell{State: HeadGitUnavailable, Reason: HeadReasonNotScanned}
		},
	},
	{
		name:  "no reflog entry at or before the session start",
		match: func(_ *cellCtx, h *headLookup) bool { return h.chosen == nil },
		out:   func(*cellCtx, *headLookup) HeadCell { return HeadCell{State: HeadReflogUnavailable} },
	},
	{
		name:  "HEAD moved within the skew margin of the start, or several times in the chosen second",
		match: func(_ *cellCtx, h *headLookup) bool { return len(h.near) > 0 },
		out: func(_ *cellCtx, h *headLookup) HeadCell {
			cands := []string{shortID(h.chosen.SHA)}
			for _, m := range h.near {
				cands = appendUnique(cands, shortID(m.SHA))
			}
			reason := HeadReasonSkew
			if h.sameSecond {
				reason = HeadReasonSameSecond
			}
			return HeadCell{State: HeadMovedNearStart, SHA: h.chosen.SHA, Candidates: cands, Reason: reason}
		},
	},
	{
		name:  "tree resolution",
		match: func(*cellCtx, *headLookup) bool { return true },
		out:   headFromTree,
	},
}

func resolveHead(c *cellCtx) HeadCell {
	h := c.b.lookupHead(c.session)
	for _, r := range headRules {
		if r.match(c, h) {
			return r.out(c, h)
		}
	}
	return HeadCell{State: HeadPending}
}

func headFromTree(c *cellCtx, h *headLookup) HeadCell {
	sha := h.chosen.SHA
	tree := c.b.trees[sha]
	switch {
	case tree == nil:
		return HeadCell{State: HeadPending, SHA: sha}
	case tree.State != TreeOK:
		return HeadCell{State: HeadCommitUnavailable, SHA: sha}
	}
	tf, ok := tree.Files[c.b.fold(ScopeProject, c.acc.versionRel)]
	if !ok {
		return HeadCell{State: HeadAbsentInCommit, SHA: sha}
	}
	v := c.b.sighting(c.acc, tf.BlobOID, h.chosen.MovedAt)
	return HeadCell{State: HeadCommitted, SHA: sha, Version: v.ID}
}
