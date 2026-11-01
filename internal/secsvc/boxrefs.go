//go:build !sbo_omit_security

package secsvc

import (
	"sort"
	"strings"
)

// boxrefs.go plans the commit scan's walk over box refs (security plan
// 4.8 "Copy workspaces", 5.3 (d), 7.10, M7; lane sec-box): the sandbox
// return step's refs/observer/sandbox/<run> and the worktree source's
// refs/heads/observer-sandbox/<id>/<label>. Each tick lists the box refs
// once; this table turns the listing and the tips walked last into the
// walks to make. Pure: the git calls and the record are the caller's.

// BoxRef is one listed box ref and the commit it names.
type BoxRef struct {
	Ref string
	Tip string
}

// BoxRefWalk is one walk: a ref seen for the first time (From empty: the
// commits no ref outside the box namespaces reaches) or a ref that moved
// (its commits since From).
type BoxRefWalk struct {
	Ref   string
	Tip   string
	From  string
	RunID string
	// Claimed: RunID was read from a ref name the box itself can write
	// (the worktree source's branch, whose directory the box has
	// writable); the caller checks it against the host's run records and
	// records UnknownRunID when no record owns it (lane sec-box audit
	// finding 5). A return ref's run id is written by the host.
	Claimed bool
}

// The box ref namespaces and the run id each one names.
const (
	boxReturnPrefix   = "refs/observer/sandbox/"
	boxWorktreePrefix = "refs/heads/observer-sandbox/"
)

// BoxRunID is the sandbox run a box ref names: the last segment of a
// return ref (refs/observer/sandbox/<run>), the first segment after the
// prefix of a worktree branch (refs/heads/observer-sandbox/<id>/<label>);
// "" for any other ref.
func BoxRunID(ref string) string {
	switch {
	case strings.HasPrefix(ref, boxReturnPrefix):
		rest := ref[len(boxReturnPrefix):]
		if i := strings.LastIndexByte(rest, '/'); i >= 0 {
			rest = rest[i+1:]
		}
		return rest
	case strings.HasPrefix(ref, boxWorktreePrefix):
		id, _, _ := strings.Cut(ref[len(boxWorktreePrefix):], "/")
		return id
	}
	return ""
}

// PlanBoxRefs turns one listing and the tips walked last (prev, ref to
// tip) into the walks of this tick and the tips to remember, by row:
//
//	a ref not in prev             walk it whole (From empty)
//	a ref whose tip moved         walk From..Tip
//	a ref whose tip is unchanged  nothing
//	a ref in prev, not listed     forgotten (the ref was deleted)
//
// Walks come in ref order; a listing entry repeated keeps its first tip.
func PlanBoxRefs(prev map[string]string, listing []BoxRef) ([]BoxRefWalk, map[string]string) {
	next := make(map[string]string, len(listing))
	var walks []BoxRefWalk
	for _, r := range listing {
		if r.Ref == "" || r.Tip == "" {
			continue
		}
		if _, dup := next[r.Ref]; dup {
			continue
		}
		next[r.Ref] = r.Tip
		old, seen := prev[r.Ref]
		claimed := strings.HasPrefix(r.Ref, boxWorktreePrefix)
		switch {
		case !seen:
			walks = append(walks, BoxRefWalk{Ref: r.Ref, Tip: r.Tip, RunID: BoxRunID(r.Ref), Claimed: claimed})
		case old != r.Tip:
			walks = append(walks, BoxRefWalk{Ref: r.Ref, Tip: r.Tip, From: old, RunID: BoxRunID(r.Ref), Claimed: claimed})
		}
	}
	sort.Slice(walks, func(i, j int) bool { return walks[i].Ref < walks[j].Ref })
	return walks, next
}

// CapBoxWalks keeps the first max walks of a tick (in PlanBoxRefs's ref
// order) and returns the rest, which wait for a later tick (lane sec-box
// audit finding 3). max <= 0 keeps every walk.
func CapBoxWalks(walks []BoxRefWalk, max int) (kept, deferred []BoxRefWalk) {
	if max <= 0 || len(walks) <= max {
		return walks, nil
	}
	return walks[:max], walks[max:]
}

// RotateBoxWalks orders a tick's walks (PlanBoxRefs's ref order) to start
// after the ref named after, wrapping round (lane LEFT-SEC, the P-102
// residual): with CapBoxWalks after it, a box that keeps moving its first
// refs no longer delays the rest, since each tick resumes where the last
// one stopped. after "" (no tick was cut short) keeps ref order.
func RotateBoxWalks(walks []BoxRefWalk, after string) []BoxRefWalk {
	if after == "" || len(walks) < 2 {
		return walks
	}
	i := sort.Search(len(walks), func(i int) bool { return walks[i].Ref > after })
	if i == 0 || i == len(walks) {
		return walks
	}
	out := make([]BoxRefWalk, 0, len(walks))
	out = append(out, walks[i:]...)
	return append(out, walks[:i]...)
}

// NextBoxCursor is the cursor the next tick resumes after: the last walk a
// tick kept when it deferred some, "" when it walked every one.
func NextBoxCursor(kept, deferred []BoxRefWalk) string {
	if len(deferred) == 0 || len(kept) == 0 {
		return ""
	}
	return kept[len(kept)-1].Ref
}

// KeepUnwalked is the tips to remember after a tick: next (PlanBoxRefs's)
// with every ref in left (deferred by the walk cap, or cut short by the
// tick's budget or commit cap) put back to its tip in prev, or forgotten
// when prev did not have it, so the next tick walks it again. The commits
// already recorded are skipped then (store.SecBoxCommitsScanned).
func KeepUnwalked(prev, next map[string]string, left []string) map[string]string {
	if len(left) == 0 {
		return next
	}
	out := make(map[string]string, len(next))
	for ref, tip := range next {
		out[ref] = tip
	}
	for _, ref := range left {
		if tip, ok := prev[ref]; ok {
			out[ref] = tip
			continue
		}
		delete(out, ref)
	}
	return out
}
