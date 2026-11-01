package commitscan

import (
	"bytes"
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/commitlog"
)

// boxrefs.go hands the commits a sandbox box returned to the OnBoxCommit seam
// (security plan 7.10 revision 2.3 M7; sandbox plan section 6; lane
// SEC-F2B): an agent working in a sandbox copy workspace commits there, and
// its work reaches the source repository as refs/observer/sandbox/<run>
// (internal/workspace.ReturnRefPrefix) or, for the worktree source, the
// branch observer-sandbox/<run>/<label> (internal/workspace.
// WorktreeBranchPrefix), not on HEAD. So the change record of a box commit
// is made when it returns, not only once it is merged.
//
// HEAD-only stays HEAD-only: box commits are never written to the commit
// ledger (Sink), never change the watermark and never count for the
// Projects page; they are only offered to OnBoxCommit, with Root.BoxRef
// set. Nothing is listed unless BoxActive answers true (lane SEC-F2B audit
// finding 4: no `git for-each-ref` per root per tick on an install without
// security.provenance). Only the commits a box ref has that HEAD does not
// (`git log <tip> ^HEAD`) are read, at most MaxPerTick per ref and
// boxMaxRefs refs per scan, and only when the ref's tip moved since its
// commits were last decided. A failure here never fails the scan.
//
// The ref listing is not shared with SEC-BOX's (internal/secquickscan
// ListBoxRefs and ParseBoxRefList): that package belongs to the security
// pillar and imports internal/policy and the detectors, which this core
// package must not link; the two keep the same namespaces, pinned by
// cmd/observer's TestBoxRefPrefixesAgree.

// The box ref namespaces, the same strings as internal/workspace's
// ReturnRefPrefix and "refs/heads/" + WorktreeBranchPrefix (this package
// imports no workspace code).
var boxRefPrefixes = []string{"refs/observer/sandbox/", "refs/heads/observer-sandbox/"}

// BoxRefPrefixes returns a copy of the box ref namespaces this package lists.
func BoxRefPrefixes() []string { return append([]string(nil), boxRefPrefixes...) }

// boxMaxRefs bounds the box refs read per scan.
const boxMaxRefs = 64

// boxRefRE is the ref shape read: a namespace, then clean segments.
var boxRefRE = regexp.MustCompile(`^refs/(observer/sandbox|heads/observer-sandbox)/[A-Za-z0-9_][A-Za-z0-9_./-]{0,200}$`)

var boxSHARE = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// BoxRunID is the sandbox run id a box ref names (the segment after the
// namespace), "" for any other ref.
func BoxRunID(ref string) string {
	for _, p := range boxRefPrefixes {
		if rest, ok := strings.CutPrefix(ref, p); ok {
			id, _, _ := strings.Cut(rest, "/")
			return id
		}
	}
	return ""
}

// notifyBoxCommits offers the commits of every moved box ref to
// OnBoxCommit, only while BoxActive answers true.
func (s *Scanner) notifyBoxCommits(ctx context.Context, root Root, res Result) {
	if s.opts.OnBoxCommit == nil || s.opts.BoxActive == nil || ctx.Err() != nil || !s.opts.BoxActive() {
		return
	}
	args := append([]string{"for-each-ref", "--format=%(objectname) %(refname)", "--count=" + strconv.Itoa(boxMaxRefs)}, boxRefPrefixes...)
	out, _, err := s.opts.Exec(ctx, root.RootPath, s.opts.MaxOutputBytes, args...)
	if err != nil {
		return
	}
	for _, line := range bytes.Split(out, []byte("\n")) {
		sha, ref, ok := strings.Cut(strings.TrimSpace(string(line)), " ")
		if !ok || !boxSHARE.MatchString(sha) || !boxRefRE.MatchString(ref) || strings.Contains(ref, "..") {
			continue
		}
		key := root.RootPath + "\x00" + ref
		if prev, seen := s.boxTips.Load(key); seen && prev.(string) == sha {
			continue
		}
		if s.offerBoxRef(ctx, root, ref, sha, res) {
			s.boxTips.Store(key, sha)
		}
	}
}

// offerBoxRef reads one box ref's commits HEAD does not have and offers
// them; false when they could not be read or the seam did not decide every
// one (retried next scan).
func (s *Scanner) offerBoxRef(ctx context.Context, root Root, ref, tip string, res Result) bool {
	out, over, err := s.opts.Exec(ctx, root.RootPath, s.opts.MaxOutputBytes,
		commitlog.PageArgsRange(tip, res.HeadSHA, s.opts.MaxPerTick, 0, subtreePathspec(res.Subtree))...)
	if err != nil {
		return false
	}
	commits, err := commitlog.ParseLog(out, over)
	if err != nil {
		return false
	}
	if commits, err = rebaseSubtree(commits, res.Subtree); err != nil {
		return false
	}
	box := root
	box.BoxRef = ref
	decided := true
	for _, c := range commits {
		if ctx.Err() != nil {
			return false
		}
		if !s.opts.OnBoxCommit(ctx, box, c) {
			decided = false
		}
	}
	return decided
}
