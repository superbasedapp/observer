//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/secscan/depdriver"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/gitmodules"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvnet"
)

// security_scan_submodules.go is the online check of a project's git
// submodules (spike CPP-0, docs/plans/spikes/CPP-0-online-cpp-deps-2026-11.md;
// ledger SECP-53), run only by a manual scan that asked for online
// matching (`observer security scan --online`, or the dashboard's Scan now
// with "Also check online", both through depsRunMatchers), after online
// matching, through the linked driver (depdriver.Env.Submodules).
//
// Locally, with no network: each .gitmodules file (the project root's, any
// the gap probe named, and those of checked-out submodules, at most
// depsSubmoduleMaxDepth levels) is read for its section names and paths
// (the url is skipped by the parser), and git lists the index's gitlinks
// at those paths through internal/gitview's read-only envelope (no hooks,
// no fsmonitor, no lazy fetch). Sent: only each distinct pinned commit id,
// one query per commit to api.osv.dev through the security.scan.osv.db
// lane's client, after the public self-test commit answered. The answers
// are mapped back to the submodule paths here. Gate: the online gate
// (`[security.deps] online` on and the disclosure, version 3, which names
// the commit ids, recorded) on an individual node; a managed node never
// runs it (its online matching goes to the org relay, which has no commit
// lookup), so its submodules stay gaps.

// The check's caps.
const (
	// depsSubmoduleMaxFiles caps the .gitmodules files read per project.
	depsSubmoduleMaxFiles = 64
	// depsSubmoduleMaxPins caps the submodules checked per project.
	depsSubmoduleMaxPins = 256
	// depsSubmoduleMaxDepth caps the nesting of submodules read.
	depsSubmoduleMaxDepth = 4
	// depsSubmoduleLsBytes caps git's listing of one file's gitlinks.
	depsSubmoduleLsBytes = 4 << 20
	// depsSubmoduleGitTimeout bounds one git listing.
	depsSubmoduleGitTimeout = 30 * time.Second
	// depsSubmoduleParallel is how many commit queries run at once.
	depsSubmoduleParallel = 4
	// depsSubmoduleDeadline bounds the whole check of one project.
	depsSubmoduleDeadline = 5 * time.Minute
)

// depsSubmoduleOSV is the lane's client for the commit queries, built once.
var depsSubmoduleOSV = sync.OnceValue(func() *osvnet.Client { return osvnet.New(osvnet.Options{}) })

// depsSubmoduleQuery is the check's one network call (a test swaps it):
// the OSV records for one commit id, and nothing else sent.
var depsSubmoduleQuery = func(ctx context.Context, commit string) ([]osvnet.CommitVuln, error) {
	return depsSubmoduleOSV().QueryCommit(ctx, commit)
}

// depsSubmoduleGit runs one read-only git listing in dir (a test swaps it).
var depsSubmoduleGit = func(ctx context.Context, dir string, args ...string) ([]byte, bool, error) {
	return gitview.RunReadOnlyNoLazyFetch(ctx, dir, depsSubmoduleLsBytes, depsSubmoduleGitTimeout, args...)
}

// submoduleMatcher returns the online submodule check, or nil on a managed
// node. The online gate is walked again per project at the call (a project
// section may forbid online checks there), and a closed gate leaves the
// response as it is: nothing is read and nothing is sent.
func (e *depsScanEnv) submoduleMatcher() depdriver.SubmoduleMatcher {
	if e.managed {
		return nil
	}
	return func(ctx context.Context, root string, resp depscan.ChildResponse) depscan.ChildResponse {
		if e.managed || e.onlineBlockedAt(root) != "" {
			return resp
		}
		return depscan.ApplySubmodules(resp, checkSubmodules(ctx, root, resp.Gaps))
	}
}

// checkSubmodules reads a project's submodule pins and checks them online.
// gaps are the response's gaps: a .gitmodules file the gap probe named is
// read too.
func checkSubmodules(ctx context.Context, root string, gaps []depscan.Gap) depscan.SubmoduleCheck {
	ctx, cancel := context.WithTimeout(ctx, depsSubmoduleDeadline)
	defer cancel()
	return querySubmodules(ctx, readSubmoduleFiles(ctx, root, submoduleSeeds(root, gaps)))
}

// submoduleFileState is one .gitmodules file: its pins and what of it could
// not be checked.
type submoduleFileState struct {
	rel   string
	depth int
	// read: the file and its gitlinks were read.
	read bool
	pins []gitmodules.Pin
	// unreadable counts pins that cannot be matched (a SHA-256 id, the pin
	// cap); failed counts pins whose query failed.
	unreadable, failed int
}

// submoduleSeeds are the .gitmodules files to start from: the root's own
// and every one the gap probe named, relative to the root, sorted.
func submoduleSeeds(root string, gaps []depscan.Gap) []string {
	set := map[string]bool{}
	if _, ok := submoduleNoLinkFile(root, gitmodules.FileName); ok {
		set[gitmodules.FileName] = true
	}
	for _, g := range gaps {
		if !depscan.OnlineCovers(g.Path) {
			continue
		}
		if rel, ok := gitmodules.CleanRel(g.Path); ok {
			set[rel] = true
		}
	}
	out := make([]string, 0, len(set))
	for rel := range set {
		out = append(out, rel)
	}
	sort.Strings(out)
	return out
}

// readSubmoduleFiles reads each seed's pins, then the .gitmodules of each
// checked-out submodule (breadth first, depth and count capped).
func readSubmoduleFiles(ctx context.Context, root string, seeds []string) []*submoduleFileState {
	queue := make([]*submoduleFileState, 0, len(seeds))
	for _, s := range seeds {
		queue = append(queue, &submoduleFileState{rel: s})
	}
	seen := map[string]bool{}
	var out []*submoduleFileState
	pins := 0
	for len(queue) > 0 {
		f := queue[0]
		queue = queue[1:]
		if seen[f.rel] {
			continue
		}
		seen[f.rel] = true
		out = append(out, f)
		if len(out) > depsSubmoduleMaxFiles {
			continue
		}
		ps, unmatchable, err := readSubmodulePins(ctx, root, f.rel)
		if err != nil {
			continue
		}
		f.read = true
		f.unreadable = len(unmatchable)
		for _, p := range ps {
			if pins >= depsSubmoduleMaxPins {
				f.unreadable++
				continue
			}
			pins++
			f.pins = append(f.pins, p)
			if f.depth+1 < depsSubmoduleMaxDepth {
				nested := path.Join(p.Path, gitmodules.FileName)
				if _, ok := submoduleNoLinkFile(root, nested); ok {
					queue = append(queue, &submoduleFileState{rel: nested, depth: f.depth + 1})
				}
			}
		}
	}
	return out
}

// errSubmoduleListTooLarge is a gitlink listing over its cap.
var errSubmoduleListTooLarge = errors.New("the gitlink listing is over its cap")

// readSubmodulePins reads one .gitmodules file and the gitlinks git lists
// for its paths in the file's directory, and joins them.
func readSubmodulePins(ctx context.Context, root, rel string) ([]gitmodules.Pin, []string, error) {
	body, err := readSubmoduleFile(root, rel)
	if err != nil {
		return nil, nil, err
	}
	entries := gitmodules.Parse(body)
	if len(entries) == 0 {
		return nil, nil, nil
	}
	dir := path.Dir(rel)
	out, overflow, err := depsSubmoduleGit(ctx, filepath.Join(root, filepath.FromSlash(dir)), gitmodules.LsFilesArgs(gitmodules.Paths(entries))...)
	if err != nil {
		return nil, nil, err
	}
	if overflow {
		return nil, nil, errSubmoduleListTooLarge
	}
	pins, unmatchable := gitmodules.Join(dir, entries, gitmodules.ParseLsFiles(out))
	return pins, unmatchable, nil
}

// errSubmoduleFileRefused is a .gitmodules path that is not a regular file
// reached without a symbolic link, or one over the cap.
var errSubmoduleFileRefused = errors.New("not a regular .gitmodules file inside the project")

// submoduleNoLinkFile returns the absolute path of rel under root when
// every component below the root is a directory, or the last a regular
// file, with no symbolic link on the way (a submodule can never be one).
func submoduleNoLinkFile(root, rel string) (string, bool) {
	clean, ok := gitmodules.CleanRel(rel)
	if !ok {
		return "", false
	}
	parts := strings.Split(clean, "/")
	cur := root
	for i, p := range parts {
		cur = filepath.Join(cur, p)
		fi, err := os.Lstat(cur)
		if err != nil || fi.Mode()&os.ModeSymlink != 0 {
			return "", false
		}
		if last := i == len(parts)-1; (last && !fi.Mode().IsRegular()) || (!last && !fi.IsDir()) {
			return "", false
		}
	}
	return cur, true
}

// readSubmoduleFile reads one .gitmodules file, capped.
func readSubmoduleFile(root, rel string) ([]byte, error) {
	abs, ok := submoduleNoLinkFile(root, rel)
	if !ok {
		return nil, errSubmoduleFileRefused
	}
	f, err := os.Open(abs) //nolint:gosec // G304: the project's own .gitmodules, reached with no symbolic link; only parsed.
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, gitmodules.MaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > gitmodules.MaxFileBytes {
		return nil, errSubmoduleFileRefused
	}
	return b, nil
}

// submoduleAnswer is one commit's answer.
type submoduleAnswer struct {
	vulns []osvnet.CommitVuln
	err   error
}

// querySubmodules sends the self-test commit, then, only if it answered
// with its advisory, each distinct pinned commit (at most
// depsSubmoduleParallel at a time), and builds the check's answer.
func querySubmodules(ctx context.Context, files []*submoduleFileState) depscan.SubmoduleCheck {
	var c depscan.SubmoduleCheck
	seen := map[string]bool{}
	var commits []string
	for _, f := range files {
		for _, p := range f.pins {
			if !seen[p.Commit] {
				seen[p.Commit] = true
				commits = append(commits, p.Commit)
			}
		}
	}
	if len(commits) == 0 {
		// Nothing to send: the files are covered (or gaps) without a query.
		for _, f := range files {
			finishSubmoduleFile(&c, f)
		}
		return c
	}
	c.Ran = true
	canary, err := depsSubmoduleQuery(ctx, depscan.SubmoduleCanary.Version)
	if err != nil {
		c.MatchError = true
	} else {
		c.CanaryHit = submoduleAdvisoryIn(canary, depscan.SubmoduleCanary.Advisory)
	}
	if !c.CanaryHit {
		// No project commit is sent when the self-test did not answer.
		for _, f := range files {
			f.failed += len(f.pins)
			finishSubmoduleFile(&c, f)
		}
		return c
	}
	answers := make(map[string]submoduleAnswer, len(commits))
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, depsSubmoduleParallel)
	)
	for _, commit := range commits {
		wg.Add(1)
		go func(commit string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			v, err := depsSubmoduleQuery(ctx, commit)
			mu.Lock()
			answers[commit] = submoduleAnswer{vulns: v, err: err}
			mu.Unlock()
		}(commit)
	}
	wg.Wait()
	c.Epoch = "online:" + osvnet.APIHost + " " + time.Now().UTC().Format(time.RFC3339)
	for _, f := range files {
		for _, p := range f.pins {
			a := answers[p.Commit]
			if a.err != nil {
				f.failed++
				continue
			}
			c.Pins = append(c.Pins, depscan.SubmodulePin{Path: p.Path, Name: p.Name, Commit: p.Commit, Advisories: submoduleAdvisories(a.vulns)})
		}
		finishSubmoduleFile(&c, f)
	}
	return c
}

// finishSubmoduleFile records one file as covered (read, every pin checked)
// or as the gaps of what was not.
func finishSubmoduleFile(c *depscan.SubmoduleCheck, f *submoduleFileState) {
	switch {
	case !f.read:
		c.Unchecked = append(c.Unchecked, depscan.Gap{Path: f.rel, Reason: depscan.ReasonSubmodulePinsUnreadable})
		return
	case f.unreadable == 0 && f.failed == 0:
		c.Covered = append(c.Covered, f.rel)
		return
	}
	if f.unreadable > 0 {
		c.Unchecked = append(c.Unchecked, depscan.Gap{Path: f.rel, Reason: depscan.ReasonSubmodulePinsUnreadable, Packages: f.unreadable})
	}
	if f.failed > 0 {
		c.Unchecked = append(c.Unchecked, depscan.Gap{Path: f.rel, Reason: depscan.ReasonSubmoduleCheckFailed, Packages: f.failed})
	}
}

// submoduleAdvisoryIn reports whether id is one of the records or their
// aliases.
func submoduleAdvisoryIn(vulns []osvnet.CommitVuln, id string) bool {
	for _, v := range vulns {
		if v.ID == id {
			return true
		}
		for _, a := range v.Aliases {
			if a == id {
				return true
			}
		}
	}
	return false
}

// submoduleAdvisories maps one commit's records onto advisories (the
// finding path checks every id's charset).
func submoduleAdvisories(vulns []osvnet.CommitVuln) []depscan.Advisory {
	out := make([]depscan.Advisory, 0, len(vulns))
	for _, v := range vulns {
		out = append(out, depscan.Advisory{ID: v.ID, Aliases: append([]string(nil), v.Aliases...), Severity: v.Severity})
	}
	return out
}
