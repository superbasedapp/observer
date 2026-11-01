package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/projectmatch"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// project_audience.go is the node's project matcher (security plan section
// 7.11, spike JSP-10, lane sec-p): it matches a directory's identity against
// the org-signed project mapping and writes the result as that project root's
// match record (projectmatch.MatchFile), which the guard's org project layer
// and the security posture writer read. It is the ONE writer of the match
// records. It runs at launch (the project.match row of the launch-gate table)
// and from the daemon's project-audience-match loop for every recently active
// project root, so a session that starts without a launch is matched within
// one interval; until then the hook matches from the mapping itself.
//
// Lane sec-p2a: for a root the mapping does not match, the launch row first
// runs the root-commit read once (projectRootCommit: git rev-list in the
// read-only git envelope, 2 s timeout, cached in the store behind its
// 7-day fence; the fork, mirror and remote-removed copy hard case) and then,
// like the loop at session start, asks the org server's signed resolve call
// (POST /api/agent/project/resolve), at most once per root while its answer is
// current. Never on the hook path.
//
// Inert until the node holds a v3 delivery (an org that published a
// project-scoped guard bundle): with no project binding on the cached bundle
// it reads one file and writes nothing.

// projectAudienceMatchEvery is the daemon loop's interval.
const projectAudienceMatchEvery = 30 * time.Second

// projectAudienceActiveWithin is how recently a project root must have had a
// session to be matched by the loop.
const projectAudienceActiveWithin = 24 * time.Hour

// projectMatcher matches directories for one node.
type projectMatcher struct {
	bundlePath string
	st         *store.Store
	now        func() time.Time
	// resolve is the signed resolve call (orgclient.ResolveProject), set at
	// launch and in the daemon loop (session start); nil never calls it.
	resolve func(ctx context.Context, req orgcontract.ProjectResolveRequest) (orgcontract.ProjectResolveAnswer, error)
	// rootCommit runs projectRootCommit (2 s timeout) for an unmatched
	// repository whose root commit the store has not cached. Set at LAUNCH
	// only (security plan 7.11 hard cases); never on the hook path.
	rootCommit func(ctx context.Context, root string) (string, error)
}

// projectResolveUnknownRetry is how long an unknown record (a truncated
// mapping and a failed resolve call) stands before the matcher asks again.
const projectResolveUnknownRetry = 10 * time.Minute

// projectResolveBackoffMax caps the backoff of a failed resolve below the cap
// (projectResolveBackoff).
const projectResolveBackoffMax = 6 * time.Hour

// projectResolveFailedBelowCap is the reason of the record a failed resolve
// below the cap leaves: not unknown (the mapping lists every project that
// reaches the member, so the directory is unmatched), only remembered so the
// matcher does not ask again before the record expires.
const projectResolveFailedBelowCap = "resolve_failed_below_cap"

// projectResolveTimeout bounds one resolve call at launch or in the loop.
const projectResolveTimeout = 3 * time.Second

// composedProjectBundle reads the cached org bundle (ok=false when absent,
// unreadable or not v3). The guard re-verifies the bundle and every envelope
// before it loads anything; the matcher only names projects, and checks a
// resolve answer against this bundle's key, epoch and version.
func composedProjectBundle(bundlePath string) (orgcontract.PolicyBundle, bool) {
	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		return orgcontract.PolicyBundle{}, false
	}
	var b orgcontract.PolicyBundle
	if json.Unmarshal(raw, &b) != nil || b.ProjectBinding == nil {
		return orgcontract.PolicyBundle{}, false
	}
	return b, true
}

// composedProjectBinding is composedProjectBundle's binding and version.
func composedProjectBinding(bundlePath string) (*orgcontract.ProjectBinding, int64) {
	b, ok := composedProjectBundle(bundlePath)
	if !ok {
		return nil, 0
	}
	return b.ProjectBinding, b.Version
}

// match computes dir's match record, walked top-down: the signed mapping
// (through the node index when it is of this delivery); for an unmatched
// repository, the root commit run once at launch, then the mapping again;
// then a current resolve record already held; then the resolve call. ok is
// false when the node holds no v3 delivery. prev is the record on disk (nil
// when none).
func (m projectMatcher) match(ctx context.Context, dir string, prev *projectmatch.MatchFile) (projectmatch.MatchFile, bool, error) {
	composed, held := composedProjectBundle(m.bundlePath)
	if !held {
		return projectmatch.MatchFile{}, false, nil
	}
	pb := composed.ProjectBinding
	// A stored root that is not a path (FU-193's "Xcode (project
	// unknown)") would be resolved against the daemon's working directory
	// (audit row 7 on the w13 hand-back): nothing to match.
	if !git.HostRooted(dir) {
		return projectmatch.MatchFile{}, false, nil
	}
	s, err := projectmatch.SignalsFor(dir, "")
	if err != nil {
		return projectmatch.MatchFile{}, false, err
	}
	// The store's cached root commit, keyed by the identity root (the main
	// repository for a linked worktree): a fork, mirror or remote-less copy
	// still matches by root commit, with no exec on this path.
	if m.st != nil {
		if sha, cerr := m.st.CachedRootCommit(ctx, s.Root); cerr == nil && sha != "" {
			s.RootCommitHash = projectmatch.Hash(sha)
		}
	}
	now := m.now().UTC()
	rec := projectmatch.MatchFile{
		ProjectRootHash: projectmatch.RootHash(s.Root), Epoch: pb.Epoch, MappingDigest: pb.MappingDigest, MatchedAt: now,
		Source: projectmatch.SourceMapping,
	}
	mf, err := m.mapping(pb)
	if err != nil {
		return projectmatch.MatchFile{}, false, err
	}
	rec.ValidUntil = mf.ValidUntil().UTC()
	ix := projectmatch.BuildIndex(mf.Mapping)
	lookup := func() ([]string, error) {
		if m.st != nil {
			lk, lerr := m.st.LookupOrgProjects(ctx, s.RemoteLookupHashes(), s.RootCommitHash)
			if lerr != nil {
				return nil, lerr
			}
			if lk.Epoch == pb.Epoch && lk.MappingDigest == pb.MappingDigest {
				return lk.OrgProjectIDs, nil
			}
		}
		return ix.Match(s), nil
	}
	ids, err := lookup()
	if err != nil {
		return projectmatch.MatchFile{}, false, err
	}
	if len(ids) == 0 && m.launchRootCommit(ctx, &s) {
		if ids, err = lookup(); err != nil {
			return projectmatch.MatchFile{}, false, err
		}
	}
	if len(ids) > 0 || !s.HasIdentity() {
		rec.OrgProjectIDs = ids
		return rec, true, nil
	}
	// Unmatched by the mapping. A resolve answer still current for this
	// delivery stands (the loop does not ask again every interval).
	if prev != nil && prev.Source == projectmatch.SourceResolve && prev.CurrentFor(pb, composed.Version) && now.Before(prev.ValidUntil) {
		return *prev, true, nil
	}
	if m.resolve == nil {
		return m.unmatched(rec, mf, now, "", prev), true, nil
	}
	ans, rerr := m.callResolve(ctx, s, composed, now)
	if rerr != nil {
		return m.unmatched(rec, mf, now, rerr.Error(), prev), true, nil
	}
	rec.Source = projectmatch.SourceResolve
	rec.BundleVersion = composed.Version
	rec.OrgProjectIDs = ans.OrgProjectIDs
	if exp := time.Unix(ans.ExpiresAt, 0).UTC(); exp.Before(rec.ValidUntil) {
		rec.ValidUntil = exp
	}
	return rec, true, nil
}

// mapping reads the cached mapping file and checks it belongs to the
// delivery in force. It bounds a record's lifetime (the hook trusts a record
// only inside it) and is the fallback when the index is of another delivery
// (or there is no store).
func (m projectMatcher) mapping(pb *orgcontract.ProjectBinding) (projectmatch.MappingFile, error) {
	raw, err := os.ReadFile(projectmatch.LayoutFor(m.bundlePath).MappingPath())
	if err != nil {
		return projectmatch.MappingFile{}, err
	}
	mf, err := projectmatch.DecodeMappingFile(raw)
	if err != nil {
		return projectmatch.MappingFile{}, err
	}
	if orgcontract.ProjectMappingDigest(mf.Mapping) != pb.MappingDigest {
		return projectmatch.MappingFile{}, errors.New("project audience: the cached mapping is of another delivery")
	}
	return mf, nil
}

// launchRootCommit is the fork, mirror and remote-removed copy hard case:
// only the root commit can match such a repository, so at launch (rootCommit
// set) it runs once, behind the store's 7-day fence, is cached in the store,
// and s gains its hash. It reports whether s changed (match again).
func (m projectMatcher) launchRootCommit(ctx context.Context, s *projectmatch.Signals) bool {
	if m.rootCommit == nil || m.st == nil || !s.IsGit || s.RootCommitHash != "" {
		return false
	}
	if due, err := m.st.LaunchRootCommitDue(ctx, s.Root); err != nil || !due {
		return false
	}
	sha, _ := m.rootCommit(ctx, s.Root)
	_ = m.st.CacheLaunchRootCommit(ctx, s.Root, sha)
	if sha == "" {
		return false
	}
	s.RootCommitHash = projectmatch.Hash(sha)
	return true
}

// unmatched is the record for a repository the mapping did not match and no
// resolve answer covers: unmatched when the mapping lists every project that
// reaches the member, unknown when it is truncated (security plan PR14:
// above the cap "nothing matched" is not an answer). An unknown record is a
// resolve record of this version that expires after
// projectResolveUnknownRetry, so the matcher asks again then.
//
// Below the cap a failed resolve call is remembered too (lane sec-p2a audit
// finding 4): an unmatched resolve record of this version, never unknown,
// standing for projectResolveBackoff, so neither the 30 s loop nor each launch
// asks again (and waits up to projectResolveTimeout) before it expires.
func (m projectMatcher) unmatched(rec projectmatch.MatchFile, mf projectmatch.MappingFile, now time.Time, why string, prev *projectmatch.MatchFile) projectmatch.MatchFile {
	composed, _ := composedProjectBundle(m.bundlePath)
	if !mf.Mapping.Truncated {
		if why == "" {
			return rec
		}
		rec.Source = projectmatch.SourceResolve
		rec.BundleVersion = composed.Version
		rec.Reason = projectResolveFailedBelowCap
		if retry := now.Add(projectResolveBackoff(prev, composed.Version)); retry.Before(rec.ValidUntil) {
			rec.ValidUntil = retry
		}
		return rec
	}
	rec.Source = projectmatch.SourceResolve
	rec.BundleVersion = composed.Version
	rec.Unknown = true
	rec.Reason = projectmatch.ReasonResolveFailed
	if why == "" {
		rec.Reason = projectmatch.ReasonTruncated
	}
	if retry := now.Add(projectResolveUnknownRetry); retry.Before(rec.ValidUntil) {
		rec.ValidUntil = retry
	}
	return rec
}

// projectResolveBackoff is how long a failed resolve below the cap stands:
// projectResolveUnknownRetry the first time, then twice the previous failed
// record's span, capped at projectResolveBackoffMax.
func projectResolveBackoff(prev *projectmatch.MatchFile, version int64) time.Duration {
	d := projectResolveUnknownRetry
	if prev != nil && prev.Source == projectmatch.SourceResolve && prev.Reason == projectResolveFailedBelowCap && prev.BundleVersion == version {
		if span := prev.ValidUntil.Sub(prev.MatchedAt); span >= d {
			d = 2 * span
		}
	}
	if d > projectResolveBackoffMax {
		d = projectResolveBackoffMax
	}
	return d
}

// callResolve asks the org server, checks the answer against the composed
// bundle in force (projectmatch.AcceptResolve), and writes the matched
// projects' envelopes into the resolved directory.
func (m projectMatcher) callResolve(ctx context.Context, s projectmatch.Signals, composed orgcontract.PolicyBundle, now time.Time) (orgcontract.ProjectResolveAnswer, error) {
	nonce, err := orgclient.NewProjectResolveNonce()
	if err != nil {
		return orgcontract.ProjectResolveAnswer{}, err
	}
	req := orgcontract.ProjectResolveRequest{RootCommitHash: s.RootCommitHash, Nonce: nonce}
	for _, h := range s.RemoteLookupHashes() {
		if h != "" && len(req.RemoteHashes) < orgcontract.MaxProjectResolveHashes {
			req.RemoteHashes = append(req.RemoteHashes, h)
		}
	}
	rctx, cancel := context.WithTimeout(ctx, projectResolveTimeout)
	defer cancel()
	ans, err := m.resolve(rctx, req)
	if err != nil {
		return orgcontract.ProjectResolveAnswer{}, err
	}
	key, err := base64.RawURLEncoding.DecodeString(composed.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return orgcontract.ProjectResolveAnswer{}, errors.New("project audience: the composed bundle carries no usable key")
	}
	if err := projectmatch.AcceptResolve(ans, req, composed, ed25519.PublicKey(key), now); err != nil {
		return orgcontract.ProjectResolveAnswer{}, err
	}
	l := projectmatch.LayoutFor(m.bundlePath)
	if err := os.MkdirAll(l.ResolvedDir(), 0o700); err != nil {
		return orgcontract.ProjectResolveAnswer{}, err
	}
	for _, env := range ans.Envelopes {
		raw, merr := json.Marshal(env)
		if merr != nil {
			return orgcontract.ProjectResolveAnswer{}, merr
		}
		if werr := fsatomic.WriteFile(l.ResolvedEnvelopePath(env.ProjectBinding.OrgProjectID), raw, fsatomic.Options{TempPattern: ".org-project-resolved-*.tmp"}); werr != nil {
			return orgcontract.ProjectResolveAnswer{}, werr
		}
	}
	return ans, nil
}

// matchAndRecord matches dir and writes its record when it changed (the
// matched set, epoch or digest; the time alone never rewrites the file).
func (m projectMatcher) matchAndRecord(ctx context.Context, dir string) (projectmatch.MatchFile, bool, error) {
	// Never a root that is not a path: git.ResolveIdentity and SignalsFor
	// would read it relative to the working directory (audit row 7).
	if !git.HostRooted(dir) {
		return projectmatch.MatchFile{}, false, nil
	}
	var prev *projectmatch.MatchFile
	if id, ierr := git.ResolveIdentity(dir, git.IdentityOptions{SkipContentFingerprint: true}); ierr == nil {
		if raw, rerr := os.ReadFile(projectmatch.LayoutFor(m.bundlePath).MatchPath(projectmatch.RootHash(id.Root))); rerr == nil {
			if p, derr := projectmatch.DecodeMatchFile(raw); derr == nil {
				prev = &p
			}
		}
	}
	rec, ok, err := m.match(ctx, dir, prev)
	if err != nil || !ok {
		return rec, ok, err
	}
	path := projectmatch.LayoutFor(m.bundlePath).MatchPath(rec.ProjectRootHash)
	if prev != nil && sameMatch(*prev, rec) {
		return *prev, true, nil
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return rec, true, err
	}
	if err := os.MkdirAll(projectmatch.LayoutFor(m.bundlePath).MatchDir(), 0o700); err != nil {
		return rec, true, err
	}
	return rec, true, fsatomic.WriteFile(path, raw, fsatomic.Options{TempPattern: ".org-project-match-*.tmp"})
}

// sameMatch compares two records ignoring when they were taken.
func sameMatch(a, b projectmatch.MatchFile) bool {
	a.MatchedAt, b.MatchedAt = time.Time{}, time.Time{}
	if a.Source == "" {
		a.Source = projectmatch.SourceMapping
	}
	if b.Source == "" {
		b.Source = projectmatch.SourceMapping
	}
	if len(a.OrgProjectIDs) == 0 && len(b.OrgProjectIDs) == 0 {
		a.OrgProjectIDs, b.OrgProjectIDs = nil, nil
	}
	return reflect.DeepEqual(a, b)
}

// gateProjectMatch is the project.match launch-gate row: it records the
// launch directory's project audience match before the agent starts, so a
// new clone of a known repository is matched before its first session. It
// never refuses and never warns: a match that cannot be computed leaves the
// hook to match from the mapping, and the org, team and member layers apply
// either way.
func gateProjectMatch(r *launchGateRun) launchGateStep {
	if r.launchDir == nil {
		return launchGateStep{}
	}
	bundlePath := orgBundleCachePath(r.cfg)
	if bundlePath == "" {
		return launchGateStep{}
	}
	dir, err := r.launchDir()
	if err != nil {
		return launchGateStep{}
	}
	var st *store.Store
	if r.database != nil {
		st = store.New(r.database)
	}
	m := projectMatcher{bundlePath: bundlePath, st: st, now: time.Now, rootCommit: projectRootCommit}
	if st != nil && r.cfg.OrgClient.Enabled {
		m.resolve = projectResolveCall(r.cfg, st)
	}
	_, _, _ = m.matchAndRecord(r.ctx, dir)
	return launchGateStep{}
}

// projectRootCommitTimeout bounds the launch-time root-commit read (the
// git.DefaultRootCommit bound).
const projectRootCommitTimeout = 2 * time.Second

// projectRootCommit is git.DefaultRootCommit run through the read-only git
// envelope (gitview.RunReadOnlyEnv: no optional locks, no pager, fsmonitor and
// hooks off, capped output, a bounded wait) with the git hardening
// environment (extrun.GitHardeningEnv: no system or global config), because
// the repository is the developer's own working copy of an UNTRUSTED
// project (lane sec-p2a audit finding 6). It returns the smallest root commit
// SHA (several after an unrelated-histories merge), or an error.
func projectRootCommit(ctx context.Context, root string) (string, error) {
	out, _, err := gitview.RunReadOnlyEnv(ctx, root, 64<<10, projectRootCommitTimeout,
		extrun.GitHardeningEnv(runtime.GOOS), "rev-list", "--max-parents=0", "HEAD")
	if err != nil {
		return "", fmt.Errorf("projectRootCommit: %w", err)
	}
	shas := strings.Fields(string(out))
	if len(shas) == 0 {
		return "", fmt.Errorf("projectRootCommit: no root commit found in %s", root)
	}
	sort.Strings(shas)
	return shas[0], nil
}

// projectResolveCall builds the resolve call over a short-lived org client
// (the launcher's own process). The bearer store opens only when the call is
// made: a launch in a repository the mapping matched never touches it.
func projectResolveCall(cfg config.Config, st *store.Store) func(context.Context, orgcontract.ProjectResolveRequest) (orgcontract.ProjectResolveAnswer, error) {
	return func(ctx context.Context, req orgcontract.ProjectResolveRequest) (orgcontract.ProjectResolveAnswer, error) {
		bs := orgclient.OpenBearerStoreQuiet(cfg.OrgClient.KeychainID, filepath.Dir(cfg.Observer.DBPath))
		return orgclient.New(cfg.OrgClient, st, bs, version, nil, nil).ResolveProject(ctx, req)
	}
}

// runProjectAudienceMatch is the daemon's project-audience-match loop: every
// interval it matches each project root with a session in the last day. It
// does nothing while the node holds no v3 delivery, and it never returns an
// error (a failed root is retried next interval).
//
// resolve, when non-nil, is the daemon's org client's resolve call: a root
// the mapping does not match and that holds no current resolve answer is
// resolved here (session start). The loop never runs git.
func runProjectAudienceMatch(ctx context.Context, bundlePath string, st *store.Store, resolve func(context.Context, orgcontract.ProjectResolveRequest) (orgcontract.ProjectResolveAnswer, error)) {
	if bundlePath == "" || st == nil {
		return
	}
	m := projectMatcher{bundlePath: bundlePath, st: st, now: time.Now, resolve: resolve}
	t := time.NewTicker(projectAudienceMatchEvery)
	defer t.Stop()
	for {
		if pb, _ := composedProjectBinding(bundlePath); pb != nil {
			if roots, err := st.ProjectAudienceRoots(ctx, time.Now().Add(-projectAudienceActiveWithin)); err == nil {
				for _, root := range roots {
					if ctx.Err() != nil {
						return
					}
					_, _, _ = m.matchAndRecord(ctx, root)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// projectMatchForPosture reads a project root's current match record by its
// root hash, for the security posture writer's reserved fields (security
// plan section 4.8). A record of another delivery than the cached bundle
// reads as no match.
func projectMatchForPosture(bundlePath string) func(projectRootHash string) ([]string, uint64) {
	return func(projectRootHash string) ([]string, uint64) {
		if bundlePath == "" {
			return nil, 0
		}
		pb, _ := composedProjectBinding(bundlePath)
		if pb == nil {
			return nil, 0
		}
		raw, err := os.ReadFile(projectmatch.LayoutFor(bundlePath).MatchPath(projectRootHash))
		if err != nil {
			return nil, 0
		}
		rec, err := projectmatch.DecodeMatchFile(raw)
		_, version := composedProjectBinding(bundlePath)
		if err != nil || !rec.CurrentFor(pb, version) || rec.Unknown || pb.Epoch < 0 {
			return nil, 0
		}
		return rec.OrgProjectIDs, uint64(pb.Epoch)
	}
}
