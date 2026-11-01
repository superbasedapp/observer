//go:build !sbo_omit_security

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	obsgit "github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secchange"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_provenance_writers.go is the cmd side of the two repository
// writers of the AI change records (security plan 7.10 "Where it lives";
// roadmap section 11 item 5): git notes under refs/notes/observer, written
// by the provenance loop, and the `Assisted-by: AGENT:MODEL` trailer, added
// by a prepare-commit-msg hook block while an agent's commit is being
// made. Both only in a repository a person consented for, on one seam the
// CLI and the dashboard share (provenanceSetConsent). Neither ever
// rewrites history, and neither writes on a commit the agent did not make:
// a note is written only for a commit that has a record (the attribution
// tied it to an agent session), and the trailer only when guard and the
// commit gate allowed the agent's own `git commit` in that repository
// moments before, on the same HEAD and index (audit finding F3).

// provenanceNotesEvery is the notes loop's period; the first pass runs
// after provenanceNotesFirst.
const (
	provenanceNotesEvery = 2 * time.Minute
	provenanceNotesFirst = 30 * time.Second
	provenanceNotesBatch = 50
)

// provenanceGitWrite is the one git invocation that writes (secsvc
// GitWriter): repository hooks off, the identity of the notes commit fixed
// to Observer's, no prompt, no pager.
func provenanceGitWrite(ctx context.Context, root string, stdin []byte, timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	full := append([]string{
		"-C", root,
		"-c", "core.hooksPath=" + os.DevNull, "-c", "core.fsmonitor=false", "-c", "core.pager=cat",
		"-c", "user.name=SuperBased Observer", "-c", "user.email=observer@localhost.invalid",
	}, args...)
	cmd := exec.CommandContext(ctx, "git", full...) //nolint:gosec // G204: fixed program, arguments built from fixed verbs and a validated commit id.
	cmd.Stdin = bytes.NewReader(stdin)
	cmd.Env = append(provenanceGitEnv(os.Environ()), "LC_ALL=C", "GIT_TERMINAL_PROMPT=0")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

// provenanceGitEnv drops the variables that would point git at another
// repository or index (set while a hook runs).
func provenanceGitEnv(env []string) []string {
	drop := map[string]bool{"GIT_DIR": true, "GIT_WORK_TREE": true, "GIT_INDEX_FILE": true, "GIT_COMMON_DIR": true, "GIT_OBJECT_DIRECTORY": true, "GIT_NOTES_REF": true}
	out := env[:0:0]
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if !drop[k] {
			out = append(out, kv)
		}
	}
	return out
}

// provenanceNotesLoop writes the consented repositories' pending notes
// until ctx ends.
func provenanceNotesLoop(ctx context.Context, svc *provenanceSvc) {
	t := time.NewTimer(provenanceNotesFirst)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		// A managed node keeps its key certified (re-enrolled after a
		// rotation, renewed before the 90 days run out; lane SEC-F2B).
		if err := svc.enrolKey(ctx); err != nil {
			svc.logger.Warn("security provenance: key enrolment with the org failed; retried later", "err", err)
		}
		if n, err := svc.writeNotes(ctx, provenanceGitWrite); err != nil {
			svc.logger.Warn("security provenance: notes not written", "err", err)
		} else if n > 0 {
			svc.logger.Info("security provenance: git notes written", "notes", n)
		}
		t.Reset(provenanceNotesEvery)
	}
}

// writeNotes writes every consented repository's records that have no note
// yet. A record whose commit git cannot find (rewritten away) is left
// pending and retried; nothing is forced.
func (p *provenanceSvc) writeNotes(ctx context.Context, write secsvc.GitWriter) (int, error) {
	consents, err := p.st.ChangeConsents(ctx)
	if err != nil {
		return 0, err
	}
	written := 0
	for _, c := range consents {
		if !c.Notes || c.RootPath == "" {
			continue
		}
		recs, err := p.st.ChangeRecordsWithoutNote(ctx, c.ProjectRootHash, provenanceNotesBatch)
		if err != nil {
			return written, err
		}
		for _, r := range recs {
			ok, err := secsvc.WriteChangeNote(ctx, secsvc.GitRunner(p.git), write, c.RootPath, r.CommitSHA, r.Envelope)
			if err != nil {
				p.logger.Debug("security provenance: note not written", "commit", r.CommitSHA, "err", err)
				continue
			}
			if err := p.st.MarkChangeNoteWritten(ctx, r.ID, p.now()); err != nil {
				return written, err
			}
			if ok {
				written++
			}
		}
	}
	return written, nil
}

// provenanceDirs are the marker directories under the security layout:
// the per-repository trailer flags the hook stats, and the pending
// agent-commit markers.
func provenanceTrailerFlag(layoutDir, rootHash string) string {
	return filepath.Join(layoutDir, "provenance", "trailer", rootHash)
}

func provenancePendingPath(layoutDir, rootHash string) string {
	return filepath.Join(layoutDir, "provenance", "pending", rootHash+".json")
}

// provenanceResolveRoot returns the project root dir belongs to: the git
// working tree's top level, or inside a linked worktree the main
// repository's (git.FindRoot, the Root of git.Resolve). It is the same root
// the records (the commit scanner's project) and the hook
// (hookProjectRoot) key on, so a consent given from a subdirectory or a
// linked worktree matches them (audit finding F4, decision log P-041).
func provenanceResolveRoot(_ context.Context, _ provenanceGit, dir string) (string, error) {
	root, ok := obsgit.FindRoot(dir)
	if !ok {
		return "", fmt.Errorf("%s is not inside a git repository", dir)
	}
	return filepath.Clean(root), nil
}

// provenanceConsentResult is what a consent change did.
type provenanceConsentResult struct {
	Root        string `json:"root"`
	RootHash    string `json:"root_hash"`
	Notes       bool   `json:"notes"`
	Trailer     bool   `json:"trailer"`
	HookRefusal string `json:"hook_refusal,omitempty"`
}

// provenanceSetConsent is the ONE consent seam the CLI and the dashboard
// share: it records a person's consent for one repository (or its
// withdrawal), and installs or removes the trailer hook block and its flag
// to match. Giving consent needs the component selected; withdrawing works
// while it is off, so a person can always take the writers out.
func provenanceSetConsent(ctx context.Context, st *store.Store, layoutDir string, git provenanceGit, dir string, notes, trailer bool, surface string, selected bool, observerPath string) (provenanceConsentResult, error) {
	var res provenanceConsentResult
	if (notes || trailer) && !selected {
		return res, errProvenanceOff
	}
	root, err := provenanceResolveRoot(ctx, git, dir)
	if err != nil {
		return res, err
	}
	res.Root, res.RootHash, res.Notes, res.Trailer = root, secposture.ProjectRootHash(root), notes, trailer
	target, err := secsvc.ResolveGithookTarget(ctx, secsvc.GitRunner(git), root)
	if err != nil {
		return res, err
	}
	if trailer {
		if target.Refusal != "" {
			res.HookRefusal = target.Refusal
			return res, errors.New(target.Refusal)
		}
		if err := secsvc.InstallTrailerHook(target, observerPath); err != nil {
			return res, err
		}
		flag := provenanceTrailerFlag(layoutDir, res.RootHash)
		if err := os.MkdirAll(filepath.Dir(flag), 0o700); err != nil {
			return res, err
		}
		if err := os.WriteFile(flag, []byte(root+"\n"), 0o600); err != nil {
			return res, err
		}
	} else {
		if _, err := secsvc.UninstallTrailerHook(target); err != nil {
			return res, err
		}
		if err := os.Remove(provenanceTrailerFlag(layoutDir, res.RootHash)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return res, err
		}
	}
	err = st.SetChangeConsent(ctx, store.ChangeConsent{ProjectRootHash: res.RootHash, RootPath: root, Notes: notes, Trailer: trailer, Surface: surface}, time.Now())
	return res, err
}

// provenanceWithdrawAll withdraws consent in every repository that holds
// it, through the one consent seam (provenanceSetConsent), so each trailer
// block is removed byte-exactly and each flag deleted: the
// security.provenance teardown step (lane SEC-F2B). It works while the
// component is off. A repository that is gone or no longer a repository is
// reported in failed and left as it is; the others are still withdrawn.
func provenanceWithdrawAll(ctx context.Context, st *store.Store, layoutDir string, git provenanceGit) ([]provenanceConsentResult, map[string]string, error) {
	consents, err := st.ChangeConsents(ctx)
	if err != nil {
		return nil, nil, err
	}
	var done []provenanceConsentResult
	failed := map[string]string{}
	for _, c := range consents {
		if (!c.Notes && !c.Trailer) || c.RootPath == "" {
			continue
		}
		res, err := provenanceSetConsent(ctx, st, layoutDir, git, c.RootPath, false, false, "teardown", false, "")
		if err != nil {
			failed[c.RootPath] = err.Error()
			continue
		}
		done = append(done, res)
	}
	return done, failed, nil
}

// provenanceTrailerPreview is the exact prepare-commit-msg block a trailer
// consent writes and the hook file it goes into, shown before the write
// (PR11; audit finding F7). Digest names the block, so the dashboard's
// consent proves the person was shown this block.
func provenanceTrailerPreview(ctx context.Context, git provenanceGit, dir, observerPath string) (dashapi.ProvenanceHookPreview, error) {
	var out dashapi.ProvenanceHookPreview
	root, err := provenanceResolveRoot(ctx, git, dir)
	if err != nil {
		return out, err
	}
	target, err := secsvc.ResolveGithookTarget(ctx, secsvc.GitRunner(git), root)
	if err != nil {
		return out, err
	}
	out.Root, out.Block, out.Refusal = root, secchange.TrailerBlock(observerPath), target.Refusal
	sum := sha256.Sum256([]byte(out.Block))
	out.Digest = hex.EncodeToString(sum[:])
	if target.HooksDir != "" {
		out.HookPath = filepath.Join(target.HooksDir, secchange.TrailerHookName)
		if b, err := os.ReadFile(out.HookPath); err == nil { //nolint:gosec // G304: the repository's own hook file.
			out.Installed = strings.Contains(string(b), out.Block)
		}
	}
	return out, nil
}

// provenanceAgentCommit is an agent commit the hook saw, held in the hook
// process until guard and the commit gate decide.
type provenanceAgentCommit struct {
	layoutDir, root, dir, agent, sessionID string
	// staging is what the command line stages for the commit (lane
	// SEC-F2B): the marker binds the commit to it.
	staging policy.CommitStaging
}

// provenanceCandidate is this hook process's pending agent commit (one
// hook invocation per process).
var provenanceCandidate atomic.Pointer[provenanceAgentCommit]

// The marker's git reads on the hook path: bounded, and an index listing
// over the cap writes no marker (no trailer, fail safe).
const (
	provenanceHookGitTimeout = 3 * time.Second
	provenanceIndexMaxBytes  = 64 << 20
)

// provenanceNoteAgentCommit is the hook's first half of the trailer (called
// from securityToolGateEnrich while the security module runs, BEFORE guard
// decides): when the agent's tool call commits in a repository whose
// trailer a person consented to (one stat of the flag file), it holds the
// commit as a candidate with what the command line stages for it
// (policy.PlannedCommitStaging, lane SEC-F2B). Nothing is written here: the
// marker is written only by provenanceAgentCommitAllowed, on the gate's
// allow path (audit finding F3). The event's working directory is where
// the commit runs.
func provenanceNoteAgentCommit(layoutDir, root string, pe *policy.Event, agent string, commits bool, aliases func(string) (map[string]string, bool)) {
	if !commits || layoutDir == "" || root == "" || pe == nil {
		return
	}
	// The scan nudge (security_provenance_nudge.go) for every agent commit
	// while the provenance loop runs, consent or not.
	provenanceHoldNudge(layoutDir, root)
	if _, err := os.Stat(provenanceTrailerFlag(layoutDir, secposture.ProjectRootHash(root))); err != nil {
		return
	}
	dir := pe.Cwd
	if dir == "" {
		dir = root
	}
	staging := policy.CommitStaging{Commit: true, Readable: true}
	if pe.Kind == policy.KindShellExec {
		staging = policy.PlannedCommitStaging(&policy.MatchContext{Event: pe, Cfg: &policy.Config{GitAliases: aliases}})
	}
	provenanceCandidate.Store(&provenanceAgentCommit{layoutDir: layoutDir, root: root, dir: dir, agent: agent, sessionID: pe.SessionID, staging: staging})
}

// provenanceAgentCommitAllowed is the hook's second half, called on a tool
// gate's allow path once guard and the commit gate let the agent's call
// run, before the reply goes out: it writes the marker for the held
// candidate, bound to HEAD and the index at this moment. A denied or asked
// call never reaches it, so its candidate dies with the hook process.
func provenanceAgentCommitAllowed() {
	defer provenanceSendNudge()
	c := provenanceCandidate.Swap(nil)
	if c == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*provenanceHookGitTimeout)
	defer cancel()
	provenanceWriteMarker(ctx, gitview.RunReadOnlyTimeout, *c, time.Now())
}

// provenanceRepoState reads a repository's HEAD ("" on an unborn branch)
// and its index: the fingerprint (secchange.IndexFingerprint over every
// staged entry from the top of the working tree) and the per-path listing
// (secchange.IndexListing), the binding of the marker. ok=false when the
// index cannot be read whole.
func provenanceRepoState(ctx context.Context, git provenanceGit, dir string) (head, index string, listing map[string]string, ok bool) {
	if out, _, err := git(ctx, dir, 4096, provenanceHookGitTimeout, "rev-parse", "--verify", "--quiet", "HEAD"); err == nil {
		head = strings.TrimSpace(string(out))
	}
	ls, over, err := git(ctx, dir, provenanceIndexMaxBytes, provenanceHookGitTimeout, "ls-files", "-s", "-z", "--full-name", "--", ":/")
	if err != nil || over {
		return "", "", nil, false
	}
	listing, ok = secchange.IndexListing(ls)
	if !ok {
		return "", "", nil, false
	}
	return head, secchange.IndexFingerprint(ls), listing, true
}

// provenancePlannedScopes makes the staging's pathspecs relative to the top
// of dir's working tree (`rev-parse --show-prefix` and `--show-toplevel`).
// ok=false when the staging is unreadable or a pathspec leaves the working
// tree: then no marker is written (no trailer, fail safe).
func provenancePlannedScopes(ctx context.Context, git provenanceGit, dir string, st policy.CommitStaging) ([]secchange.PlannedScope, bool) {
	if !st.Readable {
		return nil, false
	}
	if len(st.Scopes) == 0 {
		return nil, true
	}
	out, _, err := git(ctx, dir, 4096, provenanceHookGitTimeout, "rev-parse", "--show-toplevel", "--show-prefix")
	if err != nil {
		return nil, false
	}
	lines := strings.Split(strings.TrimRight(string(out), "\r\n"), "\n")
	if len(lines) < 1 || lines[0] == "" {
		return nil, false
	}
	top, prefix := filepath.Clean(strings.TrimSpace(lines[0])), ""
	if len(lines) > 1 {
		prefix = strings.TrimSpace(lines[1])
	}
	scopes := make([]secchange.PlannedScope, 0, len(st.Scopes))
	for _, sc := range st.Scopes {
		if sc.WholeTree {
			scopes = append(scopes, secchange.PlannedScope{TrackedOnly: sc.TrackedOnly})
			continue
		}
		var rel string
		if filepath.IsAbs(sc.Path) {
			r, err := filepath.Rel(top, filepath.Clean(sc.Path))
			if err != nil {
				return nil, false
			}
			rel = filepath.ToSlash(r)
		} else {
			rel = path.Clean(prefix + filepath.ToSlash(sc.Path))
		}
		if rel == ".." || strings.HasPrefix(rel, "../") || path.IsAbs(rel) {
			return nil, false
		}
		if rel == "." {
			rel = ""
		}
		scopes = append(scopes, secchange.PlannedScope{Prefix: rel, TrackedOnly: sc.TrackedOnly})
	}
	return scopes, true
}

// provenanceWriteMarker writes the marker of an allowed agent commit.
// Best-effort: a marker that cannot be written only means no trailer.
func provenanceWriteMarker(ctx context.Context, git provenanceGit, c provenanceAgentCommit, now time.Time) {
	planned, ok := provenancePlannedScopes(ctx, git, c.dir, c.staging)
	if !ok {
		return
	}
	head, index, listing, ok := provenanceRepoState(ctx, git, c.dir)
	if !ok {
		return
	}
	hash := secposture.ProjectRootHash(c.root)
	b, err := json.Marshal(secchange.PendingCommit{
		RootHash: hash, Agent: c.agent, SessionID: c.sessionID, At: now.UTC().Format(time.RFC3339), Head: head, IndexFP: index,
		Index: listing, Planned: planned,
	})
	if err != nil {
		return
	}
	markerPath := provenancePendingPath(c.layoutDir, hash)
	if os.MkdirAll(filepath.Dir(markerPath), 0o700) != nil {
		return
	}
	tmp := markerPath + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, markerPath)
	}
}

// provenanceCommentSetting is git's comment character setting for dir
// (core.commentString, else core.commentChar; "" when unset).
func provenanceCommentSetting(ctx context.Context, git provenanceGit, dir string) string {
	for _, key := range []string{"core.commentString", "core.commentChar"} {
		if out, _, err := git(ctx, dir, 256, provenanceGitTimeout, "config", "--get", key); err == nil {
			if v := strings.TrimRight(string(out), "\r\n"); v != "" {
				return v
			}
		}
	}
	return ""
}

// provenanceTrailerStep is `observer security provenance trailer <msg
// file> [<source> [<sha>]]`, run by the prepare-commit-msg block: it adds
// the trailer when secchange.DecideTrailer says the commit is the agent's,
// and consumes the marker. It never fails the commit (the block ignores
// its status); reason says what it decided.
func provenanceTrailerStep(ctx context.Context, st *store.Store, layoutDir string, git provenanceGit, selected bool, msgFile, source string, now time.Time) (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	root, err := provenanceResolveRoot(ctx, git, cwd)
	if err != nil {
		return "", err
	}
	hash := secposture.ProjectRootHash(root)
	consent, err := st.ChangeConsentFor(ctx, hash)
	if err != nil {
		return "", err
	}
	head, index, listing, _ := provenanceRepoState(ctx, git, cwd)
	facts := secchange.TrailerFacts{Selected: selected, Consent: consent.Trailer, Source: source, RootHash: hash, Now: now, Head: head, IndexFP: index, Index: listing}
	pendingPath := provenancePendingPath(layoutDir, hash)
	if b, err := os.ReadFile(pendingPath); err == nil { //nolint:gosec // G304: a marker under Observer's own security directory.
		var p secchange.PendingCommit
		if json.Unmarshal(b, &p) == nil {
			facts.Pending = &p
		}
	}
	add, reason := secchange.DecideTrailer(facts)
	if !add {
		return reason, nil
	}
	_ = os.Remove(pendingPath)
	model := ""
	if facts.Pending.SessionID != "" {
		model = st.SessionModel(ctx, facts.Pending.SessionID)
	}
	value := secchange.TrailerValue(facts.Pending.Agent, model)
	msg, err := os.ReadFile(msgFile) //nolint:gosec // G304: git's own commit message file, named by git.
	if err != nil {
		return "", err
	}
	next := secchange.AddTrailer(string(msg), value, secchange.CommentChar(provenanceCommentSetting(ctx, git, cwd), string(msg)))
	if next == string(msg) {
		return "unchanged", nil
	}
	return reason, os.WriteFile(msgFile, []byte(next), 0o600) //nolint:gosec // G703: git's own commit message file, named by git to its hook.
}
