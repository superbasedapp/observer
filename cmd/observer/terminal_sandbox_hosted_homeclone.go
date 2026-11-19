//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox_hosted_homeclone.go is the daemon side of a hosted row's
// clone made on this machine (lane CLONE2, decision SBXD-5): the anonymous
// listing that decides auto, the clone itself (the local rows' clone-remote
// plan, workspace.Plan, run step by step through the same runGitStep with
// the operator's own git login, GIT_TERMINAL_PROMPT=0 and the prep
// timeout) into a run-owned temporary directory under the hosted state
// directory, and the upload manifest of that clone. The host helper uploads
// the clone's files (terminal_sandbox_hosted_host.go prepare) and removes
// the directory once they are sent. No Go network package is involved: both
// git calls are subprocesses of the user's own git, the same posture as the
// local rows' clone-remote (allow_remote_clone, remote_allowed_hosts).

// hostedAnonListTimeout bounds the anonymous listing; a listing that does
// not answer within it reads as refused (the clone then runs here).
var hostedAnonListTimeout = 10 * time.Second

// hostedAnonCacheTTL is how long one listing's answer is reused (the
// consent screen, the dialog's line and the launch of one URL a moment
// apart ask once).
const hostedAnonCacheTTL = 2 * time.Minute

// hostedAnonLsRemote runs the anonymous listing of url: nil when the
// address answered with no credential at all. A variable so tests stand it
// in (no test reaches the network).
var hostedAnonLsRemote = hostedAnonLsRemoteExec

type hostedAnonEntry struct {
	ans workspace.AnonAnswer
	at  time.Time
}

// hostedAnonCache holds recent listing answers by URL.
var hostedAnonCache sync.Map

// hostedAnonAnswer is url's anonymous listing answer, from the cache when
// fresh.
func hostedAnonAnswer(ctx context.Context, url string) workspace.AnonAnswer {
	if ctx == nil {
		ctx = context.Background()
	}
	if v, ok := hostedAnonCache.Load(url); ok {
		if e := v.(hostedAnonEntry); time.Since(e.at) < hostedAnonCacheTTL {
			return e.ans
		}
	}
	ans := workspace.AnonRefused
	lctx, cancel := context.WithTimeout(ctx, hostedAnonListTimeout)
	defer cancel()
	if hostedAnonLsRemote(lctx, url) == nil {
		ans = workspace.AnonPublic
	}
	if ctx.Err() == nil {
		hostedAnonCache.Store(url, hostedAnonEntry{ans: ans, at: time.Now()})
	}
	return ans
}

// hostedAnonLsRemoteExec is the real listing: the composed argv
// (workspace.AnonymousListArgv), the host git hardening with no inherited
// GIT_* variable, and an empty temporary HOME, so no credential helper,
// .netrc or stored login of this machine is read.
func hostedAnonLsRemoteExec(ctx context.Context, url string) error {
	argv, err := workspace.AnonymousListArgv(url)
	if err != nil {
		return err
	}
	home, err := os.MkdirTemp("", "observer-anon-list-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(home) }()
	fixed := workspace.AnonymousListEnv(home)
	var env []string
	for _, kv := range hardenedGitEnv(os.Environ()) {
		name, _, _ := strings.Cut(kv, "=")
		if _, override := fixed[name]; override || name == "SSH_AUTH_SOCK" {
			continue
		}
		env = append(env, kv)
	}
	for k, v := range fixed {
		env = append(env, k+"="+v)
	}
	//nolint:gosec // G204: argv is workspace.AnonymousListArgv's fixed shape over a URL ValidateBoxCloneURL accepted, with "--" before it.
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env, cmd.Dir = env, home
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, io.Discard, io.Discard
	return cmd.Run()
}

// hostedCloneWhereView is the dialog's clone location facts for hosted row
// id on tier under cfg (nil for a row that clones only in its box, or that
// takes no clone-remote at all): which places a launch can choose before a
// URL is typed, and why the others cannot.
func hostedCloneWhereView(id string, tier vocab.Tier, cfg config.TerminalSandboxConfig) *dashapi.SandboxCloneWhere {
	v, ok := sandboxremote.VendorFor(id)
	if !ok || !hostedHomeCloneOffered(v) {
		return nil
	}
	if _, err := workspace.DeliveryFor(workspace.SourceCloneRemote, hostedRowModes(v)); err != nil {
		return nil
	}
	set, err := workspace.ParseCloneWhere(cfg.Hosted.CloneWhere)
	if err != nil {
		set = workspace.CloneWhereAuto
	}
	view := &dashapi.SandboxCloneWhere{Setting: string(set), Fixed: set != workspace.CloneWhereAuto, Choices: []string{}, Rule: hostedCloneWhereRules[set]}
	for _, w := range workspace.CloneWhereValues {
		if view.Fixed && w != set {
			continue
		}
		_, ref := hostedDecideSource(hostedSourceInput{v: v, src: workspace.SourceCloneRemote, tier: tier, cfg: cfg, cloneWhere: string(w)})
		if ref == nil {
			view.Choices = append(view.Choices, string(w))
			continue
		}
		if view.Notes == nil {
			view.Notes = map[string]string{}
		}
		view.Notes[string(w)] = ref.Message
	}
	return view
}

// hostedCloneWhereRules is each setting's rule in plain words.
var hostedCloneWhereRules = map[workspace.CloneWhere]string{
	workspace.CloneWhereAuto: "A repository anyone can read is cloned inside the box; any other is cloned on this machine with your git login and its tracked files are uploaded.",
	workspace.CloneWhereBox:  "The box clones the repository itself: public repositories only, on the internet network setting only.",
	workspace.CloneWhereHome: "This machine clones the repository with your git login and uploads its tracked files: private repositories work, on any network setting.",
}

// hostedApplyCloneWhere adds a clone-remote consent screen's location
// lines: where this agreement's clone runs and why, and the auto rule;
// nothing on a row that clones only in its box (the org row).
func hostedApplyCloneWhere(scr *sandboxremote.ConsentScreen, v sandboxremote.Vendor, del hostedDelivery) {
	if !hostedHomeCloneOffered(v) {
		return
	}
	if line := hostedCloneWhereLine(del); line != "" {
		scr.Lines = append(scr.Lines, sandboxremote.ConsentLine{Label: "Where the repository is cloned", Value: line})
	}
	scr.Lines = append(scr.Lines, sandboxremote.ConsentLine{Label: "Clone location rule", Value: hostedCloneWhereRule})
}

// hostedCloneScope is the consent scope of a clone-remote delivery: the
// box-side clone's, or the clone made here and uploaded (so switching
// where the clone runs asks again).
func hostedCloneScope(del hostedDelivery) string {
	if del.HomeClone {
		return sandboxremote.HomeCloneScopeKey(del.CloneURL)
	}
	return sandboxremote.RemoteCloneScopeKey(del.CloneURL)
}

// hostedHomeCloneRoot is where this machine's clones for hosted boxes are
// made, one directory per run (removed once uploaded).
func hostedHomeCloneRoot(observerDir string) string {
	return filepath.Join(hostedStateDir(observerDir), "homeclones")
}

// hostedHomeCloneStaleAfter is the age past which a run's clone directory
// that was never uploaded (a launch whose helper never started) is removed
// at the next home clone.
const hostedHomeCloneStaleAfter = 24 * time.Hour

// hostedSweepHomeClones removes the run directories under root older than
// hostedHomeCloneStaleAfter.
func hostedSweepHomeClones(root string, now time.Time) {
	ents, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range ents {
		info, err := e.Info()
		if err != nil || !e.IsDir() || now.Sub(info.ModTime()) < hostedHomeCloneStaleAfter || !returnsRunIDOK(e.Name()) {
			continue
		}
		_ = os.RemoveAll(filepath.Join(root, e.Name()))
	}
}

// hostedHomeCloneStep runs one git step of the clone (a variable so the
// fake vendor harness stands in for the network).
var hostedHomeCloneStep = func(ctx context.Context, r *sandboxRuntime, step workspace.Step) error {
	return r.runGitStep(ctx, step)
}

// hostedHomeCloneResult is a finished clone made here.
type hostedHomeCloneResult struct {
	// Dir is the clone (resolved, under hostedHomeCloneRoot).
	Dir string
	// Manifest is the upload of its tracked files.
	Manifest sandboxremote.Manifest
}

// homeClone clones del.CloneURL on this machine for run runID and plans the
// upload of the clone's files. Every failure removes what it made.
func (d *hostedDriver) homeClone(ctx context.Context, runID string, del hostedDelivery) (hostedHomeCloneResult, error) {
	root := hostedHomeCloneRoot(d.r.observerDir)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return hostedHomeCloneResult{}, fmt.Errorf("terminal_sandbox: the clone directory: %w", err)
	}
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	hostedSweepHomeClones(root, d.now())
	plan, err := workspace.Plan(workspace.Request{
		Source: workspace.SourceCloneRemote, RemoteURL: del.CloneURL, Branch: del.CloneBranch,
		ManagedRoot: root, ID: runID, AllowRemoteClone: d.r.cfg.AllowRemoteClone, RemoteAllowedHosts: d.r.cfg.RemoteAllowedHosts,
	})
	if err != nil {
		return hostedHomeCloneResult{}, fmt.Errorf("terminal_sandbox: clone_url_invalid: %w", err)
	}
	runDir := filepath.Dir(plan.Dir)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return hostedHomeCloneResult{}, fmt.Errorf("terminal_sandbox: the clone directory: %w", err)
	}
	done := false
	defer func() {
		if !done {
			_ = os.RemoveAll(runDir) //nolint:gosec // G703: runDir is <hosted state>/homeclones/<fresh run id>
		}
	}()
	prepCtx := ctx
	if secs := d.r.cfg.PrepTimeoutSeconds; secs > 0 {
		var cancel context.CancelFunc
		prepCtx, cancel = context.WithTimeout(ctx, time.Duration(secs)*time.Second)
		defer cancel()
	}
	for _, step := range plan.Steps {
		if err := hostedHomeCloneStep(prepCtx, d.r, step); err != nil {
			return hostedHomeCloneResult{}, &dashapi.SandboxStepRefusal{
				Code:      "home_clone_failed",
				Message:   "This machine could not clone " + del.CloneURL + " with your git login (check the address, and that this machine can sign in to it); nothing was sent and no box was made.",
				Technical: err.Error(),
			}
		}
	}
	resolved, err := filepath.EvalSymlinks(plan.Dir)
	if err != nil {
		return hostedHomeCloneResult{}, fmt.Errorf("terminal_sandbox: resolve the clone: %w", err)
	}
	if err := workspace.ValidateManagedWorkspace(resolved, root); err != nil {
		return hostedHomeCloneResult{}, err
	}
	m, err := d.manifest(ctx, resolved)
	if err != nil {
		return hostedHomeCloneResult{}, err
	}
	done = true
	return hostedHomeCloneResult{Dir: resolved, Manifest: m}, nil
}

// hostedRemoveHomeCloneDir removes a run's clone directory (the parent of
// its clone), only when it is a run directory under the hosted clone root.
func hostedRemoveHomeCloneDir(observerDir, cloneDir string) error {
	if cloneDir == "" {
		return nil
	}
	root := hostedHomeCloneRoot(observerDir)
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	runDir := filepath.Dir(filepath.Clean(cloneDir))
	if filepath.Dir(runDir) != root || !returnsRunIDOK(filepath.Base(runDir)) {
		return errors.New("the clone directory is not a run's clone under " + root + "; left in place")
	}
	return os.RemoveAll(runDir)
}
