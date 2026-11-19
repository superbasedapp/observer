//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox_hosted_boxclone_linux.go is the core box-side clone of a
// remote_clone delivery (lane CLONE): the box itself runs `git clone` of a
// validated public URL, so nothing of this machine's tree is uploaded and no
// git credential is sent. It runs on a row whose registration fixes no clone
// argv of its own (the vendor rows; the org row sends its organization's
// argv as the run's first exec, boxClone). Then the commit the box cloned is
// read and recorded, so the saved diff (against that commit) can be applied.

// hostedBoxCloneTimeout bounds the box's clone (the org's clone deadline is
// the same ten minutes); a variable for tests.
var hostedBoxCloneTimeout = 10 * time.Minute

// The run record's Extra keys of a box-side clone (not secrets: the URL is
// validated to carry no credential).
const (
	hostedExtraCloneURL    = "clone_url"
	hostedExtraCloneCommit = "clone_commit"
)

// hostedCloneReturnVersion is the version of the clone return record.
const hostedCloneReturnVersion = 1

// hostedCloneReturn is the record of what a box-side clone run's saved diff
// applies to, written owner-only next to the diff as
// <observer dir>/sandbox-hosted/returns/<run>.clone.json once the box has
// cloned (before the agent starts, so it is there whatever the run's end).
type hostedCloneReturn struct {
	Version  int    `json:"version"`
	RunID    string `json:"run_id"`
	Provider string `json:"provider"`
	// CloneURL is the repository the box cloned, exactly as the launch
	// passed it; Commit the full commit name the clone checked out (the
	// base of the saved diff); Branch the work branch made in the box ("" for
	// none, the repository's default branch).
	CloneURL string `json:"clone_url"`
	Commit   string `json:"commit"`
	Branch   string `json:"branch,omitempty"`
	// Root is the launch directory on this machine; the diff does NOT apply
	// there (it is against the clone, not that folder).
	Root string `json:"root"`
	// Diff is the file name of the saved diff in the same directory
	// (<run>.diff), written at the run's end when the box changed anything.
	Diff string `json:"diff"`
	// DiffAgainst says what the diff is against: "commit" (Commit itself;
	// commits the agent made in the box are in the diff), or "bundle_tip"
	// (a row whose guest keeps the baseline: the diff is against the box's
	// HEAD at the end, and its commits since Commit are in <run>.bundle,
	// fetched first), or "upload_baseline" (a clone this machine made and
	// uploaded, decision SBXD-5: the diff is against the box's baseline of
	// the uploaded files, which are Commit's tracked files less the ones the
	// upload left out; the clone itself is removed after the upload).
	DiffAgainst string `json:"diff_against"`
	ClonedAt    string `json:"cloned_at"`
	// Where is where the clone ran ("box", or "home" for a clone made on
	// this machine; absent on a record written before lane CLONE2: box).
	Where string `json:"where,omitempty"`
}

// The DiffAgainst values.
const (
	hostedCloneDiffAgainstCommit         = "commit"
	hostedCloneDiffAgainstBundleTip      = "bundle_tip"
	hostedCloneDiffAgainstUploadBaseline = "upload_baseline"
)

// hostedExtraHomeCloneCommit is the run record's Extra key of the commit a
// clone made on this machine checked out (never hostedExtraCloneCommit:
// that one makes the box diff against a commit only a box-side clone has).
const hostedExtraHomeCloneCommit = "home_clone_commit"

// hostedPlanHomeClone reports a run whose repository this machine cloned
// and uploaded (SBXD-5).
func hostedPlanHomeClone(plan hostedPlanFile) bool {
	return plan.CloneWhere == string(workspace.CloneWhereHome) && plan.Delivery != hostedDeliveryRemoteClone && plan.CloneURL != ""
}

// uploadRoot is the tree an upload run sends: the clone this machine made
// for a home clone, else the launch directory.
func (r *hostedRun) uploadRoot() string {
	if r.plan.HomeCloneDir != "" {
		return r.plan.HomeCloneDir
	}
	return r.plan.Root
}

// uploadScopeOK reports whether the re-listed upload is the consented
// scope: a home clone's consent is for its URL's clone (the clone's
// directory is new each run), any other upload's for the re-listed root.
func (r *hostedRun) uploadScopeOK(m sandboxremote.Manifest) bool {
	if hostedPlanHomeClone(r.plan) {
		return r.plan.ScopeKey == sandboxremote.HomeCloneScopeKey(r.plan.CloneURL)
	}
	return m.ScopeKey == r.plan.ScopeKey
}

// hostedHomeCloneListedExcluded caps the excluded names the terminal lists.
const hostedHomeCloneListedExcluded = 20

// homeCloneUploading says, before a home clone's files are sent, where the
// clone was made and why, what goes and what stays, and records the commit
// the saved diff applies to (the clone return record, as a box clone's).
func (r *hostedRun) homeCloneUploading(m sandboxremote.Manifest) {
	if !hostedPlanHomeClone(r.plan) {
		return
	}
	r.say("%s was cloned on this machine (%s); uploading its tracked files, never its git history or a git credential: %s", r.plan.CloneURL, workspace.CloneWhereReasonText[r.plan.CloneWhereReason], m.Summary())
	if n := len(m.Excluded); n > 0 {
		var names []string
		for i, e := range m.Excluded {
			if i == hostedHomeCloneListedExcluded {
				names = append(names, fmt.Sprintf("and %d more", n-i))
				break
			}
			names = append(names, e.Path+" ("+strings.ReplaceAll(e.Reason, "_", " ")+")")
		}
		r.say("left on this machine: %s", strings.Join(names, ", "))
	}
	commit := r.uploadBase.Commit
	if !workspace.ValidSHA(commit) {
		r.say("the commit of the clone was not read, so the saved diff is offered as a file only")
		return
	}
	r.setExtra(map[string]string{hostedExtraCloneURL: r.plan.CloneURL, hostedExtraHomeCloneCommit: commit})
	_ = hostedSaveRecord(r.plan.ObserverDir, r.rec)
	if err := hostedWriteCloneReturn(r.plan.ObserverDir, hostedCloneReturn{
		Version: hostedCloneReturnVersion, RunID: r.plan.RunID, Provider: r.plan.Provider,
		CloneURL: r.plan.CloneURL, Commit: commit, Branch: r.plan.CloneBranch, Root: r.plan.Root,
		Diff: r.plan.RunID + ".diff", DiffAgainst: hostedCloneDiffAgainstUploadBaseline,
		ClonedAt: r.now().UTC().Format(time.RFC3339), Where: string(workspace.CloneWhereHome),
	}); err != nil {
		r.say("the record of the commit the clone checked out was not written (%v); it is %s", err, commit)
	}
}

// homeCloneUploaded removes a home clone once its files are sent.
func (r *hostedRun) homeCloneUploaded() {
	if r.plan.HomeCloneDir == "" {
		return
	}
	dir := r.plan.HomeCloneDir
	r.removeHomeClone()
	r.say("the temporary clone at %s is removed; the box works on its uploaded copy", dir)
}

// removeHomeClone removes the run's home clone, once (the upload's end, or
// the run's end whatever it was).
func (r *hostedRun) removeHomeClone() {
	dir := r.plan.HomeCloneDir
	if dir == "" {
		return
	}
	r.plan.HomeCloneDir = ""
	if err := hostedRemoveHomeCloneDir(r.plan.ObserverDir, dir); err != nil {
		r.say("the temporary clone at %s was not removed: %v", dir, err)
	}
}

// sayCloneWhere says where a clone-remote run clones and why.
func (r *hostedRun) sayCloneWhere() {
	d := hostedDelivery{Where: workspace.CloneWhere(r.plan.CloneWhere), WhereReason: r.plan.CloneWhereReason}
	if line := hostedCloneWhereLine(d); line != "" {
		r.say("the repository is %s", line)
	}
}

// hostedCloneReturnPath is a run's clone return record.
func hostedCloneReturnPath(observerDir, runID string) string {
	return filepath.Join(hostedStateDir(observerDir), "returns", runID+".clone.json")
}

// hostedGuestKeepsBaseline reports whether the row's in-box guest records
// the return baseline in the row's fixed run dir (the org row: its guest's
// --baseline verb writes it there, where the commits bundle starts, design
// 4.6); every other row's box records nothing, and the node keeps the
// cloned commit instead.
func hostedGuestKeepsBaseline(v sandboxremote.Vendor) bool { return v.BoxRunDir != "" }

// coreBoxClone runs the core box-side clone: git checked first, then the
// clone into the run's workspace (made by setupDirs, owned by the box user)
// as the box user, then the work branch. A box with no git, or a clone that
// fails, ends the launch plainly; the box is then deleted by the run's
// teardown, with nothing to bring back.
func (r *hostedRun) coreBoxClone(ctx context.Context) error {
	url := r.plan.CloneURL
	plan, err := workspace.PlanBoxClone(workspace.BoxCloneRequest{URL: url, Dest: r.layout.Workspace, Branch: r.plan.CloneBranch})
	if err != nil {
		r.cloneFailed = true
		return fmt.Errorf("clone_failed: %w", err)
	}
	_, code, err := hostedExecOutputIn(ctx, r.client, r.rec.VendorID, sandboxremote.ExecSpec{Argv: plan.GitCheck, Env: r.boxEnv()}, 4096)
	if err != nil {
		r.cloneFailed = true
		return fmt.Errorf("clone_failed: checking for git in the box: %w", err)
	}
	if code != 0 {
		r.cloneFailed = true
		return fmt.Errorf("git_missing: the box has no git, so it cannot clone %s; nothing was cloned and the box is deleted (use a template that holds git, or the live project directory, which this machine uploads)", url)
	}
	r.say("cloning %s in the box (never on this machine; nothing of this machine's tree is uploaded and no git credential is sent)", url)
	env := r.boxEnv()
	for k, v := range plan.Env {
		env[k] = v
	}
	cctx, cancel := context.WithTimeout(ctx, hostedBoxCloneTimeout)
	defer cancel()
	if err := r.execOK(cctx, "clone the repository in the box", sandboxremote.ExecSpec{Argv: plan.Clone, Env: env}); err != nil {
		r.cloneFailed = true
		return fmt.Errorf("clone_failed: the box could not clone %s (%w); no git credential is sent to the box, so only a public repository clones; the box is deleted", url, err)
	}
	if plan.Branch != nil {
		if err := r.execOK(ctx, "make the work branch in the box", sandboxremote.ExecSpec{Argv: plan.Branch, Env: env}); err != nil {
			r.cloneFailed = true
			return fmt.Errorf("clone_failed: %w", err)
		}
	}
	return nil
}

// recordCloneCommit reads the commit the box cloned (the org row's guest
// --baseline verb, which also keeps it for the bundle; otherwise git in the
// workspace), keeps it on the run record and writes the clone return record.
func (r *hostedRun) recordCloneCommit(ctx context.Context) error {
	spec := sandboxremote.ExecSpec{Cwd: r.layout.Workspace, Env: r.boxEnv(), Argv: []string{r.layout.Binary, "sandbox-guest", guestBaselineFlagCore}}
	if !hostedGuestKeepsBaseline(r.vendor) {
		plan, err := workspace.PlanBoxClone(workspace.BoxCloneRequest{URL: r.plan.CloneURL, Dest: r.layout.Workspace})
		if err != nil {
			return fmt.Errorf("clone_failed: %w", err)
		}
		spec.Argv = plan.Head
	}
	out, code, err := hostedExecOutputIn(ctx, r.client, r.rec.VendorID, spec, 4096)
	if err != nil {
		return fmt.Errorf("record the return baseline: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("record the return baseline exited %d: %s", code, hostedFirstLine(out))
	}
	commit := strings.TrimSpace(string(out))
	if !workspace.ValidSHA(commit) && hostedGuestKeepsBaseline(r.vendor) {
		// The guest kept the baseline in the box (its exit says so), which
		// the bundle and the organization's collect read; only this
		// machine's copy of it is missing, as before lane CLONE.
		r.say("the commit the box cloned was not read here; the box keeps it for the return")
		return nil
	}
	if !workspace.ValidSHA(commit) {
		return fmt.Errorf("clone_failed: the box's clone of %s has no commit to start from (%s)", r.plan.CloneURL, hostedFirstLine(out))
	}
	r.setExtra(map[string]string{hostedExtraCloneURL: r.plan.CloneURL, hostedExtraCloneCommit: commit})
	_ = hostedSaveRecord(r.plan.ObserverDir, r.rec)
	against := hostedCloneDiffAgainstCommit
	if hostedGuestKeepsBaseline(r.vendor) {
		against = hostedCloneDiffAgainstBundleTip
	}
	if err := hostedWriteCloneReturn(r.plan.ObserverDir, hostedCloneReturn{
		Version: hostedCloneReturnVersion, RunID: r.plan.RunID, Provider: r.plan.Provider,
		CloneURL: r.plan.CloneURL, Commit: commit, Branch: r.plan.CloneBranch, Root: r.plan.Root,
		Diff: r.plan.RunID + ".diff", DiffAgainst: against, ClonedAt: r.now().UTC().Format(time.RFC3339),
	}); err != nil {
		r.say("the record of the commit the box cloned was not written (%v); it is %s", err, commit)
	}
	r.say("the box cloned %s at commit %s; a saved diff of its changes applies to that commit", r.plan.CloneURL, commit)
	return nil
}

// hostedWriteCloneReturn writes a clone return record owner-only.
func hostedWriteCloneReturn(observerDir string, rec hostedCloneReturn) error {
	p := hostedCloneReturnPath(observerDir, rec.RunID)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, append(b, '\n'), 0o600)
}

// cloneReturn is the run's box-side clone and the commit it cloned ("" when
// the run is not a clone or the commit was not read), from the run record
// so a re-adopted run keeps it.
func (r *hostedRun) cloneReturn() (url, commit string) {
	url, commit = r.rec.Extra[hostedExtraCloneURL], r.rec.Extra[hostedExtraCloneCommit]
	if url == "" {
		url = r.plan.CloneURL
	}
	return url, commit
}

// stagedDiffSpec is the exec that prints the box's staged changes, whether
// an exit code is a diff, and whether the diff starts at the box's starting
// commit (fromStart, so commits the agent made are in it): against the
// commit the box cloned on a core clone run, against the observer-baseline
// commit the upload made on an upload run (unless
// [terminal.sandbox.hosted].diff_against is "head"), else the guest's
// staged diff against HEAD (a cut diff exits StagedDiffTruncatedExit). A
// row whose guest keeps its own baseline (the org row) always takes the
// guest's capture. The diff against a start is plain git with the guest
// staged diff's flags (no external diff driver, no textconv, no pager, no
// color; workspace.BoxCloneDiffArgv) and its fixed environment.
func (r *hostedRun) stagedDiffSpec(guest sandboxremote.ExecSpec, guestOK func(int) bool) (sandboxremote.ExecSpec, func(int) bool, bool) {
	start := ""
	if _, commit := r.cloneReturn(); commit != "" {
		start = commit
	} else if r.plan.Delivery != hostedDeliveryRemoteClone {
		start = r.uploadBaseline()
	}
	if start == "" || hostedGuestKeepsBaseline(r.vendor) {
		return guest, guestOK, false
	}
	argv, err := workspace.BoxCloneDiffArgv(start)
	if err != nil {
		return guest, guestOK, false
	}
	env := r.boxEnv()
	for k, v := range workspace.BoxCloneDiffEnv() {
		env[k] = v
	}
	return sandboxremote.ExecSpec{Argv: argv, Env: env, Cwd: r.layout.Workspace}, func(c int) bool { return c == 0 }, true
}

// hostedExtraUploadBaseline is the run record's Extra key of an upload
// run's observer-baseline commit in the box (a commit name, not a secret),
// kept on the record so a re-adopted run diffs against it too.
const hostedExtraUploadBaseline = "upload_baseline"

// hostedBaselineHeadScript prints the box workspace's commit (the baseline
// commit the upload just made); exit 3 when the box has no git.
const hostedBaselineHeadScript = `command -v git >/dev/null 2>&1 || exit 3; git rev-parse --verify --quiet 'HEAD^{commit}'`

// recordUploadBaseline reads, right after the upload made it and before the
// agent runs, the name of the box's observer-baseline commit and keeps it on
// the run record, when the saved diff is to be taken against it. Nothing is
// said when it cannot be read: the diff is then taken against HEAD, as
// before, and offered as a file only if the agent committed.
func (r *hostedRun) recordUploadBaseline(ctx context.Context, ws string) {
	if !hostedDiffAgainstBaseline(r.plan) || hostedGuestKeepsBaseline(r.vendor) {
		return
	}
	out, code, err := hostedExecOutputIn(ctx, r.client, r.rec.VendorID, sandboxremote.ExecSpec{
		Cwd: ws, Env: r.boxEnv(), Argv: []string{"sh", "-c", hostedBaselineHeadScript},
	}, 4096)
	if err != nil || code != 0 {
		return
	}
	if c := strings.TrimSpace(string(out)); workspace.ValidSHA(c) {
		r.setExtra(map[string]string{hostedExtraUploadBaseline: c})
		_ = hostedSaveRecord(r.plan.ObserverDir, r.rec)
	}
}

// uploadBaseline is the upload run's recorded baseline commit ("" when none
// was recorded, or the run is set to diff against HEAD).
func (r *hostedRun) uploadBaseline() string {
	if !hostedDiffAgainstBaseline(r.plan) {
		return ""
	}
	if c := r.rec.Extra[hostedExtraUploadBaseline]; workspace.ValidSHA(c) {
		return c
	}
	return ""
}

// hostedDiffApplyWhereRun is hostedDiffApplyWhere with the commit the box
// cloned, when the run recorded one.
func hostedDiffApplyWhereRun(r *hostedRun) string {
	if hostedPlanHomeClone(r.plan) {
		// A clone made here (SBXD-5): the diff is against its uploaded files.
		if c := r.rec.Extra[hostedExtraHomeCloneCommit]; c != "" {
			return "a checkout of " + r.plan.CloneURL + " at commit " + c + " (the diff is against the clone this machine made and uploaded, not " + r.plan.Root + "; the commit is recorded in " + hostedCloneReturnPath(r.plan.ObserverDir, r.plan.RunID) + ")"
		}
		return "a checkout of " + r.plan.CloneURL + " at the commit this machine cloned (not " + r.plan.Root + ")"
	}
	url, commit := r.cloneReturn()
	if commit == "" || url == "" || hostedGuestKeepsBaseline(r.vendor) {
		return hostedDiffApplyWhere(r.plan)
	}
	return "a checkout of " + url + " at commit " + commit + " (the diff is against the box's clone, not " + r.plan.Root + "; the commit is recorded in " + hostedCloneReturnPath(r.plan.ObserverDir, r.plan.RunID) + ")"
}
