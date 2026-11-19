//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// terminal_sandbox_hosted_execupload_linux.go is the hosted core's file
// writer for a vendor with no file API (Vendor.UploadViaExec, lane G4: the
// org-hosted row, whose SDK upload is a stub; g1-design.md section 4.2). It
// reads the capability flag, never a vendor id.
//
// The files travel as one tar stream cut into one-shot exec parts of at most
// hostedExecPartBytes. Every part is one ExecSandbox whose stdin rides in the
// request, and the next part is sent only after the previous exec exited, so
// never more than one part is in flight: the part's exit is its credit
// (flow control; the 0.1.6 supervisor ends an exec whose client outruns its
// bounded stdin buffer). The joined stream is checked against its SHA-256 in
// the box before it is unpacked; a mismatch unpacks nothing.

// hostedExecPartBytes is one part's size when the vendor row names none
// (Vendor.OneShotStdinBytes); a test sets it to cut small parts.
var hostedExecPartBytes = 256 << 10

// hostedExecPartOverride, when above 0, replaces every vendor's part size
// (tests only).
var hostedExecPartOverride = 0

// execPartBytes is one exec part of this run: the most stdin the vendor's
// one-shot exec carries (FX3 item 2: the gateway's message limit, not a
// quarter MiB, so a run sends an order of magnitude fewer execs).
func (r *hostedRun) execPartBytes() int {
	switch {
	case hostedExecPartOverride > 0:
		return hostedExecPartOverride
	case r.vendor.OneShotStdinBytes > 0:
		return r.vendor.OneShotStdinBytes
	}
	return hostedExecPartBytes
}

// writePart writes one part of the in-box observer: one exec of the part
// script with the part as its stdin on an UploadViaExec vendor (the part
// is at most execPartBytes), the vendor's file API otherwise.
func (r *hostedRun) writePart(ctx context.Context, p string, data []byte) error {
	if !r.vendor.UploadViaExec {
		return r.writeFiles(ctx, []sandboxremote.UploadFile{{Path: p, Mode: 0o644, Size: int64(len(data)), Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(data)), nil
		}}})
	}
	out, code, err := hostedExecOutputIn(ctx, r.client, r.rec.VendorID, sandboxremote.ExecSpec{
		Argv: []string{"sh", "-c", hostedExecPartScript, "sh", p}, Env: r.boxEnv(), StdinData: data,
	}, 4096)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("the part write exited %d: %s", code, hostedFirstLine(out))
	}
	return nil
}

// hostedExecPartScript writes one part owner-only from stdin. Argument: the
// part's path. A plain shell argv, so it works before the in-box observer
// exists (the in-box binary's own parts).
const hostedExecPartScript = `umask 077; cat > "$1"`

// hostedExecUnpackScript joins the parts, checks the digest, unpacks the
// tar at the unpack root without changing owners, and removes the parts and
// the joined file. Arguments: the joined path, the expected digest, the
// unpack root, the parts.
const hostedExecUnpackScript = `set -e
out=$1; want=$2; root=$3; shift 3
umask 077
cat -- "$@" > "$out"
rm -f -- "$@"
got=$(sha256sum "$out" | cut -d ' ' -f 1)
if [ "$got" != "$want" ]; then rm -f -- "$out"; echo "observer upload: digest mismatch"; exit 3; fi
tar -xf "$out" -C "$root" --no-same-owner
rm -f -- "$out"`

// hostedExecUnpackRoot is where the tar is unpacked (its names are the box
// paths without the leading slash); a test unpacks under a temp dir.
var hostedExecUnpackRoot = "/"

// writeFiles writes files into the box: the vendor's file API, or exec
// parts for an UploadViaExec vendor.
func (r *hostedRun) writeFiles(ctx context.Context, files []sandboxremote.UploadFile) error {
	if !r.vendor.UploadViaExec {
		return r.client.WriteFiles(ctx, r.rec.VendorID, files)
	}
	return hostedExecWriteFiles(ctx, r.client, r.rec.VendorID, r.layout.RunDir, r.boxEnv(), r.execPartBytes(), files)
}

// hostedPackTar packs files into one tar stream (regular files only, the
// box paths without the leading slash, the given modes) and returns it with
// its SHA-256.
func hostedPackTar(files []sandboxremote.UploadFile) ([]byte, string, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		if !path.IsAbs(f.Path) || path.Clean(f.Path) != f.Path {
			return nil, "", fmt.Errorf("upload path %q is not a clean absolute path", f.Path)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, "", err
		}
		data, err := io.ReadAll(io.LimitReader(rc, f.Size+1))
		_ = rc.Close()
		if err != nil {
			return nil, "", err
		}
		if int64(len(data)) != f.Size {
			return nil, "", fmt.Errorf("%s changed size while it was read", f.Path)
		}
		if err := tw.WriteHeader(&tar.Header{Name: strings.TrimPrefix(f.Path, "/"), Mode: int64(f.Mode & 0o7777), Size: f.Size, Typeflag: tar.TypeReg}); err != nil {
			return nil, "", err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, "", err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sum[:]), nil
}

// hostedExecWriteFiles sends files as tar parts through one-shot execs, one
// in flight at a time, then joins, checks and unpacks them in the box.
func hostedExecWriteFiles(ctx context.Context, c sandboxremote.Client, boxID, stageDir string, env map[string]string, partBytes int, files []sandboxremote.UploadFile) error {
	if len(files) == 0 {
		return nil
	}
	payload, sum, err := hostedPackTar(files)
	if err != nil {
		return err
	}
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	stem := path.Join(stageDir, ".upload."+hex.EncodeToString(raw))
	size := max(partBytes, 1)
	var parts []string
	for off, i := 0, 0; off < len(payload); i++ {
		end := min(off+size, len(payload))
		p := stem + ".part." + strconv.Itoa(i)
		out, code, err := hostedExecOutputIn(ctx, c, boxID, sandboxremote.ExecSpec{
			Argv: []string{"sh", "-c", hostedExecPartScript, "sh", p}, Env: env, StdinData: payload[off:end],
		}, 4096)
		if err != nil {
			return fmt.Errorf("send upload part %d: %w", i, err)
		}
		if code != 0 {
			return fmt.Errorf("upload part %d exited %d: %s", i, code, hostedFirstLine(out))
		}
		parts = append(parts, p)
		off = end
	}
	argv := append([]string{"sh", "-c", hostedExecUnpackScript, "sh", stem + ".tar", sum, hostedExecUnpackRoot}, parts...)
	out, code, err := hostedExecOutputIn(ctx, c, boxID, sandboxremote.ExecSpec{Argv: argv, Env: env}, 4096)
	if err != nil {
		return fmt.Errorf("unpack the upload: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("unpack the upload exited %d: %s", code, hostedFirstLine(out))
	}
	return nil
}

// hostedPacedArgv wraps argv in the in-box paced-stdin wrapper, which hands
// its stdin to argv and reports what it consumed as credit lines on stderr
// (a BoundedStdin vendor's streaming stdin).
func hostedPacedArgv(bin string, argv []string) []string {
	return append([]string{bin, "sandbox-guest", guestPacedStdinFlag, "--"}, argv...)
}

// guestPacedStdinFlag selects the in-box paced-stdin wrapper.
const guestPacedStdinFlag = "--paced-stdin"

// boxClone runs the box-side clone (a remote_clone delivery) as the run's
// first exec: exactly the argv, environment and token purpose the
// vendor's registration names (the org row: internal/openshellorg's
// CloneArgv and CloneEnv under a create token, the one owner the org's mint
// records and its front compares byte for byte, ruling A1). No working
// directory, no stdin, no TTY; nothing of the core's own is added.
func (r *hostedRun) boxClone(ctx context.Context) error {
	if r.plan.CloneURL == "" {
		return fmt.Errorf("a remote_clone run without a clone URL")
	}
	reg := hostedVendorRegs[r.plan.Provider]
	if reg.cloneSpec == nil {
		return fmt.Errorf("%s has no box-side clone in this build", r.plan.Provider)
	}
	argv, env, purpose := reg.cloneSpec(r.plan.CloneURL)
	if purpose != "" {
		ctx = sandboxremote.WithTokenPurpose(ctx, purpose)
	}
	r.say("cloning %s in the box (never on this machine)", r.plan.CloneURL)
	if err := r.execOK(ctx, "clone the repository in the box", sandboxremote.ExecSpec{Argv: argv, Env: env}); err != nil {
		return fmt.Errorf("clone_failed: %w", err)
	}
	return nil
}

// prepareAfterClone finishes a remote_clone run's box: the in-box observer,
// the ownership of its directories, the self-check and the return baseline
// (the clone's HEAD, kept on the run record and in the clone return record,
// recordCloneCommit). Nothing from this machine's tree is uploaded.
func (r *hostedRun) prepareAfterClone(ctx context.Context, owner string) error {
	if err := r.uploadBoxBinary(ctx); err != nil {
		return err
	}
	r.seedToolState(ctx)
	if err := r.giveToBoxUser(ctx, owner, r.layout.Home, path.Dir(r.layout.Binary)); err != nil {
		return err
	}
	if err := r.checkBoxBinary(ctx); err != nil {
		return err
	}
	return r.recordCloneCommit(ctx)
}

// hostedBoxSetupUserScript makes the run's directories as the box user (a
// NoRootExec vendor: every exec already runs as the box user, so nothing is
// chowned). Arguments: the directories, the last one the run dir (made
// owner-only).
const hostedBoxSetupUserScript = `set -e
for d in "$@"; do mkdir -p -- "$d"; last=$d; done
chmod 0700 -- "$last"`

// setupDirs makes the run's directories in the box: as root and handed to
// the box user on a vendor with a root exec, as the box user on a
// NoRootExec vendor (ruling A3; the wire client refuses AsRoot there).
func (r *hostedRun) setupDirs(ctx context.Context, owner string) error {
	dirs := []string{r.layout.Home, r.layout.Workspace, path.Dir(r.layout.Binary), r.layout.RunDir}
	if r.vendor.NoRootExec {
		return r.execOK(ctx, "prepare the box", sandboxremote.ExecSpec{Argv: append([]string{"sh", "-c", hostedBoxSetupUserScript, "sh"}, dirs...)})
	}
	return r.execOK(ctx, "prepare the box", sandboxremote.ExecSpec{
		Argv: append([]string{"sh", "-c", hostedBoxSetupScript, "sh", owner}, dirs...), AsRoot: true,
	})
}

// giveToBoxUser hands trees to the box user after an upload: a root chown on
// a vendor with a root exec; nothing on a NoRootExec vendor, whose uploads
// the box user wrote itself.
func (r *hostedRun) giveToBoxUser(ctx context.Context, owner string, trees ...string) error {
	if r.vendor.NoRootExec {
		return nil
	}
	return r.execOK(ctx, "give the workspace to the box user", sandboxremote.ExecSpec{
		Argv: append([]string{"sh", "-c", hostedBoxOwnScript, "sh", owner}, trees...), AsRoot: true,
	})
}

// handOver ends this machine's record of a box the organization owns (held,
// to be collected, or a resume that did not take): it is not a leftover here
// and is never deleted from this machine. The spend ledger settles to the
// minutes it ran. A MintedCredential vendor's records end this way only.
func (r *hostedRun) handOver() {
	r.rec.State = sandboxremote.StateGone
	r.rec.LastError = "handed to the organization"
	if err := hostedRemoveRecord(r.plan.ObserverDir, r.rec); err != nil && !errors.Is(err, os.ErrNotExist) {
		r.say("this machine's record of the box was not removed: %v", err)
	}
	r.settle()
}

// hostedBoxNamer is a minted credential source that names the run's box.
type hostedBoxNamer interface{ BoxName() string }

// hostedResumeWait bounds the wait for a resumed box to run again (the
// org's worker starts it on the resume mint).
var hostedResumeWait = 3 * time.Minute

// takeOverHeld is a resume launch's create (design 3.6 steps 3 and 4): the
// box exists, held by the organization, and its worker starts it on the
// resume mint. The run records the box under this run's new id, waits for
// it to run, and skips every upload: the workspace, the in-box observer and
// the agent's own session store are kept in the box.
func (r *hostedRun) takeOverHeld(ctx context.Context) error {
	namer, ok := r.cred.Minted.(hostedBoxNamer)
	if !ok || namer.BoxName() == "" {
		return errors.New("a resume needs a minted token that names the held box")
	}
	name := namer.BoxName()
	now := r.now()
	// The resumed box runs again, so its minutes are reserved like a
	// create's (fix round 1, A8), under the same daily cap.
	minutes := r.plan.TimeoutMinutes
	if err := hostedUpdateLedger(r.plan.ObserverDir, now, func(l *sandboxremote.Ledger) error {
		m, err := sandboxremote.PlanTimeout(minutes, r.plan.DailyBoxMinutes, l.Used(r.plan.Provider, sandboxremote.DayOf(now)))
		if err != nil {
			return err
		}
		minutes = m
		l.Reserve(r.plan.Provider, sandboxremote.DayOf(now), r.plan.RunID, minutes)
		return nil
	}); err != nil {
		return err
	}
	r.rec = sandboxremote.NewIntent(r.plan.RunID, r.plan.Provider, r.plan.Endpoint, r.plan.Region, r.plan.RunID, now, time.Duration(minutes)*time.Minute)
	r.rec.Extra = map[string]string{hostedHelperPIDKey: strconv.Itoa(os.Getpid()), "box_name": name, "resumed_box_run": r.plan.ResumeBoxRunID}
	r.rec.VendorID = name
	_ = r.rec.Apply(sandboxremote.EvCreateOK)
	if err := hostedSaveRecord(r.plan.ObserverDir, r.rec); err != nil {
		r.settleNoBox()
		return fmt.Errorf("record the resumed box: %w", err)
	}
	if err := r.resumeBox(ctx, name); err != nil {
		// The box stays the organization's (held, or collected by its
		// worker); this machine's record never outlives the attempt (A5).
		r.handOver()
		return err
	}
	// The relay is re-keyed: the relay secrets of the run that was held are
	// void, so the box record is replaced with this run's keys.
	r.resumed, r.rekey = true, true
	r.say("resumed the held box %s (run %s); the workspace and the agent's sessions are as they were held", name, r.plan.ResumeBoxRunID)
	return nil
}

// resumeBox waits for the held box to run again and puts back whatever the
// run needs that the hold did not keep (ruling A4): the run dir and the
// in-box observer are checked and, when missing, made and uploaded again,
// so a resume never depends on persistence alone.
func (r *hostedRun) resumeBox(ctx context.Context, name string) error {
	// The one ready wait a fresh box uses too (FX3 item 1).
	if _, err := r.waitBoxRunning(ctx, name, hostedResumeWait); err != nil {
		return fmt.Errorf("the held box %s did not start within %s (your organization's worker starts it on the resume): %w", name, hostedResumeWait, err)
	}
	owner := r.boxOwner(ctx)
	if err := r.setupDirs(ctx, owner); err != nil {
		return err
	}
	// A box prepared before the first-run state was seeded (F-L3P4-8) gets
	// it now; one that has the file keeps it.
	r.seedToolState(ctx)
	err := r.checkBoxBinary(ctx)
	if err == nil {
		return nil
	}
	if r.plan.BoxBinaryInImage {
		return err // nothing to send: the image carries it
	}
	r.say("the in-box observer did not survive the hold; sending it again")
	if err := r.checkArch(ctx); err != nil {
		return err
	}
	if err := r.uploadBoxBinary(ctx); err != nil {
		return err
	}
	return r.checkBoxBinary(ctx)
}

// hostedResumePoll is the longest wait between a ready wait's box checks
// (a resume's and a new box's; a variable for tests).
var hostedResumePoll = 3 * time.Second

// hostedSessionsPath is the box run dir's sessions.json (the agent session
// ids the run's hooks carried; no content).
func (r *hostedRun) hostedSessionsPath() string { return path.Join(r.layout.RunDir, "sessions.json") }

// hostedLastSession is the session a resume continues, read from the box's
// sessions.json (the read's output, exit code and error). The file is in
// the box, so its value is the box's: it is checked with hostedSessionIDOK,
// the rule the write side applies, before it can reach the agent's argv
// (fold delta audit N2: a leading "-" would be read as a flag). An absent
// or unreadable file is "" with refused false; a value that fails the
// check is "" with refused true.
func hostedLastSession(out []byte, code int, err error) (last string, refused bool) {
	if err != nil || code != 0 {
		return "", false
	}
	var s struct {
		Last string `json:"last"`
	}
	if json.Unmarshal(out, &s) != nil || s.Last == "" {
		return "", false
	}
	if !hostedSessionIDOK(s.Last) {
		return "", true
	}
	return s.Last, false
}

// withResumeArgs adds the tool's native resume tail to the inner launcher
// argv when the vendor's registration composes one and the box names the
// last session (design 3.6 step 5); otherwise a fresh session starts in the
// kept workspace, said so.
func (r *hostedRun) withResumeArgs(inner []string) []string {
	reg := hostedVendorRegs[r.plan.Provider]
	if reg.resumeArgs == nil || len(inner) < 2 {
		return inner
	}
	out, code, err := hostedExecOutput(context.Background(), r.client, r.rec.VendorID, []string{"cat", "--", r.hostedSessionsPath()}, r.boxEnv(), 64<<10)
	last, refused := hostedLastSession(out, code, err)
	if refused {
		r.say("the box's %s names a session that is not a session id, so it is not passed to the agent; %s starts a fresh session in the kept workspace, whose files are as they were held", r.hostedSessionsPath(), r.plan.Tool)
		return inner
	}
	tail := reg.resumeArgs(r.plan.Tool, last)
	switch {
	case tail == nil && last == "":
		// Said apart from a tool with no native resume (FX3 item 7,
		// F-L3P4-8): the box names no session of the agent's own.
		r.say("the agent's own session cannot be resumed: the box recorded none (%s names no session), so %s starts a fresh session in the kept workspace, whose files are as they were held", r.hostedSessionsPath(), r.plan.Tool)
		return inner
	case tail == nil:
		r.say("the agent's own session %s cannot be resumed: %s has no native resume Observer can drive, so it starts a fresh session in the kept workspace, whose files are as they were held", last, r.plan.Tool)
		return inner
	}
	res := append([]string{inner[0], inner[1]}, tail...)
	return append(res, inner[2:]...)
}
