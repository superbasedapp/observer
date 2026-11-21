//go:build linux && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxengine"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox_oci_run.go is the engine half of the oci-runc host
// helper (sandbox plan v2 sections 4.6 and 5.5; JSP-4): create the
// container from the plan, read it back before anything runs, attach to
// its main process BEFORE start (so no output is lost), open the wait
// BEFORE start (so the status is this run's), start it, pump the terminal
// both ways, pass resizes on, re-attach after a dropped stream with the
// two-step repaint, and keep the exit status. A container whose state is
// not running is never attached to, signalled, resized or stopped
// (sandboxoci.Allowed): on Podman that re-initialises it or rewrites its
// status. Teardown removes the container. The terminal and signals are
// injected (ociTerm), so a test drives it against a fake engine.

// ociTerm is the helper's terminal: its byte streams, its size, resize and
// stop notifications, and raw mode.
type ociTerm struct {
	in  io.Reader
	out io.Writer
	// size returns the terminal's rows and columns (0, 0 when unknown).
	size func() (uint16, uint16)
	// resized delivers one value per terminal resize.
	resized <-chan struct{}
	// stopped delivers a signal name when the helper is asked to end the
	// run (the terminal closed: SIGHUP; a SIGTERM).
	stopped <-chan string
	// raw puts the terminal in raw mode and returns the restore.
	raw func() func()
	// interactive reports whether someone can answer on the terminal (its
	// stdin is a terminal); nil is false. The first-start install asks
	// there (lane SBX-P3C).
	interactive func() bool
	// keepOnHangup, when set, is asked on a stop request (R-033): true
	// keeps the container running for re-adoption after a daemon exit, and
	// the helper then leaves without stopping or removing it; nil always
	// stops, as before.
	keepOnHangup func() bool
	// detached is set when the helper left the container for re-adoption.
	detached *atomic.Bool
	// awaitOffer, when set, bounds a kept container's life (LEFT2 audit
	// S4): asked once the helper left the container, false (no offer from
	// the next start within the re-adoption bound) stops it after all.
	awaitOffer func() bool
}

// ociReattachAttempts bounds the re-attach loop after a dropped stream.
const ociReattachAttempts = 5

// ociRun is one run's engine state.
type ociRun struct {
	c       *sandboxengine.Client
	id      string
	engine  sandboxoci.Engine
	term    ociTerm
	running atomic.Bool

	mu     sync.Mutex
	stream *sandboxengine.Stream
}

// driveOCIRun runs the container for plan with inner as the agent's
// launch, and returns the exit status to give the terminal. A refusal
// before start returns sandboxHelperFailCode with one line on the
// terminal; nothing of the agent ran.
func driveOCIRun(ctx context.Context, plan ociPlanFile, inner []string, env []string, t ociTerm) int {
	fail := func(format string, a ...any) int {
		fmt.Fprintf(t.out, "observer sandbox (%s): "+format+"\r\n", append([]any{ociRowLabel(plan)}, a...)...)
		return sandboxHelperFailCode
	}
	if len(inner) == 0 {
		return fail("no inner launch")
	}
	c, err := ociEngineClient(plan.Socket, plan.APIVersion)
	if err != nil {
		return fail("%v", err)
	}
	// The daemon on the socket must still be the one the probe recorded
	// (A9): read it again now, right before driving it.
	qctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	v, err := c.Version(qctx)
	if err != nil {
		cancel()
		return fail("%s: %v", sandboxoci.VerdictEngineUnreachable, err)
	}
	pre, _ := sandboxoci.Classify(v, sandboxoci.InfoFacts{})
	info, err := c.Info(qctx, pre.Engine)
	cancel()
	if err != nil {
		return fail("%s: %v", sandboxoci.VerdictEngineUnreachable, err)
	}
	id, verdict := sandboxoci.Classify(v, info)
	if !verdict.OK() {
		return fail("%s", verdict.Error())
	}
	if id.Fingerprint != plan.Fingerprint || id.Engine != plan.Engine || id.Mode != plan.Mode {
		return fail("%s: the daemon on %s changed after the launch was planned", sandboxoci.VerdictSocketUntrusted, plan.Socket)
	}
	// The row's runtime and socket bridge, read again from the same answer
	// (oci-runsc: runsc still registered with --host-uds=open).
	if plan.Backend != "" {
		profile, ok := sandboxoci.RuntimeProfileFor(plan.Backend)
		if !ok {
			return fail("%s: the plan names an unknown row %q", sandboxoci.VerdictRuntimeMissing, plan.Backend)
		}
		if plan.Create.Runtime != profile.CreateRuntime {
			return fail("%s: the plan's runtime %q is not the %s row's", sandboxoci.VerdictRuntimeMissing, plan.Create.Runtime, plan.Backend)
		}
		if _, v := sandboxoci.CheckRuntime(profile, id, info); !v.OK() {
			return fail("%s", v.Error())
		}
	}

	// The image's own environment is merged under the create body's: an
	// image that sets a routing, proxy or loader variable is refused before
	// anything is created (SBX-P3A merge finding F2).
	if v := ociImageEnvVerdict(ctx, c, plan.Create.Image); !v.OK() {
		return fail("%s", v.Error())
	}
	// The first-start install (lane SBX-P3C) runs on the daemon just
	// verified, after the image's environment passed and before anything of
	// the agent is created; a refused or failed install ends the launch.
	if err := ociInstall(ctx, c, id, plan, t); err != nil {
		return fail("%v", err)
	}
	cp := plan.Create
	cp.Entrypoint = append(append([]string(nil), cp.Entrypoint...), inner...)
	cp.Env = env
	// The engine just verified on the socket (never the plan file's word)
	// picks the tmpfs owner form.
	cp.Engine = id.Engine
	name, body, err := sandboxoci.BuildCreate(cp)
	if err != nil {
		return fail("%v", err)
	}
	cctx, ccancel := context.WithTimeout(ctx, 60*time.Second)
	cid, _, err := c.ContainerCreate(cctx, name, body)
	ccancel()
	if err != nil {
		// The engine may have made the container although the answer
		// failed or never came (Linux live check 2026-10-23: a timed-out
		// create left one behind until the reaper's sweep); remove it by
		// its name now.
		ociRemoveByName(c, name)
		return fail("create the container: %v", err)
	}
	run := &ociRun{c: c, id: cid, engine: id.Engine, term: t}
	defer func() {
		if run.isDetached() {
			// Left for re-adoption (R-033): the container keeps running.
			if s := run.currentStream(); s != nil {
				_ = s.Close()
			}
			// LEFT2 audit S4: only until the re-adoption bound. With no
			// offer by then the helper stops it and tears down as usual.
			if t.awaitOffer == nil || t.awaitOffer() {
				return
			}
			t.detached.Store(false)
			sctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			_ = run.c.ContainerStop(sctx, run.id, ociStopGrace)
			cancel()
		}
		run.remove()
	}()

	// The re-check (section 4.4) before anything of the agent runs.
	if v := run.readBack(ctx, id, cp); !v.OK() {
		return fail("%s", v.Error())
	}
	stream, err := c.ContainerAttach(ctx, cid)
	if err != nil {
		return fail("attach to the container: %v", err)
	}
	run.setStream(stream)
	wait, err := c.ContainerWait(ctx, cid, sandboxoci.WaitCondition)
	if err != nil {
		return fail("open the wait: %v", err)
	}
	restore := func() {}
	if t.raw != nil {
		restore = t.raw()
	}
	defer restore()
	if err := c.ContainerStart(ctx, cid); err != nil {
		restore()
		return fail("start the container: %v", err)
	}
	run.running.Store(true)
	run.resize(ctx, false)

	go run.pumpInput()
	go run.watch(ctx)

	code := run.pumpOutput(ctx, wait)
	return code
}

// ociImageEnvVerdict reads the image's own Config.Env and judges it
// (sandboxoci.ImageEnvRefusal); an image that cannot be read is refused too.
func ociImageEnvVerdict(ctx context.Context, c *sandboxengine.Client, image string) sandboxoci.Verdict {
	ictx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	env, err := c.ImageEnv(ictx, image)
	if err != nil {
		return sandboxoci.Verdict{Code: sandboxoci.VerdictBuiltBelowPlan, Reason: "the image's own environment could not be read: " + err.Error()}
	}
	return sandboxoci.ImageEnvRefusal(env)
}

// readBack inspects the created container and judges it against the plan.
func (r *ociRun) readBack(ctx context.Context, id sandboxoci.Identity, cp sandboxoci.CreatePlan) sandboxoci.Verdict {
	ictx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var raw []byte
	var err error
	if r.engine == sandboxoci.EnginePodman {
		raw, err = r.c.ContainerInspectLibpod(ictx, r.id)
	} else {
		raw, err = r.c.ContainerInspect(ictx, r.id)
	}
	if err != nil {
		return sandboxoci.Verdict{Code: sandboxoci.VerdictBuiltBelowPlan, Reason: "the container could not be read back: " + err.Error()}
	}
	facts, err := sandboxoci.ParseInspect(raw, r.engine)
	if err != nil {
		return sandboxoci.Verdict{Code: sandboxoci.VerdictBuiltBelowPlan, Reason: err.Error()}
	}
	return sandboxoci.ReadBack(sandboxoci.ReadBackInput{Identity: id, Plan: cp, Facts: facts})
}

func (r *ociRun) setStream(s *sandboxengine.Stream) {
	r.mu.Lock()
	old := r.stream
	r.stream = s
	r.mu.Unlock()
	if old != nil && old != s {
		_ = old.Close()
	}
}

func (r *ociRun) currentStream() *sandboxengine.Stream {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stream
}

// pumpInput copies the terminal's input to the current stream; a write
// that fails waits for the re-attach.
func (r *ociRun) pumpInput() {
	buf := make([]byte, 32<<10)
	for {
		n, err := r.term.in.Read(buf)
		if n > 0 {
			for i := 0; i < 50; i++ {
				if s := r.currentStream(); s != nil {
					if _, werr := s.Write(buf[:n]); werr == nil {
						break
					}
				}
				if !r.running.Load() {
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
		if err != nil {
			return
		}
	}
}

// watch passes resizes on and turns a stop request into the engine's stop
// (never on a container that is not running).
func (r *ociRun) watch(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-r.term.resized:
			if !ok {
				r.term.resized = nil
				continue
			}
			r.resize(ctx, false)
		case sig, ok := <-r.term.stopped:
			if !ok {
				r.term.stopped = nil
				continue
			}
			if r.term.keepOnHangup != nil && r.running.Load() && r.term.keepOnHangup() {
				// A daemon exit with the run marked re-adoptable (R-033):
				// leave the container running; the output pump sees the
				// closed stream and returns.
				if r.term.detached != nil {
					r.term.detached.Store(true)
				}
				if s := r.currentStream(); s != nil {
					_ = s.Close()
				}
				return
			}
			if sandboxoci.Allowed(sandboxoci.ActionStop, r.running.Load()) {
				sctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
				_ = r.c.ContainerStop(sctx, r.id, ociStopGrace)
				cancel()
			}
			_ = sig
		}
	}
}

// isDetached reports whether the helper left the container for re-adoption.
func (r *ociRun) isDetached() bool { return r.term.detached != nil && r.term.detached.Load() }

// ociDetachedCode is the helper's status when it left the container for
// re-adoption (128 + SIGHUP, what a hung-up terminal reports).
const ociDetachedCode = 129

// ociStopGrace is the stop grace the helper asks for (the engine's own
// StopTimeout from the create body applies when the engine decides).
var ociStopGrace = 10 * time.Second

// resize passes the terminal size to the engine; repaint sends a different
// size first (columns minus one), then the real one, because a same-size
// resize raises no SIGWINCH (section 5.5; JSP-4 measured 0 and 2).
func (r *ociRun) resize(ctx context.Context, repaint bool) {
	if r.term.size == nil || !sandboxoci.Allowed(sandboxoci.ActionResize, r.running.Load()) {
		return
	}
	rows, cols := r.term.size()
	if rows == 0 || cols == 0 {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if repaint && cols > 1 {
		_ = r.c.ContainerResize(rctx, r.id, rows, cols-1)
	}
	_ = r.c.ContainerResize(rctx, r.id, rows, cols)
}

// pumpOutput copies the stream to the terminal, re-attaching after a drop
// while the container runs, until the wait reports the end. It returns the
// container's exit status.
func (r *ociRun) pumpOutput(ctx context.Context, wait <-chan sandboxengine.WaitResult) int {
	done := make(chan int, 1)
	go func() {
		res := <-wait
		r.running.Store(false)
		code := res.StatusCode
		if res.Err != nil || code < 0 {
			code = sandboxHelperFailCode
		}
		done <- code
		// The engine closes the attach stream when the container ends; a
		// short grace for its last output, then it is closed here too, so
		// the copy below never outlives the run.
		time.Sleep(200 * time.Millisecond)
		if s := r.currentStream(); s != nil {
			_ = s.Close()
		}
	}()
	out := ociNoNUL{w: r.term.out}
	for {
		s := r.currentStream()
		if s != nil {
			_, _ = io.Copy(out, s)
		}
		// The stream ended: either the container exited, or the transport
		// dropped while it still runs, or the helper left the container for
		// re-adoption (R-033).
		if r.isDetached() {
			return ociDetachedCode
		}
		select {
		case code := <-done:
			return code
		case <-time.After(300 * time.Millisecond):
		}
		if !r.stillRunning(ctx) {
			return <-done
		}
		down := time.Now()
		if !r.reattach(ctx) {
			// Nothing more to show; keep the status from the wait.
			return <-done
		}
		fmt.Fprintf(r.term.out, "\r\n[observer: the container's terminal stream dropped and was re-attached after %s; output from that gap may be missing]\r\n", time.Since(down).Round(time.Millisecond))
		r.resize(ctx, true)
	}
}

// ociNoNUL drops NUL bytes from the box's terminal output on its way to the
// helper's terminal. A NUL draws nothing on a terminal, but a typescript or
// a log shows it: every oci-runc launch on the live Docker 29.9.2 host
// showed one `^@` before the launcher's first line (live check 2026-10-22).
// The box's own chain writes none (a raw attach of the same init, guest and
// launcher on Docker 28.1.1 carried no NUL), so it is dropped here, at the
// one seam all of the container's output passes, and nowhere on the input
// side (Ctrl-@ is a real keystroke the agent may want). The `^@` those
// launches showed was in fact two printable bytes, the box terminal's echo
// of a NUL keystroke the helper had sent: the canonical end-of-file marker a
// plain raw switch exposes, which ociEnterRaw now discards (Linux live check
// 2026-10-23, R3).
type ociNoNUL struct{ w io.Writer }

// Write writes p without its NUL bytes and reports all of p as written.
func (n ociNoNUL) Write(p []byte) (int, error) {
	if bytes.IndexByte(p, 0) < 0 {
		return n.w.Write(p)
	}
	if q := bytes.ReplaceAll(p, []byte{0}, nil); len(q) > 0 {
		if _, err := n.w.Write(q); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// stillRunning reads the container's state (the wait-first rule: the
// helper's own running flag is cleared by the wait; the engine's word is
// asked only while that flag still says running).
func (r *ociRun) stillRunning(ctx context.Context) bool {
	if !r.running.Load() {
		return false
	}
	ictx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := r.c.ContainerInspect(ictx, r.id)
	if err != nil {
		return false
	}
	var st struct {
		State struct {
			Running bool `json:"Running"`
		} `json:"State"`
	}
	if json.Unmarshal(raw, &st) != nil {
		return false
	}
	return st.State.Running && r.running.Load()
}

// reattach opens a new attach stream while the container runs.
func (r *ociRun) reattach(ctx context.Context) bool {
	backoff := 200 * time.Millisecond
	for i := 0; i < ociReattachAttempts; i++ {
		if !sandboxoci.Allowed(sandboxoci.ActionAttach, r.running.Load()) {
			return false
		}
		s, err := r.c.ContainerAttach(ctx, r.id)
		if err == nil {
			r.setStream(s)
			return true
		}
		time.Sleep(backoff)
		backoff *= 2
	}
	return false
}

// ociRemoveByName removes the container a failed create may have left under
// its name; nothing there is no error.
func ociRemoveByName(c *sandboxengine.Client, name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_ = c.ContainerRemove(ctx, name)
}

// remove is the teardown: the container goes, whatever happened.
func (r *ociRun) remove() {
	if s := r.currentStream(); s != nil {
		_ = s.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_ = r.c.ContainerRemove(ctx, r.id)
}

// ociContainerEnv is the box's environment: the helper's own (the launch
// environment the daemon gave the PTY child) without the host socket and
// interop variables bwrap also drops (sandbox.GuestUnsetEnv), the
// variables a box may never carry (sandboxoci.DeniedEnv), the variables
// that point at host-only paths (XDG_RUNTIME_DIR) and the trusted
// launcher channel's descriptor and secret (no descriptor crosses into a
// container). The sandbox marker is set.
func ociContainerEnv(environ []string, planDrop ...string) []string {
	// The allow-list first (WINFIX2, ledger SBX-WIN-ENV-1), less the plan's drops
	// (ociPlanFile.DropEnv); the drops below stay.
	environ = sandboxBoxEnv("linux", environ, planDrop...)
	drop := map[string]bool{"XDG_RUNTIME_DIR": true, envOOBFD: true, envOOBAuth: true, sandboxEnvMarker: true}
	for _, k := range sandbox.GuestUnsetEnv {
		drop[k] = true
	}
	for _, k := range sandboxoci.DeniedEnv() {
		drop[k] = true
	}
	out := make([]string, 0, len(environ)+1)
	for _, kv := range environ {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || k == "" || drop[k] {
			continue
		}
		out = append(out, kv)
	}
	return append(out, sandboxEnvMarker+"=1")
}

// ociPrependPath puts dir first on the environment's PATH (the tool cache's
// bin directory of a cache-installed tool); a PATH-less environment gets one
// with the usual system directories after dir.
func ociPrependPath(env []string, dir string) []string {
	out := make([]string, 0, len(env)+1)
	found := false
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok && !found {
			found = true
			kv = "PATH=" + dir + string(os.PathListSeparator) + v
		}
		out = append(out, kv)
	}
	if !found {
		out = append(out, "PATH="+dir+":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	}
	return out
}

// parseOCIHostArgs reads `--plan <path> -- observer sandbox-host <flags>
// -- <inner...>`.
func parseOCIHostArgs(args []string) (string, sandbox.HostArgs, error) {
	if len(args) < 3 || args[0] != "--plan" || args[2] != "--" {
		return "", sandbox.HostArgs{}, errors.New("usage: sandbox-oci-host --plan <file> -- <observer> sandbox-host <flags> -- <launch>")
	}
	rest := args[3:]
	if len(rest) < 2 || rest[1] != sandbox.HostVerb {
		return "", sandbox.HostArgs{}, errors.New("the host services are missing after --plan")
	}
	h, err := sandbox.ParseHostArgs(rest[2:])
	if err != nil {
		return "", sandbox.HostArgs{}, err
	}
	if len(h.Command) < 2 || h.Command[0] != ociInnerMarker {
		return "", sandbox.HostArgs{}, errors.New("no inner launch after the marker")
	}
	h.Command = h.Command[1:]
	return args[1], h, nil
}

// ociRowLabel is the row a run's refusals name once its plan is read: the
// plan's own backend (oci-runc or oci-runsc), oci-runc for a plan written
// before the oci-runsc row (Linux live re-check on the Docker sandbox
// 2026-10-23, N5: the runsc row's refusals read "oci-runc"). A refusal
// before the plan is read still names oci-runc, the verb's own row.
func ociRowLabel(plan ociPlanFile) string {
	if plan.Backend != "" {
		return plan.Backend
	}
	return sandboxoci.RuntimeOCIRunc
}

// runOCIHostWith is runOCIHost over an injected terminal and socket check:
// read the plan, start the host services, drive the run.
func runOCIHostWith(args []string, t ociTerm, checkSocket func(plan ociPlanFile) error) int {
	planPath, h, err := parseOCIHostArgs(args)
	if err != nil {
		return helperFail("observer sandbox (oci-runc): %v", err)
	}
	plan, err := readOCIPlan(planPath)
	_ = os.Remove(planPath) //nolint:gosec // G703: the plan file the daemon wrote for this helper; read no-follow and owner-checked above
	if err != nil {
		return helperFail("observer sandbox (oci-runc): %v", err)
	}
	if checkSocket != nil {
		if err := checkSocket(plan); err != nil {
			return helperFail("observer sandbox (%s): %v", ociRowLabel(plan), err)
		}
	}
	for _, n := range plan.Notices {
		fmt.Fprintf(t.out, "observer sandbox: %s\r\n", n)
	}
	// A daemon exit with this run marked re-adoptable keeps the container
	// (R-033); the helper then leaves as a killed one would, with no
	// teardown, so the next start offers the run.
	var detached atomic.Bool
	t.detached = &detached
	if f := ociReadoptKeepOnHangup; f != nil {
		t.keepOnHangup = f(h.ObserverDir, h.RelayRun)
	}
	if f := ociReadoptAwaitOffer; f != nil {
		t.awaitOffer = f(h.ObserverDir, h.RelayRun)
	}
	stop, err := startHostServices(h)
	release := sync.OnceFunc(stop)
	defer func() {
		if !detached.Load() {
			release()
		}
	}()
	if err != nil {
		return helperFail("observer sandbox (%s): %v", ociRowLabel(plan), err)
	}
	// The tier comes from this helper's own flags (withSandboxTier, R3).
	env := localCredBoxEnv(h, withSandboxTier(ociContainerEnv(os.Environ(), plan.DropEnv...), h))
	if plan.PathPrefix != "" {
		env = ociPrependPath(env, plan.PathPrefix)
	}
	for _, kv := range plan.ExtraEnv {
		if k, _, ok := strings.Cut(kv, "="); ok && sandboxoci.AllowedContainerEnv(k) {
			env = append(env, kv)
		}
	}
	// The OOB channel into the container (plan 5.6, lane SBX-P3C): the
	// trusted half stays on this helper's fd 3, the box gets a socket.
	oob, boxEnv := ociOpenOOB(os.Getenv, h.SockDir)
	env = append(env, boxEnv...)
	code := driveOCIRun(context.Background(), plan, h.Command, env, t)
	if detached.Load() {
		return code
	}
	oob.end(code)
	ociEndRun(plan, t, release)
	return code
}

// ociEndRun is the helper's end once the container has ended: release first
// (the host services, and with them Observer's own placeholders, each removed
// only while it is still the inode the helper made holding the body it was
// made with), then ociAfterRun, so the return step's scan of the copy's git
// dir sees only what the box wrote. Before this order every clone-local
// return was refused naming the placeholders, even for a box that only
// committed (Linux live re-check 3, 2026-10-23, D3); a box-written file is
// never removed, so it is still refused.
func ociEndRun(plan ociPlanFile, t ociTerm, release func()) {
	release()
	ociAfterRun(plan, t)
}

// ociAfterRun is what the helper does once the container has ended: the
// return step of a clone-local copy, the db-copy collection, and then the
// removal of the run's projected state directories, which nothing needs
// after the copies are read (Linux live check 2026-10-23, R1: they stayed
// until the next daemon start). A removal that fails is said; the daemon's
// start sweep still removes what is left.
func ociAfterRun(plan ociPlanFile, t ociTerm) {
	if plan.Return != nil {
		ociReturn(context.Background(), *plan.Return, ociReturnScan(plan.ConfigPath), t)
	} else if plan.ReturnRefused != "" {
		fmt.Fprintf(t.out, "\r\n[observer: %s]\r\n", plan.ReturnRefused)
	}
	ociCollectDBCopies(plan, t)
	// A run no watcher took (a CLI launch) is read once now, before the
	// projection goes (lane LEFT-SBX).
	ociIngestUnwatched(plan, t)
	// A watched run (or one from a daemon before the Transcripts field)
	// leaves the watcher its settle pass.
	if len(plan.TranscriptRoots) > 0 && (plan.TranscriptsWatched || len(plan.Transcripts) == 0) {
		// The watcher reads a transcript's last lines in its settle pass.
		time.Sleep(ociProjectionSettle)
	}
	if err := ociRemoveProjection(plan.Projections); err != nil {
		fmt.Fprintf(t.out, "\r\n[observer: the run's projected state was not removed: %v; the next daemon start removes it]\r\n", err)
	}
}

// ociProjectionSettle is how long the helper leaves a projection with
// transcript roots in place after the container ends, so the watcher's
// settle pass (2 s after the last write) reads the last lines; a variable
// for tests.
var ociProjectionSettle = 3 * time.Second

// ociRemoveProjection removes the run's projected state root, the one
// parent every projected directory shares (<managed>/<run>.state,
// sandboxoci.PlanProjection). Nothing with no projection; a root that is
// not that shape, or is not a plain directory (a symlink), is left alone
// and reported.
func ociRemoveProjection(proj []sandboxoci.ProjectedDir) error {
	if len(proj) == 0 {
		return nil
	}
	root := filepath.Dir(proj[0].Host)
	if !filepath.IsAbs(root) || !strings.HasSuffix(filepath.Base(root), sandboxoci.ProjectionLeaf) {
		return fmt.Errorf("%s is not a projected state root", root)
	}
	for _, pd := range proj {
		if filepath.Dir(pd.Host) != root {
			return fmt.Errorf("the projected directories do not share one root (%s, %s)", root, pd.Host)
		}
	}
	st, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%s is not a directory, left alone", root)
	}
	return os.RemoveAll(root)
}

// ociReturnScan is the return step's scan in the helper: the bound scan
// with the daemon's config path from the plan (lane sec-box audit finding
// 4); nil while no scan is bound.
func ociReturnScan(configPath string) func(context.Context, sandboxReturnScanInput) error {
	scan := sandboxReturnScan
	if scan == nil {
		return nil
	}
	return func(ctx context.Context, in sandboxReturnScanInput) error {
		in.ConfigPath = configPath
		return scan(ctx, in)
	}
}

// ociReturn runs the return step of a clone-local copy once its container
// has ended, and says on the terminal what came back.
func ociReturn(ctx context.Context, req workspace.ReturnRequest, scan func(context.Context, sandboxReturnScanInput) error, t ociTerm) {
	if req.Bare {
		ociReturnBare(ctx, req, scan, t)
		return
	}
	res, err := sandboxReturn(ctx, req, runReturnGit, scan)
	switch {
	case err != nil:
		fmt.Fprintf(t.out, "\r\n[observer: the box's commits were not returned: %v; the copy is kept at %s]\r\n", err, req.CopyDir)
	case res.NothingNew:
		fmt.Fprintf(t.out, "\r\n[observer: the box made no new commit; the copy is kept at %s]\r\n", req.CopyDir)
	default:
		fmt.Fprintf(t.out, "\r\n[observer: the box's commits are on %s in %s (commit %.12s); your branch and working tree are unchanged]\r\n", res.Ref, req.SourceRepo, res.Commit)
	}
}

// ociReturnBare runs the return of a clone-remote copy into its bare return
// repository (lane SBX-P3C) and says on the terminal where the commits are
// and the one command that brings them into the developer's checkout.
func ociReturnBare(ctx context.Context, req workspace.ReturnRequest, scan func(context.Context, sandboxReturnScanInput) error, t ociTerm) {
	res, err := sandboxReturnBare(ctx, req, runReturnGit, scan)
	switch {
	case err != nil:
		fmt.Fprintf(t.out, "\r\n[observer: the box's commits were not returned: %v; the copy is kept at %s]\r\n", err, req.CopyDir)
	case res.NothingNew:
		fmt.Fprintf(t.out, "\r\n[observer: the box made no new commit; the copy is kept at %s]\r\n", req.CopyDir)
	default:
		fmt.Fprintf(t.out, "\r\n[observer: the box's commits are on %s in the return repository %s (commit %.12s); nothing was pushed. In your checkout run: %s ; the copy is kept at %s]\r\n",
			res.Ref, req.SourceRepo, res.Commit, workspace.ReturnFetchCommand(req.SourceRepo, res.Ref), req.CopyDir)
	}
}

// ociCollectDBCopies reads the guest's db-copy copies out of each projected
// state directory (oci-runsc, lane SBX-P3B) once the container has ended,
// no-follow and capped (collectGuestDBCopies), and says on the terminal
// what it kept and what it refused. Nothing with no projection.
func ociCollectDBCopies(plan ociPlanFile, t ociTerm) {
	if len(plan.Projections) == 0 || plan.DBCopyDest == "" {
		return
	}
	kept := 0
	for i, pd := range plan.Projections {
		n, err := collectGuestDBCopies(pd.Host, filepath.Join(plan.DBCopyDest, fmt.Sprintf("%d", i)))
		kept += n
		if err != nil {
			fmt.Fprintf(t.out, "\r\n[observer: some of the box's SQLite copies were refused: %v]\r\n", err)
		}
	}
	if kept > 0 {
		fmt.Fprintf(t.out, "\r\n[observer: %d SQLite store copies from the box were checked and kept under %s]\r\n", kept, plan.DBCopyDest)
	}
}
