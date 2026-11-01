package host

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/extrun"
)

// Defaults for the Executor knobs.
const (
	defaultPollInterval = 50 * time.Millisecond
	defaultDrainTimeout = 2 * time.Second
	readChunk           = 32 << 10
)

// Executor is the production extrun.Executor.
type Executor struct {
	// PollInterval is how often the child-process count is read where the
	// OS lets it be counted (Linux). Zero means 50ms.
	PollInterval time.Duration
	// DrainTimeout bounds how long the output pipes may stay open after the
	// group is killed before the run is marked Leftover. Zero means 2s.
	DrainTimeout time.Duration
	// NoTrampoline starts programs directly even where the binary offers
	// the trampoline (TrampolineDispatch): the per-process caps are then
	// reported not enforced. For tests of that path; production leaves it
	// false.
	NoTrampoline bool
	// CgroupParent, when set, is a writable cgroup v2 directory (for example
	// the daemon's own unit with Delegate=yes, or a delegated subtree) under
	// which each run gets its own child cgroup: the first cgroup source.
	CgroupParent string
	// NoSystemdScope turns off the second cgroup source, a transient
	// systemd scope with Delegate=yes per run.
	NoSystemdScope bool
	// StopGrace is how long the not-contained rung's supervisor gets to
	// sweep after it is told to stop, before the whole group is killed (so a
	// stopped run can end up to this much after its wall cap). Zero means
	// 3s.
	StopGrace time.Duration

	activeMu sync.Mutex
	active   map[*launch]struct{}
}

// NewExecutor returns an Executor with the defaults.
func NewExecutor() *Executor { return &Executor{} }

// procGroup is the OS handle on everything one run started.
type procGroup interface {
	// kill kills every process in the group. Safe to call more than once.
	kill()
	// count returns how many processes run beside the leader; ok is false
	// when this OS cannot count them.
	count() (n int, ok bool)
	// close releases the handle.
	close()
}

// softStopper is a procGroup whose leader should first be asked to stop
// (the supervisor, which then sweeps what the program left), before the
// group is killed.
type softStopper interface {
	softStop()
}

// rungSetup is how one rung starts a run: an optional launcher in front of
// the trampoline (a transient systemd scope), the payload's mode and cgroup
// to join, the containment facts it already knows, and its cleanup.
type rungSetup struct {
	launcher    []string
	launcherEnv []string
	mode        string
	cgroupJoin  string
	// notUnder is the daemon's own cgroup: the trampoline refuses a run
	// cgroup that is it or one of its ancestors, so a cgroup.kill can never
	// reach the daemon.
	notUnder string
	cont     extrun.Containment
	cleanup  func()
}

// launch is one started run: the process, its group, its output and the
// trampoline's status.
type launch struct {
	cmd     *exec.Cmd
	grp     procGroup
	status  *statusLog
	outR    *os.File
	errR    *os.File
	stdout  *capBuf
	stderr  *capBuf
	readers sync.WaitGroup
	trig    chan extrun.KillReason
	start   time.Time
	// startTicks is the boot-relative start in clock ticks, for the
	// survivor scan (Linux).
	startTicks uint64
	tramp      bool
	rung       extrun.Rung
	setup      rungSetup
	identity   []string
}

// fire records the first kill reason; later ones are dropped.
func (l *launch) fire(r extrun.KillReason) {
	select {
	case l.trig <- r:
	default:
	}
}

// rungError is a failure to set a rung up before the program ran: the
// executor falls through to the next rung.
type rungError struct{ reason string }

func (e rungError) Error() string { return e.reason }

// startAbort is a start that ended because the run itself ended before the
// program was reached: the caller's context was cancelled, or the one wall
// deadline of the run passed, during a rung's ready wait. The next rungs are
// never tried (decision log P-018 items b and c).
type startAbort struct{ reason extrun.KillReason }

func (e startAbort) Error() string {
	return "the run ended before the program started: " + string(e.reason)
}

// settler is a procGroup that can wait, after its kill, until every member
// is gone (a cgroup reports its members; a process group cannot).
type settler interface {
	settle()
}

// Platform reports the caps this executor enforces on this OS.
func (e *Executor) Platform() extrun.Platform {
	return extrun.Platform{GOOS: runtime.GOOS, Caps: platformCaps()}
}

func (e *Executor) pollInterval() time.Duration {
	if e.PollInterval > 0 {
		return e.PollInterval
	}
	return defaultPollInterval
}

func (e *Executor) stopGrace() time.Duration {
	if e.StopGrace > 0 {
		return e.StopGrace
	}
	return 3 * time.Second
}

func (e *Executor) drainTimeout() time.Duration {
	if e.DrainTimeout > 0 {
		return e.DrainTimeout
	}
	return defaultDrainTimeout
}

// capBuf keeps up to limit bytes of one stream and discards the rest, so the
// program never blocks on a full pipe before the kill lands.
type capBuf struct {
	mu        sync.Mutex
	limit     int64
	buf       bytes.Buffer
	truncated bool
}

// drain reads r until EOF or an error. overflow is called once, when the
// stream first passes the limit.
func (c *capBuf) drain(r io.Reader, overflow func()) {
	chunk := make([]byte, readChunk)
	for {
		n, err := r.Read(chunk)
		if n > 0 {
			c.mu.Lock()
			room := c.limit - int64(c.buf.Len())
			if int64(n) > room {
				if room > 0 {
					c.buf.Write(chunk[:room])
				}
				if !c.truncated {
					c.truncated = true
					c.mu.Unlock()
					overflow()
					c.mu.Lock()
				}
			} else {
				c.buf.Write(chunk[:n])
			}
			c.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

// snapshot returns a copy of what was kept and whether anything was cut.
func (c *capBuf) snapshot() ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf.Bytes()...), c.truncated
}

// Exec runs the plan. It walks the ordered containment table
// (extrun.ContainmentRungs): the first rung that can be set up holds the
// run, and a rung that fails before the program ran falls through to the
// next, recorded in Containment.Skipped. See the package doc for what each
// OS holds.
func (e *Executor) Exec(ctx context.Context, p extrun.Plan) extrun.ExecFacts {
	facts := extrun.ExecFacts{PeakChildren: -1}
	for _, d := range p.MakeDirs {
		if err := os.MkdirAll(d, 0o700); err != nil {
			facts.StartErr = "create " + d + ": " + err.Error()
			return facts
		}
	}
	// One wall deadline for the whole run, taken before the first rung: a
	// rung that hangs in its ready wait spends the run's own time, so falling
	// through to the next rung can never double the cap.
	start := time.Now()
	deadline := start.Add(p.Limits.Wall)
	tramp := e.trampolineOn()
	cf := e.containmentFacts(p, tramp)
	if msg := childrenBelowTrampoline(cf, tramp, p.Limits.Children); msg != "" {
		facts.StartErr = msg
		return facts
	}
	l, skipped, ok := e.startFirstRung(ctx, p, cf, tramp, start, deadline, &facts)
	if !ok {
		return facts
	}
	e.track(l, true)
	defer e.track(l, false)
	defer l.grp.close()
	if l.setup.cleanup != nil {
		defer l.setup.cleanup()
	}
	facts.Trampoline = l.tramp
	ready, _ := l.status.last(evReady)

	stopMon := make(chan struct{})
	monDone := make(chan struct{})
	peak := -1
	// The /proc walk costs a directory scan per poll, so it runs only when a
	// child cap was asked for. Where a cgroup's pids.max holds the cap the
	// count is only recorded; the kernel refuses the extra task itself.
	carried := ready.Pids == extrun.MechCgroup
	if _, countable := l.grp.count(); countable && p.Limits.Children > 0 {
		go func() {
			defer close(monDone)
			peak = monitorChildren(l.grp, p.Limits.Children, e.pollInterval(), stopMon, func() {
				if !carried {
					l.fire(extrun.KillChildrenCap)
				}
			})
		}()
	} else {
		close(monDone)
	}

	waitCh := make(chan error, 1)
	go func() { waitCh <- l.cmd.Wait() }()
	remaining := time.Until(deadline)
	if remaining <= 0 {
		remaining = time.Nanosecond
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()

	stop := func() {
		if ss, ok := l.grp.(softStopper); ok {
			ss.softStop()
			select {
			case <-waitCh:
				return
			case <-time.After(e.stopGrace()):
			}
		}
		l.grp.kill()
		<-waitCh
	}
	select {
	case <-waitCh:
		// The leader exited on its own: what is still in the group was left
		// behind, and is swept by the kill below.
		if n, ok := l.grp.count(); ok {
			facts.Containment.Swept = n
		}
	case <-ctx.Done():
		facts.KillReason = extrun.KillCanceled
		stop()
	case <-timer.C:
		facts.KillReason = extrun.KillTimeout
		stop()
	case r := <-l.trig:
		facts.KillReason = r
		stop()
	}
	// Nothing the program started outlives the run: the group (or cgroup,
	// or job) is killed after the leader exits as well as at a cap.
	l.grp.kill()
	close(stopMon)
	<-monDone
	facts.PeakChildren = peak

	drained := make(chan struct{})
	go func() { l.readers.Wait(); close(drained) }()
	select {
	case <-drained:
	case <-time.After(e.drainTimeout()):
		// A process outside the group still holds a pipe.
		facts.Leftover = true
		closeAll(l.outR, l.errR)
		select {
		case <-drained:
		case <-time.After(e.drainTimeout()):
		}
	}
	closeAll(l.outR, l.errR)

	select {
	case <-l.status.done:
	case <-time.After(e.drainTimeout()):
	}
	ready, _ = l.status.last(evReady)
	facts.Applied = appliedCaps(p.Limits, ready, l.tramp)
	if fail := l.status.failure(); fail != "" && facts.KillReason == extrun.KillNone {
		facts.StartErr = fail
	}

	facts.Duration = time.Since(start)
	facts.Stdout, facts.StdoutTruncated = l.stdout.snapshot()
	facts.Stderr, facts.StderrTruncated = l.stderr.snapshot()
	if ps := l.cmd.ProcessState; ps != nil {
		facts.ExitCode = ps.ExitCode()
		facts.Signal, facts.Signaled = signalOf(ps)
	}
	cont := l.setup.cont
	cont.Rung = l.rung
	cont.Skipped = skipped
	cont.Swept = facts.Containment.Swept
	if ex, ok := l.status.last(evExit); ok {
		// The supervisor reports the program's own exit, and what it swept.
		facts.ExitCode = ex.Code
		facts.Signal, facts.Signaled = ex.Signal, ex.Signal != ""
		cont.Swept += ex.Swept
		// Only the supervisor sends an exit message.
		cont.Supervised = true
	}
	// Survivors are counted only once the group has emptied: a member the
	// cgroup kill is still taking down is not a survivor (P-018 item f).
	if st, ok := l.grp.(settler); ok {
		st.settle()
	}
	cont.Survivors = e.survivors(l)
	facts.Containment = cont
	return facts
}

// startFirstRung walks the ordered containment table and starts the run on
// the first rung that can be set up. ok is false when the run ended before
// its program was reached (facts then says why).
func (e *Executor) startFirstRung(ctx context.Context, p extrun.Plan, cf extrun.ContainmentFacts, tramp bool, start, deadline time.Time, facts *extrun.ExecFacts) (*launch, []extrun.RungSkip, bool) {
	var skipped []extrun.RungSkip
	end := func(rung extrun.Rung, reason extrun.KillReason) (*launch, []extrun.RungSkip, bool) {
		facts.KillReason = reason
		facts.Duration = time.Since(start)
		facts.Containment = extrun.Containment{Rung: rung, Skipped: skipped}
		return nil, skipped, false
	}
	for _, rung := range extrun.ContainmentRungs(cf) {
		if r := endedBeforeStart(ctx, deadline); r != extrun.KillNone {
			return end("", r)
		}
		l, err := e.start(ctx, p, rung, tramp, deadline)
		if err == nil {
			return l, skipped, true
		}
		var re rungError
		if errors.As(err, &re) {
			skipped = append(skipped, extrun.RungSkip{Rung: rung, Reason: re.reason})
			continue
		}
		var ab startAbort
		if errors.As(err, &ab) {
			return end(rung, ab.reason)
		}
		facts.StartErr = err.Error()
		facts.Containment = extrun.Containment{Rung: rung, Skipped: skipped}
		return nil, skipped, false
	}
	facts.StartErr = "no containment rung could be set up"
	facts.Containment = extrun.Containment{Skipped: skipped}
	return nil, skipped, false
}

// trampolineOn reports whether runs go through the trampoline.
func (e *Executor) trampolineOn() bool {
	return trampolineSupported && TrampolineInstalled() && !e.NoTrampoline
}

// track adds or removes a live run, so the survivor scan of one run never
// counts a process that belongs to another live run of the same program.
func (e *Executor) track(l *launch, on bool) {
	e.activeMu.Lock()
	defer e.activeMu.Unlock()
	if on {
		if e.active == nil {
			e.active = map[*launch]struct{}{}
		}
		e.active[l] = struct{}{}
		return
	}
	delete(e.active, l)
}

// start sets one rung up and starts the run under it. A rungError means the
// program never ran and the next rung may be tried.
func (e *Executor) start(ctx context.Context, p extrun.Plan, rung extrun.Rung, tramp bool, deadline time.Time) (*launch, error) {
	setup, err := e.setupRung(rung, p, tramp)
	if err != nil {
		return nil, rungError{reason: err.Error()}
	}
	l := &launch{
		status:   newStatusLog(),
		stdout:   &capBuf{limit: p.Limits.StdoutBytes},
		stderr:   &capBuf{limit: p.Limits.StderrBytes},
		trig:     make(chan extrun.KillReason, 1),
		tramp:    tramp,
		rung:     rung,
		setup:    setup,
		identity: []string{p.Path, p.Program},
	}
	fail := func(err error, files ...*os.File) (*launch, error) {
		closeAll(files...)
		if setup.cleanup != nil {
			setup.cleanup()
		}
		return nil, err
	}
	var outW, errW *os.File
	if l.outR, outW, err = os.Pipe(); err != nil {
		return fail(fmt.Errorf("stdout pipe: %w", err))
	}
	if l.errR, errW, err = os.Pipe(); err != nil {
		return fail(fmt.Errorf("stderr pipe: %w", err), l.outR, outW)
	}
	var payloadR, payloadW, statusR, statusW *os.File
	if tramp {
		// Behind a launcher (systemd-run) a /proc/self/exe argument would
		// name the launcher itself, so the resolved path is used there.
		self, err := selfPath(len(setup.launcher) > 0)
		if err != nil {
			return fail(rungError{reason: "trampoline: " + err.Error()}, l.outR, outW, l.errR, errW)
		}
		if payloadR, payloadW, err = os.Pipe(); err != nil {
			return fail(fmt.Errorf("trampoline: %w", err), l.outR, outW, l.errR, errW)
		}
		if statusR, statusW, err = os.Pipe(); err != nil {
			return fail(fmt.Errorf("trampoline: %w", err), l.outR, outW, l.errR, errW, payloadR, payloadW)
		}
		argv := append(append([]string{}, setup.launcher...), self, trampolineArg)
		l.cmd = exec.Command(argv[0], argv[1:]...) //nolint:gosec // G204: the binary itself in its trampoline mode, behind a fixed launcher
		l.cmd.Env = append([]string{trampolineEnv + "=1"}, setup.launcherEnv...)
		l.cmd.ExtraFiles = []*os.File{payloadR, statusW}
	} else {
		l.cmd = exec.Command(p.Path, p.Args...) //nolint:gosec // G204: the path is absolute, checked and hashed by extrun.Runner; argv is never a shell string
		// A nil Env would inherit the daemon's environment; an empty one is
		// the point of the runner.
		l.cmd.Env = append([]string{}, p.Env...)
		close(l.status.done)
		close(l.status.readyCh)
	}
	l.cmd.Dir = p.Dir
	if l.cmd.Dir == "" {
		l.cmd.Dir = os.TempDir()
	}
	l.cmd.Stdout = outW
	l.cmd.Stderr = errW
	if p.Stdin != nil {
		l.cmd.Stdin = bytes.NewReader(p.Stdin)
	}
	// Bounds the stdin copy after the program exits.
	l.cmd.WaitDelay = e.drainTimeout()
	prepareCmd(l.cmd)

	l.start = time.Now()
	l.startTicks = bootTicks()
	if err := l.cmd.Start(); err != nil {
		return fail(err, l.outR, outW, l.errR, errW, payloadR, payloadW, statusR, statusW)
	}
	closeAll(outW, errW, payloadR, statusW)
	l.readers.Add(2)
	go func() { defer l.readers.Done(); l.stdout.drain(l.outR, func() { l.fire(extrun.KillOutputCap) }) }()
	go func() { defer l.readers.Done(); l.stderr.drain(l.errR, func() { l.fire(extrun.KillOutputCap) }) }()
	if tramp {
		payload := trampolinePayloadFor(p)
		payload.Mode = setup.mode
		payload.CgroupJoin = setup.cgroupJoin
		payload.NotUnder = setup.notUnder
		go func() {
			_, _ = payloadW.Write(encodePayload(payload))
			_ = payloadW.Close()
		}()
		go func() {
			l.status.read(statusR)
			_ = statusR.Close()
		}()
		// Wait until the trampoline is ready (the program is being exec'd)
		// or gave up. Bounded by the run's one wall deadline and the
		// caller's context.
		wait := time.NewTimer(max(time.Until(deadline), time.Nanosecond))
		select {
		case <-l.status.readyCh:
		case <-ctx.Done():
		case <-wait.C:
		}
		wait.Stop()
		if _, ok := l.status.last(evReady); !ok {
			abortStart(l.cmd)
			drained := make(chan struct{})
			go func() { l.readers.Wait(); close(drained) }()
			select {
			case <-drained:
			case <-time.After(e.drainTimeout()):
			}
			closeAll(l.outR, l.errR)
			reason := l.status.failure()
			if setup.cleanup != nil {
				setup.cleanup()
			}
			if r := endedBeforeStart(ctx, deadline); r != extrun.KillNone && reason == "" {
				return nil, startAbort{reason: r}
			}
			if reason == "" {
				out, _ := l.stderr.snapshot()
				_, said := l.status.last(evStarted)
				switch silentDeath(rung, p.Limits.Children, said, out) {
				case deathCap:
					// The trampoline itself was running and then died
					// without a word inside a cgroup that carries pids.max:
					// dropping to a weaker rung would silently lose the cap
					// (P-018 item e).
					return nil, fmt.Errorf("the trampoline started inside the run's cgroup and died before the program started, under a child-process cap of %d, which may be below what it needs (%s); the run is not retried without the cap", p.Limits.Children, firstLine(out))
				default:
					// The launcher failed on its own (a systemd scope that
					// cannot start writes its reason and exits): the rung
					// was never set up, so the next rung is tried.
					reason = "the launcher exited before the program started: " + firstLine(out)
				}
			}
			return nil, rungError{reason: reason}
		}
	}
	grp, err := e.groupFor(l, p)
	if err != nil {
		abortStart(l.cmd)
		closeAll(l.outR, l.errR)
		if setup.cleanup != nil {
			setup.cleanup()
		}
		return nil, err
	}
	l.grp = grp
	return l, nil
}

// deathKind is what a silent start death (no ready and no error from the
// trampoline) means.
type deathKind int

const (
	// deathRung: the launcher failed before the trampoline ran; the rung
	// was never set up and the next one may hold the run.
	deathRung deathKind = iota
	// deathCap: the trampoline ran inside a capped cgroup and died; a
	// weaker rung would lose the cap, so the run fails.
	deathCap
)

// goRuntimeDeath are stderr prefixes of a Go program that could not create
// a thread at start (the trampoline is the observer binary, a Go program):
// it ran, and died of the task cap before it could say so.
var goRuntimeDeath = []string{
	"runtime: failed to create new OS thread",
	"runtime/cgo: pthread_create failed",
	"fatal error: newosproc",
}

// silentDeath decides a start that ended with no ready and no error. Only
// a trampoline that started (its first status word arrived, or its own Go
// runtime reported a thread it could not create) and then died inside a
// cgroup rung with a child cap is a cap failure. A launcher that exits
// with its own stderr, and every uncapped or non-cgroup start, is a rung
// error: a cap at or above the trampoline floor (trampolineMinTasks) does
// not by itself make a launcher failure a cap failure.
func silentDeath(rung extrun.Rung, children int, started bool, stderr []byte) deathKind {
	if rung != extrun.RungCgroup || children <= 0 {
		return deathRung
	}
	if started {
		return deathCap
	}
	text := string(stderr)
	for _, sig := range goRuntimeDeath {
		if strings.Contains(text, sig) {
			return deathCap
		}
	}
	return deathRung
}

// endedBeforeStart reports whether the run ended before its program was
// reached: the caller cancelled (Canceled) or the wall deadline passed
// (Timeout). KillNone means the start may go on.
func endedBeforeStart(ctx context.Context, deadline time.Time) extrun.KillReason {
	switch {
	case ctx.Err() != nil:
		return extrun.KillCanceled
	case !time.Now().Before(deadline):
		return extrun.KillTimeout
	}
	return extrun.KillNone
}

// trampolineMinTasks is the fewest tasks (processes and threads) a run's
// cgroup must allow for the trampoline to reach execve: it joins the cgroup
// as a running Go program, which already has several threads (5 to 6
// measured on a minimal Go 1.27 binary; the observer binary does more at
// start, so the floor keeps a wide margin). Below it the start fails.
const trampolineMinTasks = 16

// childrenBelowTrampoline returns a refusal sentence when the run would be
// held by a cgroup whose pids.max is below what the trampoline needs, else
// "". Such a cap is never silently dropped by falling to a weaker rung
// (decision log P-018 item e); the caller must raise it.
func childrenBelowTrampoline(cf extrun.ContainmentFacts, tramp bool, children int) string {
	if !tramp || !cf.Cgroup || cf.JobObject || children <= 0 || children >= trampolineMinTasks {
		return ""
	}
	return fmt.Sprintf("the child-process cap of %d tasks is below the %d tasks the trampoline needs to start the program inside the run's cgroup; raise the cap to at least %d", children, trampolineMinTasks, trampolineMinTasks)
}

// firstLine returns the first line of b, trimmed and capped, or a fixed
// phrase when b is empty.
func firstLine(b []byte) string {
	line, _, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
	if len(line) > 200 {
		line = line[:200]
	}
	if line == "" {
		return "no reason given"
	}
	return line
}

// monitorChildren polls the group's process count until stop closes, fires
// over when the count passes limit (when limit > 0), and returns the peak.
func monitorChildren(g procGroup, limit int, every time.Duration, stop <-chan struct{}, over func()) int {
	peak := 0
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if n, ok := g.count(); ok {
			if n > peak {
				peak = n
			}
			// The cap counts the program too (extrun.Limits.Children).
			if limit > 0 && n+1 > limit {
				over()
			}
		}
		select {
		case <-stop:
			return peak
		case <-t.C:
		}
	}
}

// closeAll closes every file, ignoring errors (a second close is harmless)
// and nil entries.
func closeAll(fs ...*os.File) {
	for _, f := range fs {
		if f != nil {
			_ = f.Close()
		}
	}
}

// trampolinePayloadFor builds the exec-mode payload of a plan.
func trampolinePayloadFor(p extrun.Plan) trampolinePayload {
	return trampolinePayload{
		V:           trampolineVersion,
		Mode:        modeExec,
		Path:        p.Path,
		Argv:        append([]string{p.Path}, p.Args...),
		Env:         append([]string{}, p.Env...),
		MemoryBytes: p.Limits.MemoryBytes,
		PidsMax:     int64(p.Limits.Children),
		CPUSeconds:  extrun.CPUSeconds(p.Limits.CPU),
		FileBytes:   p.Limits.FileBytes,
	}
}
