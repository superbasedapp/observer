package hookctx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Path says which caller filled a Context.
type Path string

const (
	// PathHost is the hook process on the developer's machine.
	PathHost Path = "host"
	// PathDaemon is the sandbox capture relay's handler in the daemon.
	PathDaemon Path = "daemon"
)

// File is an open payload-named file: what the hook readers use of
// *os.File (Stat, Read, Seek, Close).
type File interface {
	fs.File
	io.Seeker
}

// Files is the file access a Context reads payload-named paths through. A
// nil member refuses every path with ErrRefused.
type Files struct {
	ReadFile func(path string) ([]byte, error)
	Open     func(path string) (File, error)
	Stat     func(path string) (fs.FileInfo, error)
}

// Source is the process and file I/O a Context reads through. On the host
// path a nil member falls back to the operating system (HostSource); on the
// daemon path every member comes from the run's Channel.
type Source struct {
	// ParentPID returns the id of the process that started the hook.
	ParentPID func() int
	// Ancestors returns the agent process chain above parentPID (the
	// caller's walker; nil reports no ancestry).
	Ancestors func(parentPID int) []int
	// Getenv reads one environment variable.
	Getenv func(key string) string
	// Environ lists the environment as "key=value" pairs (the install
	// gate's source-naming variables).
	Environ func() []string
	// Files reads the paths a payload names.
	Files Files
}

// Channel is what a sandbox run's relay channel supplies on the daemon
// path (sandbox plan section 5.2): the run's launch facts and its declared,
// validated frame fields. The daemon's own process tree, environment and
// filesystem are never consulted.
type Channel struct {
	// RunID is the run identity stamped from the channel, never from the
	// event body.
	RunID string
	// ParentPID and Ancestors are the run's launch facts.
	ParentPID int
	Ancestors []int
	// Env holds the environment variables the frame declared.
	Env map[string]string
	// Files resolves paths only under the run's own roots (workspace,
	// projected state dir), no-follow and size-capped. A nil member
	// refuses every path, which is the safe default until the relay ships.
	Files Files
	// Delivery is the run's workspace delivery launch fact (sandbox plan
	// section 6, M7): DeliveryLive or DeliveryCopy; empty is unknown.
	Delivery string
	// CopyHostPath is, for a copy whose tree the host can see, its host
	// path.
	CopyHostPath string
	// ProjectRoot is the run's project as the host launched it (the run
	// record's attribution), never a path the box reports. The hook's
	// project-scoped state (posture, dirty marker) is keyed on it.
	ProjectRoot string
	// CheckoutRoot is the checkout the run was launched in, as the host
	// launched it (for a live run in a linked git worktree, the worktree,
	// while ProjectRoot is its main repository). Empty is unknown.
	CheckoutRoot string
	// Contains reports whether a path lies under the run's roots once its
	// symlinks are resolved, for readers that walk a tree rather than open
	// one file (a skill scan). nil contains nothing.
	Contains func(path string) bool
}

// The workspace delivery values a Channel carries.
const (
	// DeliveryLive: the agent edits the live tree.
	DeliveryLive = "live"
	// DeliveryCopy: the agent edits a copy (a clone, or a tree inside a
	// box); the security plan reads CopyHostPath for it.
	DeliveryCopy = "copy"
)

// ErrRefused reports a payload-named path the context does not read: on
// the daemon path, any path the channel's confined reader does not serve.
var ErrRefused = fmt.Errorf("hookctx: path not readable in this context: %w", fs.ErrPermission)

// SecuritySource fills Event.Security for a request. On the host path it
// reads the signed posture sidecar and the dirty counter (security plan
// section 4.8); on the daemon path it reads the daemon's in-memory posture.
type SecuritySource func(ctx context.Context, req Request) (Security, error)

// DirtyMarker raises the project's dirty marker before a write-capable or
// shell call proceeds (section 4.8). Host: the dirty/<project_root_hash>
// file. Daemon: the same marker, raised in process before the relay
// replies.
type DirtyMarker func(ctx context.Context, projectRoot string) error

// QuickScanner answers a quick-scan request at a commit or push (section
// 4.8). Host: a request to the daemon over loopback. Daemon: in process.
type QuickScanner func(ctx context.Context, req QuickScanRequest) (QuickScanResult, error)

// Limits caps each provider call. Zero leaves only the caller's context
// deadline (the hook watchdog in production).
type Limits struct {
	Security  time.Duration
	Dirty     time.Duration
	QuickScan time.Duration
	// Install caps the install check, including the install-gate wait
	// for the daemon's online answer (security plan section 8.3).
	Install time.Duration
}

// HostProviders are the extension points of the host path. Every nil
// member does nothing. Security Phase A and Phase C fill them.
type HostProviders struct {
	// Sidecar reads the signed posture sidecar, its seen mark and the
	// project's dirty counter into Event.Security.
	Sidecar SecuritySource
	// Dirty raises the dirty marker file.
	Dirty DirtyMarker
	// QuickScan asks the daemon over loopback.
	QuickScan QuickScanner
	// Install checks an install command or manifest edit against the
	// offline index and the online-answer cache, asking the daemon on a
	// miss (security Phase D1).
	Install InstallChecker
	Limits  Limits
}

// DaemonProviders are the extension points of the daemon path. There is
// no sidecar reader on purpose: the daemon path reads no sidecar. Sandbox
// P2 and security Phase C fill them.
type DaemonProviders struct {
	// Memory is the daemon's in-memory posture.
	Memory SecuritySource
	// Dirty raises the dirty marker in the daemon before the relay replies.
	Dirty DirtyMarker
	// QuickScan runs the quick scan in process.
	QuickScan QuickScanner
	// Install checks an install in process (the daemon's own index,
	// cache and online lane).
	Install InstallChecker
	Limits  Limits
}

// Request is what the receiver knows about the event when it asks for its
// context. A zero Request (the start of a hook invocation, before the
// payload is read) fills only the process and file access.
type Request struct {
	Tool        string
	Event       string
	ProjectRoot string
	SessionID   string
	// WriteCapable marks a write-capable or shell tool call: the dirty
	// marker is raised before it proceeds.
	WriteCapable bool
	// QuickScan is set at a git_commit or git_push sink.
	QuickScan *QuickScanRequest
}

// Step names one row of the fill table.
type Step string

const (
	// StepSecurity fills Event.Security.
	StepSecurity Step = "security"
	// StepQuickScan runs the quick-scan request.
	StepQuickScan Step = "quick_scan"
	// StepDirty raises the dirty marker.
	StepDirty Step = "dirty"
	// StepInstall checks an install (CheckInstall; not part of Fill).
	StepInstall Step = "install"
)

// Issue records a provider that failed, panicked or overran its limit.
// The fact it would have filled is set to its honest unknown value.
type Issue struct {
	Step Step
	Err  error
}

// Context is one hook event's filled context. It is owned by one
// invocation (the hook process, or one relayed event in the daemon) and is
// not safe for concurrent Fill calls.
type Context struct {
	path Path
	src  Source
	prov providers
	// delivery and copyHostPath are the run's workspace delivery (daemon
	// path only; the host path has no run).
	delivery, copyHostPath string
	// projectRoot and contains are the run's attribution and its roots
	// check (daemon path only).
	projectRoot string
	// checkoutRoot is the run's launched checkout (Channel.CheckoutRoot).
	checkoutRoot string
	contains     func(path string) bool

	// Security is Event.Security; nil when no provider filled it.
	Security *Security
	// QuickScan is the quick-scan answer; nil when none was requested or
	// no provider is wired.
	QuickScan *QuickScanResult
	// DirtyRaised reports that the dirty marker was raised.
	DirtyRaised bool
	// Issues lists the providers that failed during the last Fill.
	Issues []Issue
}

// providers is the path-neutral form both entry points reduce to, so the
// one Fill serves both.
type providers struct {
	security  SecuritySource
	dirty     DirtyMarker
	quickScan QuickScanner
	install   InstallChecker
	limits    Limits
}

// Host is the host-path entry point: the hook process fills req's context
// from src (nil members fall back to HostSource) and p.
func Host(ctx context.Context, req Request, src Source, p HostProviders) *Context {
	def := HostSource()
	if src.ParentPID == nil {
		src.ParentPID = def.ParentPID
	}
	if src.Getenv == nil {
		src.Getenv = def.Getenv
	}
	if src.Environ == nil {
		src.Environ = def.Environ
	}
	if src.Files.ReadFile == nil {
		src.Files.ReadFile = def.Files.ReadFile
	}
	if src.Files.Open == nil {
		src.Files.Open = def.Files.Open
	}
	if src.Files.Stat == nil {
		src.Files.Stat = def.Files.Stat
	}
	c := &Context{path: PathHost, src: src, prov: providers{
		security: p.Sidecar, dirty: p.Dirty, quickScan: p.QuickScan, install: p.Install, limits: p.Limits,
	}}
	c.Fill(ctx, req)
	return c
}

// Daemon is the daemon-path entry point: the relay handler fills req's
// context from the run's channel and p. Nothing here reads the daemon's
// own process, environment or filesystem.
func Daemon(ctx context.Context, req Request, ch Channel, p DaemonProviders) *Context {
	c := &Context{path: PathDaemon, src: channelSource(ch), prov: providers{
		security: p.Memory, dirty: p.Dirty, quickScan: p.QuickScan, install: p.Install, limits: p.Limits,
	}, delivery: ch.Delivery, copyHostPath: ch.CopyHostPath, projectRoot: ch.ProjectRoot, checkoutRoot: ch.CheckoutRoot, contains: ch.Contains}
	c.Fill(ctx, req)
	return c
}

// channelSource turns a Channel into a Source.
func channelSource(ch Channel) Source {
	env := make(map[string]string, len(ch.Env))
	for k, v := range ch.Env {
		env[k] = v
	}
	pairs := make([]string, 0, len(env))
	for k, v := range env {
		pairs = append(pairs, k+"="+v)
	}
	sort.Strings(pairs)
	anc := append([]int(nil), ch.Ancestors...)
	ppid := ch.ParentPID
	return Source{
		ParentPID: func() int { return ppid },
		Ancestors: func(parentPID int) []int {
			if parentPID != ppid || len(anc) == 0 {
				return nil
			}
			return append([]int(nil), anc...)
		},
		Getenv:  func(key string) string { return env[key] },
		Environ: func() []string { return append([]string(nil), pairs...) },
		Files:   ch.Files,
	}
}

// fillStep is one row of the fill table: when it applies and what it
// does. Rows run top to bottom; a row that does not apply costs nothing.
type fillStep struct {
	step    Step
	applies func(req Request, p providers) bool
	run     func(ctx context.Context, c *Context, req Request)
}

// fillSteps is the fill order. The posture is read first, the quick scan
// (a commit or push) is answered against that state, and the dirty marker
// for this call's own activity is raised last, still before the hook (or
// the relay) replies.
var fillSteps = []fillStep{
	{
		step:    StepSecurity,
		applies: func(_ Request, p providers) bool { return p.security != nil },
		run: func(ctx context.Context, c *Context, req Request) {
			sec, err := call(ctx, c.prov.limits.Security, func(ctx context.Context) (Security, error) {
				return c.prov.security(ctx, req)
			})
			if err != nil {
				c.issue(StepSecurity, err)
				sec = Security{Posture: PostureUnknown}
			}
			c.Security = &sec
		},
	},
	{
		step:    StepQuickScan,
		applies: func(req Request, p providers) bool { return req.QuickScan != nil && p.quickScan != nil },
		run: func(ctx context.Context, c *Context, req Request) {
			if only := req.QuickScan.OnlyWhen; only != nil && (c.Security == nil || !only(*c.Security)) {
				return
			}
			res, err := call(ctx, c.prov.limits.QuickScan, func(ctx context.Context) (QuickScanResult, error) {
				return c.prov.quickScan(ctx, *req.QuickScan)
			})
			if err != nil {
				c.issue(StepQuickScan, err)
				res = QuickScanResult{Verdict: QuickScanUnknown}
			}
			c.QuickScan = &res
		},
	},
	{
		step:    StepDirty,
		applies: func(req Request, p providers) bool { return req.WriteCapable && p.dirty != nil },
		run: func(ctx context.Context, c *Context, req Request) {
			_, err := call(ctx, c.prov.limits.Dirty, func(ctx context.Context) (struct{}, error) {
				return struct{}{}, c.prov.dirty(ctx, req.ProjectRoot)
			})
			if err != nil {
				c.issue(StepDirty, err)
				return
			}
			c.DirtyRaised = true
		},
	},
}

// Fill fills the event-dependent context for req: Event.Security, the
// quick scan and the dirty marker, in fillSteps order, replacing what an
// earlier Fill set. A receiver that learns more about the event (its
// project root, its action) calls Fill again. A provider never blocks the
// hook: an error, a panic or an overrun is an Issue, and the fact is left
// at its unknown value.
func (c *Context) Fill(ctx context.Context, req Request) {
	if ctx == nil {
		ctx = context.Background()
	}
	c.Security, c.QuickScan, c.DirtyRaised, c.Issues = nil, nil, false, nil
	for _, s := range fillSteps {
		if s.applies(req, c.prov) {
			s.run(ctx, c, req)
		}
	}
}

// CheckInstall runs the install check for one event into c.Security,
// after Fill (the caller decides that the install gate applies: the
// security.deps pack is in the posture's active pack set). It is not a
// Fill step because only an install command or a manifest edit needs it.
// A nil provider does nothing; a failure, panic or overrun records an
// Issue and one synthetic unknown check, never a clean answer (PR14).
func (c *Context) CheckInstall(ctx context.Context, req InstallRequest) {
	if c.prov.install == nil || req.Event == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	res, err := call(ctx, c.prov.limits.Install, func(ctx context.Context) (InstallResult, error) {
		return c.prov.install(WithContext(ctx, c), req)
	})
	if c.Security == nil {
		c.Security = &Security{Posture: PostureUnknown}
	}
	if err != nil {
		c.issue(StepInstall, err)
		res = InstallResult{Checks: []policy.InstallCheck{{Verdict: policy.InstallUnknownName, Source: policy.InstallSourceNone, Reason: InstallCheckFailed}}}
	}
	if len(res.Checks) > policy.InstallChecksMax {
		res.Checks = res.Checks[:policy.InstallChecksMax]
	}
	c.Security.Installs = res.Checks
	c.Security.InstallCustomRegistry = res.CustomRegistry
	c.Security.InstallManifest = res.Manifest
	c.Security.Install, c.Security.InstallSource = policy.InstallNotChecked, policy.InstallSourceNone
	for _, ch := range res.Checks {
		if policy.InstallVerdictRank(ch.Verdict) > policy.InstallVerdictRank(c.Security.Install) {
			c.Security.Install, c.Security.InstallSource = ch.Verdict, ch.Source
		}
	}
}

func (c *Context) issue(s Step, err error) { c.Issues = append(c.Issues, Issue{Step: s, Err: err}) }

// call runs one provider under limit and the caller's context. The
// provider runs on its own goroutine so a provider that ignores its
// context still cannot hold the hook past the deadline; the buffered
// channel lets that goroutine finish and exit on its own. A panic is an
// error.
func call[T any](ctx context.Context, limit time.Duration, fn func(context.Context) (T, error)) (T, error) {
	if limit > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, limit)
		defer cancel()
	}
	type result struct {
		v   T
		err error
	}
	ch := make(chan result, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- result{err: fmt.Errorf("hookctx: provider panic: %v", r)}
			}
		}()
		v, err := fn(ctx)
		ch <- result{v: v, err: err}
	}()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-ctx.Done():
		var zero T
		return zero, fmt.Errorf("hookctx: provider: %w", ctx.Err())
	}
}

// Path reports which entry point filled the context.
func (c *Context) Path() Path { return c.path }

// WorkspaceDelivery returns the run's workspace delivery and, for a copy the
// host can see, its host path. The host path reports ("", "").
func (c *Context) WorkspaceDelivery() (delivery, copyHostPath string) {
	return c.delivery, c.copyHostPath
}

// RunProjectRoot returns the run's project root on the daemon path (the
// host's launch fact), "" on the host path, where the event's own working
// directory decides.
func (c *Context) RunProjectRoot() string {
	if c.path != PathDaemon {
		return ""
	}
	return c.projectRoot
}

// RunCheckoutRoot returns the checkout the run was launched in on the
// daemon path (the host's launch fact, Channel.CheckoutRoot), "" on the
// host path.
func (c *Context) RunCheckoutRoot() string {
	if c.path != PathDaemon {
		return ""
	}
	return c.checkoutRoot
}

// Contains reports whether a tree reader may walk path: always on the host
// path; on the daemon path only under the run's roots (symlinks resolved),
// and never when the channel supplied no check.
func (c *Context) Contains(path string) bool {
	if c.path != PathDaemon {
		return true
	}
	return c.contains != nil && c.contains(path)
}

// ParentPID returns the id of the process that started the hook: the
// operating system's answer on the host path, the run's launch fact on the
// daemon path. It is read at each call, as the hook did before the seam.
func (c *Context) ParentPID() int {
	if c.src.ParentPID == nil {
		return 0
	}
	return c.src.ParentPID()
}

// Ancestors returns the agent process chain above parentPID, or nil when
// the context has no ancestry source.
func (c *Context) Ancestors(parentPID int) []int {
	if c.src.Ancestors == nil {
		return nil
	}
	return c.src.Ancestors(parentPID)
}

// Getenv reads one environment variable: the hook process's own on the
// host path, the frame's declared fields on the daemon path.
func (c *Context) Getenv(key string) string {
	if c.src.Getenv == nil {
		return ""
	}
	return c.src.Getenv(key)
}

// Environ lists the environment as "key=value" pairs: the hook process's
// own on the host path, only the frame's declared fields (sorted) on the
// daemon path.
func (c *Context) Environ() []string {
	if c.src.Environ == nil {
		return nil
	}
	return c.src.Environ()
}

// ReadFile reads a payload-named path.
func (c *Context) ReadFile(path string) ([]byte, error) {
	if c.src.Files.ReadFile == nil {
		return nil, refused(path)
	}
	return c.src.Files.ReadFile(path)
}

// Open opens a payload-named path.
func (c *Context) Open(path string) (File, error) {
	if c.src.Files.Open == nil {
		return nil, refused(path)
	}
	return c.src.Files.Open(path)
}

// Stat stats a payload-named path.
func (c *Context) Stat(path string) (fs.FileInfo, error) {
	if c.src.Files.Stat == nil {
		return nil, refused(path)
	}
	return c.src.Files.Stat(path)
}

func refused(path string) error {
	return &fs.PathError{Op: "read", Path: path, Err: ErrRefused}
}

// IsRefused reports whether err is a path the context refused.
func IsRefused(err error) bool { return errors.Is(err, ErrRefused) }
