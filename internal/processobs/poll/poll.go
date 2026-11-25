package poll

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/processobs"
)

// ErrUnsupported is returned by the platform enumerate on an OS that has no
// poll implementation yet. Backend.Start surfaces it so the Observer reports
// degraded health and the daemon continues (fail-open).
var ErrUnsupported = errors.New("processobs/poll: process enumeration not supported on this OS")

// ProcInfo is one process at a snapshot instant — the result of a platform
// enumerate. StartTicks is a per-process creation time (Linux: jiffies since
// boot from /proc/<pid>/stat; other OSes: their native monotonic stamp);
// combined with BootID it yields the PID-reuse-proof ProcessKey.
type ProcInfo struct {
	PID        int
	PPID       int
	StartTicks int64
	HasStart   bool
	ExePath    string
	Argv       []string
	// CWD is the process working directory (Linux: /proc/<pid>/cwd; Windows:
	// the PEB read). Empty when unreadable. Cross-OS attribution (§5.5) matches
	// it against a session's project_root, so it is captured as a real path.
	CWD string
	// SessionToken is an allowlisted session-id env var value recovered from the
	// process environment (§5.5 P-B6 env-token; Windows only — "" elsewhere).
	// Read ONLY for new processes (the diff's added set + the initial snapshot),
	// never the whole table every poll, to bound the added per-poll cost.
	SessionToken string
	UID          int
	GID          int
	EUID         int
	EGID         int

	// Security / isolation posture (P4), best-effort from /proc.
	SeccompMode     string
	CapabilitiesEff string
	AppArmorLabel   string
	SELinuxLabel    string
	CgroupPath      string
	ContainerID     string
	PIDNamespace    string
	MountNamespace  string
	NetNamespace    string

	// Resource metrics (best-effort; Windows poll capturer). HasMetrics gates
	// whether they were read (so a zero is "unread" vs "genuinely zero").
	HasMetrics      bool
	CPUUserMs       int64
	CPUSystemMs     int64
	MaxRSSBytes     int64
	WorkingSetBytes int64
	ReadBytes       int64
	WriteBytes      int64
	ReadOps         int64
	WriteOps        int64
	ThreadCount     int32
	HandleCount     int32
}

// EnumerateFunc returns the current process table. Injected via Options so
// the diff core is testable with canned snapshots.
type EnumerateFunc func() ([]ProcInfo, error)

// Options configure a poll Backend.
type Options struct {
	// Interval between snapshots. Default 2s.
	Interval time.Duration
	// Enumerate returns the process table. Default: the platform enumerate.
	Enumerate EnumerateFunc
	// BootID stamps every event's ProcessKey input. Default: the platform
	// boot id (Linux: /proc/sys/kernel/random/boot_id).
	BootID string
	// Now overrides time.Now for tests.
	Now func() time.Time
	// NetworkBytes optionally supplies per-process CUMULATIVE socket byte
	// counters, so the metric samples this backend produces carry a network
	// series alongside CPU/RSS/disk. The poll backend cannot measure bytes
	// itself (/proc has no per-process socket byte counter); the daemon injects
	// the Linux eBPF backend's counters here when that backend is composed
	// alongside — a capability seam (processobs.NetworkSampler), not a
	// backend-name branch. nil = no network series (samples carry
	// HasNetworkMetrics=false, i.e. UNMEASURED, never a fabricated zero).
	NetworkBytes processobs.NetworkBytesFunc
}

// Backend implements processobs.Backend by polling the process table.
type Backend struct {
	interval  time.Duration
	enumerate EnumerateFunc
	bootID    string
	now       func() time.Time
	netBytes  processobs.NetworkBytesFunc

	out      chan processobs.RawEvent
	stop     chan struct{}
	stopOnce sync.Once

	// tokened tracks live processes that carry a session-id env token (the EV
	// AI subtree). It is ONE of the two metrics-refresh signals: refreshSet
	// unions it with distinctive AI-tool-launcher subtrees (recomputed per poll)
	// so medium-attributed, non-token AI subtrees also get live metrics, while
	// per-poll volume stays bounded to AI subtrees rather than the whole table.
	// Single-goroutine (the poll loop).
	tokened map[procKey]bool
}

// New builds a poll Backend, applying defaults.
func New(opts Options) *Backend {
	if opts.Interval <= 0 {
		opts.Interval = 2 * time.Second
	}
	if opts.Enumerate == nil {
		opts.Enumerate = platformEnumerate
	}
	if opts.BootID == "" {
		opts.BootID = platformBootID()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Backend{
		interval:  opts.Interval,
		enumerate: opts.Enumerate,
		bootID:    opts.BootID,
		now:       opts.Now,
		netBytes:  opts.NetworkBytes,
		stop:      make(chan struct{}),
		tokened:   make(map[procKey]bool),
	}
}

// Name implements processobs.Backend.
func (b *Backend) Name() string { return "poll" }

// BootID returns the per-boot identifier stamped on every event's ProcessKey
// (§9.3). The cross-OS bridge capturer reports it in its hello frame.
func (b *Backend) BootID() string { return b.bootID }

// Start probes the process table once (so an unsupported OS or a permission
// failure surfaces as a Start error → degraded health, fail-open), then
// streams synthesized events on the returned channel until ctx is cancelled
// or Close is called.
func (b *Backend) Start(ctx context.Context) (<-chan processobs.RawEvent, error) {
	first, err := b.enumerate()
	if err != nil {
		return nil, err
	}
	b.out = make(chan processobs.RawEvent, 1024)
	go b.loop(ctx, first)
	return b.out, nil
}

// Close stops the poll loop. Idempotent and safe to call after a Start error.
func (b *Backend) Close() error {
	b.stopOnce.Do(func() { close(b.stop) })
	return nil
}

// procKey identifies a process within the diff by (pid, start) so PID reuse
// is a distinct key — an old (pid, startA) vanishing and a new (pid, startB)
// appearing are seen as a clean exit + fork/exec, never a survivor.
type procKey struct {
	pid   int
	start int64
}

func (b *Backend) loop(ctx context.Context, first []ProcInfo) {
	defer close(b.out)

	// Initial snapshot: emit exec-only for every existing process (no fork —
	// they predate our observation). Parents are sorted first so the
	// Attributor's livePID is populated before a child's exec resolves its
	// parent. This lets an already-running AI-tool root get attributed.
	prev := index(first)
	for _, ev := range b.initialEvents(first) {
		if !b.send(ctx, ev) {
			return
		}
	}

	ticker := time.NewTicker(b.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-b.stop:
			return
		case <-ticker.C:
			cur, err := b.enumerate()
			if err != nil {
				continue // transient enumerate failure; retry next tick
			}
			curIdx := index(cur)
			for _, ev := range b.diff(prev, curIdx) {
				if !b.send(ctx, ev) {
					return
				}
			}
			prev = curIdx
		}
	}
}

// initialEvents returns one exec event per process in the first snapshot,
// parents before children (by start time).
func (b *Backend) initialEvents(first []ProcInfo) []processobs.RawEvent {
	sorted := append([]ProcInfo(nil), first...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].StartTicks < sorted[j].StartTicks })
	now := b.now()
	out := make([]processobs.RawEvent, 0, len(sorted))
	for i := range sorted {
		sorted[i].SessionToken = platformSessionToken(sorted[i].PID) // §5.5 P-B6: new-process env-token read (one-time initial snapshot)
		if sorted[i].SessionToken != "" {
			b.tokened[procKey{pid: sorted[i].PID, start: sorted[i].StartTicks}] = true
		}
		out = append(out, b.execEvent(&sorted[i], now))
	}
	return out
}

// diff synthesizes events from two snapshots keyed by (pid, start):
// fork+exec for newly-appeared processes (parents first), exit for vanished
// ones. Pure — the whole interesting part of the backend, fully unit-tested.
func (b *Backend) diff(prev, cur map[procKey]ProcInfo) []processobs.RawEvent {
	now := b.now()

	var added []ProcInfo
	for k, p := range cur {
		if _, ok := prev[k]; !ok {
			added = append(added, p)
		}
	}
	sort.SliceStable(added, func(i, j int) bool { return added[i].StartTicks < added[j].StartTicks })

	out := make([]processobs.RawEvent, 0, len(added)*2)
	for i := range added {
		added[i].SessionToken = platformSessionToken(added[i].PID) // §5.5 P-B6: new-process env-token read (bounded to the diff's added set)
		if added[i].SessionToken != "" {
			b.tokened[procKey{pid: added[i].PID, start: added[i].StartTicks}] = true
		}
		out = append(out, b.forkEvent(&added[i], now), b.execEvent(&added[i], now))
	}

	// Survivors in an attributed-AI subtree get a metrics-refresh event so the
	// dashboard shows LIVE resource usage. The eligible set (token-bearing EV
	// procs ∪ distinctive AI-launcher subtrees) keeps per-poll volume bounded to
	// AI subtrees, not the whole table — item 3 generalized this beyond tokened
	// so medium-attributed (codex/cursor/…) and native-Linux AI subtrees refresh
	// too, not just exec-time.
	elig := b.refreshSet(cur)
	for k, p := range cur {
		if _, ok := prev[k]; ok && elig[k] {
			p := p
			out = append(out, b.metricsEvent(&p, now))
		}
	}

	for k, p := range prev {
		if _, ok := cur[k]; !ok {
			p := p
			out = append(out, b.exitEvent(&p, now))
			delete(b.tokened, k)
		}
	}
	return out
}

// refreshSet computes which live processes get a metrics-refresh event this
// poll. A process is eligible if it carries a session token (EV — populated for
// new processes in b.tokened) OR it sits in a subtree rooted at a distinctive
// AI-tool launcher (processobs.IsAIToolLauncher). The launcher signal is
// recomputed from the current snapshot each poll (basename, then parent lineage)
// so medium-attributed, non-token AI subtrees — codex/cursor/… on the cross-OS
// bridge, and native-Linux AI sessions where no env token exists — get live
// metrics too, while the set stays bounded to AI subtrees rather than the whole
// process table (item 3). Pure over the snapshot; no I/O.
func (b *Backend) refreshSet(cur map[procKey]ProcInfo) map[procKey]bool {
	byPID := make(map[int]procKey, len(cur))
	procs := make([]ProcInfo, 0, len(cur))
	for _, p := range cur {
		byPID[p.PID] = procKey{pid: p.PID, start: p.StartTicks}
		procs = append(procs, p)
	}
	// A parent starts before its children, so visiting in ascending start order
	// decides a parent's eligibility before any child's — so it can propagate.
	sort.SliceStable(procs, func(i, j int) bool { return procs[i].StartTicks < procs[j].StartTicks })

	elig := make(map[procKey]bool, len(b.tokened))
	for i := range procs {
		k := procKey{pid: procs[i].PID, start: procs[i].StartTicks}
		switch {
		case b.tokened[k]:
			elig[k] = true
		case processobs.IsAIToolLauncher(procs[i].ExePath):
			elig[k] = true
		default:
			if pk, ok := byPID[procs[i].PPID]; ok && elig[pk] {
				elig[k] = true
			}
		}
	}
	return elig
}

func (b *Backend) forkEvent(p *ProcInfo, ts time.Time) processobs.RawEvent {
	return processobs.RawEvent{
		Type: processobs.EventFork, Timestamp: ts, BootID: b.bootID,
		PID: p.PID, PPID: p.PPID, StartTimeTicks: p.StartTicks, HasStartTime: p.HasStart,
	}
}

func (b *Backend) execEvent(p *ProcInfo, ts time.Time) processobs.RawEvent {
	ev := b.execEventBase(p, ts)
	b.applyNetworkBytes(&ev, p.PID)
	return ev
}

func (b *Backend) execEventBase(p *ProcInfo, ts time.Time) processobs.RawEvent {
	return processobs.RawEvent{
		Type: processobs.EventExec, Timestamp: ts, BootID: b.bootID,
		PID: p.PID, PPID: p.PPID, StartTimeTicks: p.StartTicks, HasStartTime: p.HasStart,
		ExePath: p.ExePath, Argv: p.Argv, CWD: p.CWD, SessionToken: p.SessionToken,
		UID: p.UID, GID: p.GID, EUID: p.EUID, EGID: p.EGID,
		SeccompMode: p.SeccompMode, CapabilitiesEff: p.CapabilitiesEff,
		AppArmorLabel: p.AppArmorLabel, SELinuxLabel: p.SELinuxLabel,
		CgroupPath: p.CgroupPath, ContainerID: p.ContainerID,
		PIDNamespace: p.PIDNamespace, MountNamespace: p.MountNamespace, NetNamespace: p.NetNamespace,
		HasMetrics: p.HasMetrics,
		CPUUserMs:  p.CPUUserMs, CPUSystemMs: p.CPUSystemMs,
		MaxRSSBytes: p.MaxRSSBytes, WorkingSetBytes: p.WorkingSetBytes,
		ReadBytes: p.ReadBytes, WriteBytes: p.WriteBytes, ReadOps: p.ReadOps, WriteOps: p.WriteOps,
		ThreadCount: p.ThreadCount, HandleCount: p.HandleCount,
	}
}

// applyNetworkBytes stamps the injected per-process socket counters onto a
// metrics-bearing event. It is the ONLY place the network series enters the
// poll backend's event stream. When no sampler is injected, or the sampler
// reports accounting is not live, HasNetworkMetrics stays false and the sample
// is recorded as UNMEASURED — a chart must then omit the series rather than
// draw a zero line.
func (b *Backend) applyNetworkBytes(ev *processobs.RawEvent, pid int) {
	if b.netBytes == nil {
		return
	}
	in, out, ok := b.netBytes(pid)
	if !ok {
		return
	}
	ev.NetworkBytesIn, ev.NetworkBytesOut, ev.HasNetworkMetrics = in, out, true
}

// metricsEvent is the lightweight resource-refresh for a still-live process: it
// carries identity + the current metric counters only (§dashboard-enhancements
// EventMetrics) so the Attributor updates the run without re-attribution.
func (b *Backend) metricsEvent(p *ProcInfo, ts time.Time) processobs.RawEvent {
	ev := b.metricsEventBase(p, ts)
	b.applyNetworkBytes(&ev, p.PID)
	return ev
}

func (b *Backend) metricsEventBase(p *ProcInfo, ts time.Time) processobs.RawEvent {
	return processobs.RawEvent{
		Type: processobs.EventMetrics, Timestamp: ts, BootID: b.bootID,
		PID: p.PID, StartTimeTicks: p.StartTicks, HasStartTime: p.HasStart,
		HasMetrics: p.HasMetrics,
		CPUUserMs:  p.CPUUserMs, CPUSystemMs: p.CPUSystemMs,
		MaxRSSBytes: p.MaxRSSBytes, WorkingSetBytes: p.WorkingSetBytes,
		ReadBytes: p.ReadBytes, WriteBytes: p.WriteBytes, ReadOps: p.ReadOps, WriteOps: p.WriteOps,
		ThreadCount: p.ThreadCount, HandleCount: p.HandleCount,
	}
}

func (b *Backend) exitEvent(p *ProcInfo, ts time.Time) processobs.RawEvent {
	ev := b.exitEventBase(p, ts)
	// The pid is gone by now, so this reads whatever the counters reached
	// before the probes' exit cleanup removed the entry — best-effort, and
	// unmeasured (rather than zero) once the entry is gone.
	b.applyNetworkBytes(&ev, p.PID)
	return ev
}

func (b *Backend) exitEventBase(p *ProcInfo, ts time.Time) processobs.RawEvent {
	return processobs.RawEvent{
		Type: processobs.EventExit, Timestamp: ts, BootID: b.bootID,
		PID: p.PID, StartTimeTicks: p.StartTicks, HasStartTime: p.HasStart,
		// The last-seen metrics (from the prior snapshot) become the exited
		// process's final counters — the process is gone by the time we notice.
		HasMetrics: p.HasMetrics,
		CPUUserMs:  p.CPUUserMs, CPUSystemMs: p.CPUSystemMs,
		MaxRSSBytes: p.MaxRSSBytes, WorkingSetBytes: p.WorkingSetBytes,
		ReadBytes: p.ReadBytes, WriteBytes: p.WriteBytes, ReadOps: p.ReadOps, WriteOps: p.WriteOps,
		ThreadCount: p.ThreadCount, HandleCount: p.HandleCount,
	}
}

// send delivers an event unless ctx/stop fires first; returns false to stop.
func (b *Backend) send(ctx context.Context, ev processobs.RawEvent) bool {
	select {
	case <-ctx.Done():
		return false
	case <-b.stop:
		return false
	case b.out <- ev:
		return true
	}
}

// index keys a snapshot by (pid, start). A process with no readable start
// time falls back to a pid-only key (start 0) — it can still be tracked for
// the tree, though it cannot be persisted as attributed (§9.3).
func index(procs []ProcInfo) map[procKey]ProcInfo {
	m := make(map[procKey]ProcInfo, len(procs))
	for _, p := range procs {
		m[procKey{pid: p.PID, start: p.StartTicks}] = p
	}
	return m
}
