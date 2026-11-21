package processobs

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/procmodel"
)

// SeedLookup resolves a pid to its session seed. The bridged pid is the
// AI-tool ROOT process (spec §9.1.1); a clean miss returns ok=false. It
// must be cheap and side-effect free from this package's view.
type SeedLookup func(pid int) (Seed, bool)

// TokenLookup resolves a session-id env token (a value the capturer recovered
// from SessionTokenEnvKeys) to its session seed — the §5.5 P-B6 env-token (EV)
// path. A hit means a session with that id exists; the seed carries its
// tool/project so the attribution is complete. Unlike SeedLookup it is keyed
// on the session id directly, so it is namespace-independent — it resolves a
// Windows-captured process to a WSL session without any pid plumbing. A clean
// miss returns ok=false. The caller injects it (the store's SessionSeedByID);
// this package never imports internal/store.
type TokenLookup func(token string) (Seed, bool)

// Change is what Observe did to the tracked tree, telling the Observer
// whether (and how) to persist.
type Change int

const (
	// ChangeNone: tree bookkeeping only, nothing to persist (e.g. a fork
	// before exec, or an event for an unknown process).
	ChangeNone Change = iota
	// ChangeCreated: a process reached exec — persist it (initial upsert).
	ChangeCreated
	// ChangeUpdated: a tracked process exited — persist the update.
	ChangeUpdated
)

// DefaultBoundaryBasenames are the executable basenames treated as
// attribution boundaries (spec §9.2.6): attribution never flows through
// them. pid 1 is always a boundary regardless of name. Table-driven so the
// set is data, not a conditional ladder (CLAUDE.md rule 5).
var DefaultBoundaryBasenames = map[string]bool{
	"init":         true, // sysv / WSL2 /init (also pid 1)
	"systemd":      true,
	"systemd-init": true,
	"wsl":          true, // wsl.exe relay
	"wslhost":      true,
	"wslrelay":     true,
	"wslservice":   true,
	"relay":        true,
	"login":        true,
	"sshd":         true,
}

// Attributor maintains the in-memory process tree and resolves the §9.2
// attribution rules. It is pure: the only external knowledge it consults
// is the injected SeedLookup. Not safe for concurrent use — the Observer
// drives it from a single goroutine.
type Attributor struct {
	seed       SeedLookup
	tokenSeed  TokenLookup
	scrub      *FieldScrubber
	boundaries map[string]bool

	runs    map[string]*ProcessRun // processKey -> tracked run
	livePID map[int]string         // pid -> current processKey occupying it

	// metricRing governs the live-chart ring buffer (sample cadence, retained
	// window, persist cadence). Zero value = DefaultMetricPolicy; installed by
	// the daemon via SetMetricPolicy.
	metricRing MetricPolicy

	// isService reports whether an executable starts a service (the capture
	// budget's service table, proccapture.Policy.IsService). Nil (the default,
	// and whenever the capture budget is off) disables service marking, so
	// the tree and attribution behave exactly as before.
	isService func(exe string) bool
}

// SetServiceTable installs the capture budget's service table (plan §4.2).
// With it, a run whose executable is a service becomes a service root
// (ProcessRun.ServiceRootKey = its own key), its descendants carry that key,
// and an env-token hit on a descendant no longer counts as a direct identity
// (see resolveAttribution). Nil disables it. Not safe to call concurrently
// with Observe; the daemon sets it once at construction.
func (a *Attributor) SetServiceTable(fn func(exe string) bool) { a.isService = fn }

// serviceRootFromParent returns the service root a child inherits, "" when
// the parent is untracked or not in a service.
func (a *Attributor) serviceRootFromParent(parentKey string) string {
	if a.isService == nil || parentKey == "" {
		return ""
	}
	if p := a.runs[parentKey]; p != nil {
		return p.ServiceRootKey
	}
	return ""
}

// NewAttributor builds an Attributor. seed may be nil (everything is then
// unattributed unless inherited, which also yields none). scrub may be nil
// (a default no-cap, no-redact scrubber is used — not recommended for
// production). boundaries defaults to DefaultBoundaryBasenames when nil.
func NewAttributor(seed SeedLookup, scrub *FieldScrubber, boundaries map[string]bool) *Attributor {
	if scrub == nil {
		scrub = &FieldScrubber{ArgvMode: "preview"}
	}
	if boundaries == nil {
		boundaries = DefaultBoundaryBasenames
	}
	return &Attributor{
		seed:       seed,
		scrub:      scrub,
		boundaries: boundaries,
		runs:       make(map[string]*ProcessRun),
		livePID:    make(map[int]string),
	}
}

// SetTokenLookup installs the §5.5 P-B6 env-token (EV) resolution seam: a
// process whose captured session-token env var resolves to an existing session
// is attributed at HIGH confidence, source AttrEnvToken. nil (the default)
// disables EV — the Attributor then behaves exactly as before, so the existing
// callers are unaffected (CLAUDE.md rule 6: additive, not invasive).
func (a *Attributor) SetTokenLookup(fn TokenLookup) { a.tokenSeed = fn }

// Tracked reports how many live process runs are currently held — used by
// the Observer to cap memory and by tests.
func (a *Attributor) Tracked() int { return len(a.runs) }

// InAISubtree reports whether run is, or descends from, a distinctive AI-tool
// launcher (IsAIToolLauncher) in the live tree. The Observer consults it to
// capture UNATTRIBUTED AI subtrees on a native host — codex/cursor/… that get
// no pid-seed (no pidbridge) and no env-token hit — so the deferred
// CorrelateCrossOS cwd pass can later join them to a session, WITHOUT
// persisting the whole unattributed process table (that volume is the reason
// CaptureUnattributed stays off by default). Bounded by a hop cap so a cyclic
// parent chain can never spin. Pure tree-read; no I/O.
func (a *Attributor) InAISubtree(run *ProcessRun) bool {
	if run == nil {
		return false
	}
	if IsAIToolLauncher(run.ExePath) {
		return true
	}
	const maxHops = 64
	key := run.ParentProcessKey
	for hops := 0; hops < maxHops && key != ""; hops++ {
		p := a.runs[key]
		if p == nil {
			return false
		}
		if IsAIToolLauncher(p.ExePath) {
			return true
		}
		key = p.ParentProcessKey
	}
	return false
}

// RunForEvent returns the currently tracked process run that owns a
// non-lifecycle event such as network_connect. Prefer the stable
// boot/pid/start key when the backend has it; fall back to livePID for event
// sources that only carry pid. Nil means the process was never tracked or was
// already evicted/exited.
func (a *Attributor) RunForEvent(ev RawEvent) *ProcessRun {
	if ev.HasStartTime {
		if run := a.runs[ProcessKey(ev.BootID, ev.PID, ev.StartTimeTicks)]; run != nil {
			return run
		}
	}
	if key := a.livePID[ev.PID]; key != "" {
		return a.runs[key]
	}
	return nil
}

// Observe folds one (already-enriched) RawEvent into the tree and returns
// the affected run plus what changed. env is the process environment for
// posture capture (may be nil); it is only consulted on exec.
func (a *Attributor) Observe(ev RawEvent, env map[string]string) (*ProcessRun, Change) {
	switch ev.Type {
	case EventFork:
		return a.fork(ev)
	case EventExec:
		return a.exec(ev, env)
	case EventExit:
		return a.exit(ev)
	case EventMetrics:
		return a.metrics(ev)
	default:
		return nil, ChangeNone
	}
}

// metrics folds an EventMetrics refresh into an already-tracked run: it updates
// the resource counters and appends a live-chart sample WITHOUT re-resolving
// attribution (the run keeps its session/source). A no-op (ChangeNone) when the
// process isn't tracked — e.g. evicted, or one we never saw exec for.
//
// The return value is the PERSIST decision, and it is deliberately decoupled
// from the sample decision: the in-memory ring is updated on every refresh, but
// ChangeUpdated (→ a DB row rewrite) is only reported once per
// MetricPolicy.PersistInterval. See MetricPolicy for the reasoning.
func (a *Attributor) metrics(ev RawEvent) (*ProcessRun, Change) {
	if !ev.HasStartTime {
		return nil, ChangeNone
	}
	run := a.runs[ProcessKey(ev.BootID, ev.PID, ev.StartTimeTicks)]
	if run == nil {
		return nil, ChangeNone
	}
	if !ev.HasMetrics {
		return nil, ChangeNone
	}
	applyMetrics(run, &ev)
	a.appendMetricSample(run, &ev)
	run.LastSeenAt = ev.Timestamp
	if !a.shouldPersistMetrics(run, ev.Timestamp) {
		return nil, ChangeNone
	}
	run.LastMetricPersistAt = ev.Timestamp
	return run, ChangeUpdated
}

// shouldPersistMetrics applies the persist throttle. A zero/negative
// PersistInterval persists every refresh (the pre-decoupling behaviour); a
// zero timestamp (a backend that does not stamp events) also persists, so the
// throttle can never silently swallow every write.
func (a *Attributor) shouldPersistMetrics(run *ProcessRun, ts time.Time) bool {
	p := a.metricPolicy()
	if p.PersistInterval <= 0 || ts.IsZero() {
		return true
	}
	if run.LastMetricPersistAt.IsZero() {
		// Anchor on the run's creation so a freshly-exec'd process (already
		// persisted at exec) does not immediately rewrite its row.
		anchor := run.StartedAt
		if anchor.IsZero() {
			return true
		}
		return ts.Sub(anchor) >= p.PersistInterval
	}
	return ts.Sub(run.LastMetricPersistAt) >= p.PersistInterval
}

// SetMetricPolicy installs the live-chart ring policy (sample cadence,
// retained window, persist cadence). Additive: the zero value / never calling
// it leaves DefaultMetricPolicy in force, so existing callers are unaffected
// (CLAUDE.md rule 6). Not safe to call concurrently with Observe — the daemon
// sets it once at construction.
func (a *Attributor) SetMetricPolicy(p MetricPolicy) { a.metricRing = p.WithDefaults() }

// metricPolicy returns the effective policy, defaulting when never set.
func (a *Attributor) metricPolicy() MetricPolicy {
	if a.metricRing.SampleInterval <= 0 {
		return DefaultMetricPolicy()
	}
	return a.metricRing
}

// SnapshotForPersist returns the copy of run that goes to the Sink. It is the
// ONE place the persisted view diverges from the in-memory one: the
// full-resolution ring is downsampled to MetricPolicy.PersistMaxSamples into a
// FRESH slice, so (a) the stored JSON stays small however fast we sample and
// (b) the batched copy can never alias — and be mutated by — the live ring.
func (a *Attributor) SnapshotForPersist(run *ProcessRun) ProcessRun {
	out := *run
	out.MetricSamples = downsampleMetricSamples(run.MetricSamples, a.metricPolicy().PersistMaxSamples)
	return out
}

// downsampleMetricSamples reduces a ring to at most max points, evenly spaced,
// ALWAYS keeping the first and — load-bearing for a live chart — the last point
// exactly. Returns a fresh slice (never aliasing the input) or nil when empty.
// max ≤ 0 copies the whole ring.
func downsampleMetricSamples(in []MetricSample, max int) []MetricSample {
	if len(in) == 0 {
		return nil
	}
	if max <= 0 || len(in) <= max {
		return append([]MetricSample(nil), in...)
	}
	if max == 1 {
		return []MetricSample{in[len(in)-1]}
	}
	out := make([]MetricSample, 0, max)
	last := len(in) - 1
	for i := range max - 1 {
		out = append(out, in[i*last/(max-1)])
	}
	return append(out, in[last])
}

// applyMetrics copies resource counters from a (metrics-bearing) event onto a
// run. Cumulative counters (CPU, disk bytes/ops) take the latest reading — they
// only grow; MaxRSSBytes keeps the peak; working set / threads / handles take
// the current value. The caller guarantees ev.HasMetrics.
func applyMetrics(run *ProcessRun, ev *RawEvent) {
	run.CPUUserMs = ev.CPUUserMs
	run.CPUSystemMs = ev.CPUSystemMs
	run.WorkingSetBytes = ev.WorkingSetBytes
	if ev.MaxRSSBytes > run.MaxRSSBytes {
		run.MaxRSSBytes = ev.MaxRSSBytes
	}
	run.ReadBytes = ev.ReadBytes
	run.WriteBytes = ev.WriteBytes
	run.ReadOps = ev.ReadOps
	run.WriteOps = ev.WriteOps
	run.ThreadCount = ev.ThreadCount
	run.HandleCount = ev.HandleCount
}

// appendMetricSample appends a throttled point to the run's live-chart ring:
// a fresh point only when ≥ MetricPolicy.SampleInterval since the last (always
// for the first), else it refreshes the last point in place so "current" stays
// live without growing the buffer. On append, points outside
// MetricPolicy.Window are evicted and the ring is clamped to the derived cap,
// so a high sample rate bounds memory by TIME, not by however long the process
// lives.
func (a *Attributor) appendMetricSample(run *ProcessRun, ev *RawEvent) {
	p := a.metricPolicy()
	s := MetricSample{
		T:          ev.Timestamp,
		CPUMs:      ev.CPUUserMs + ev.CPUSystemMs,
		WorkingSet: ev.WorkingSetBytes,
		ReadBytes:  ev.ReadBytes,
		WriteBytes: ev.WriteBytes,
	}
	// Network bytes are carried ONLY when the backend actually measured them;
	// otherwise NetMeasured stays false and the consumer renders the series as
	// absent rather than as a zero line (types.go: MetricSample.NetMeasured).
	if ev.HasNetworkMetrics {
		s.NetRxBytes = ev.NetworkBytesIn
		s.NetTxBytes = ev.NetworkBytesOut
		s.NetMeasured = true
	}
	if n := len(run.MetricSamples); n > 0 {
		last := run.MetricSamples[n-1].T
		if !ev.Timestamp.IsZero() && !last.IsZero() && ev.Timestamp.Sub(last) < p.SampleInterval {
			// Refresh the current bucket's values in place but KEEP its start
			// timestamp, so the throttle measures from the last APPENDED point —
			// otherwise advancing T each poll resets the interval and a second
			// point never accrues.
			s.T = last
			run.MetricSamples[n-1] = s
			return
		}
	}
	run.MetricSamples = append(run.MetricSamples, s)
	run.MetricSamples = evictMetricSamples(run.MetricSamples, s.T, p)
}

// evictMetricSamples trims a ring to the retained window (points older than
// newest-Window are dropped) and then to the derived point cap. Both bounds
// drop from the OLDEST end, so the newest point always survives. A zero newest
// timestamp (a backend that does not stamp events) skips the time bound and
// relies on the count cap alone.
func evictMetricSamples(s []MetricSample, newest time.Time, p MetricPolicy) []MetricSample {
	if !newest.IsZero() && p.Window > 0 {
		cutoff := newest.Add(-p.Window)
		drop := 0
		for drop < len(s) && !s[drop].T.IsZero() && s[drop].T.Before(cutoff) {
			drop++
		}
		if drop > 0 {
			s = s[drop:]
		}
	}
	if capN := p.RingCap(); len(s) > capN {
		s = s[len(s)-capN:]
	}
	return s
}

// fork records a child process. We do NOT persist at fork (spec §8: the
// envelope is captured at exec) — we only seed the tree so the child can
// inherit attribution and so exec can find the node. Requires a start time
// to build a stable key (§9.3); without one the event is dropped upstream.
func (a *Attributor) fork(ev RawEvent) (*ProcessRun, Change) {
	if !ev.HasStartTime {
		return nil, ChangeNone
	}
	childKey := ProcessKey(ev.BootID, ev.PID, ev.StartTimeTicks)
	run := &ProcessRun{
		ProcessKey:     childKey,
		BootID:         ev.BootID,
		PID:            ev.PID,
		PPID:           ev.PPID,
		StartTimeTicks: ev.StartTimeTicks,
		StartedAt:      ev.Timestamp,
		LastSeenAt:     ev.Timestamp,
	}
	if parentKey, ok := a.livePID[ev.PPID]; ok {
		run.ParentProcessKey = parentKey
		if parent := a.runs[parentKey]; parent != nil {
			run.Attribution = inherit(parent)
		}
		run.ServiceRootKey = a.serviceRootFromParent(parentKey)
	}
	a.runs[childKey] = run
	a.livePID[ev.PID] = childKey
	return run, ChangeNone
}

// exec enriches a process with its executable/command/identity and
// resolves attribution. This is the persist point (ChangeCreated).
func (a *Attributor) exec(ev RawEvent, env map[string]string) (*ProcessRun, Change) {
	if !ev.HasStartTime {
		return nil, ChangeNone
	}
	key := ProcessKey(ev.BootID, ev.PID, ev.StartTimeTicks)
	run := a.runs[key]
	if run == nil {
		// exec without a prior fork (process root, or we started mid-stream).
		run = &ProcessRun{
			ProcessKey:     key,
			BootID:         ev.BootID,
			PID:            ev.PID,
			PPID:           ev.PPID,
			StartTimeTicks: ev.StartTimeTicks,
			StartedAt:      ev.Timestamp,
		}
		if parentKey, ok := a.livePID[ev.PPID]; ok {
			run.ParentProcessKey = parentKey
			if parent := a.runs[parentKey]; parent != nil {
				run.Attribution = inherit(parent)
			}
		}
		a.runs[key] = run
		a.livePID[ev.PID] = key
	}
	run.LastSeenAt = ev.Timestamp

	// Executable + command (scrubbed/capped/hashed).
	run.ExePath = a.scrub.ScrubPath(ev.ExePath)
	run.ExeBasename = basename(ev.ExePath)
	run.CWD = a.scrub.ScrubPath(ev.CWD)
	run.ArgvPreview, run.ArgvHash, run.ArgvArgc = a.scrub.ScrubArgv(ev.Argv)
	run.UID, run.GID, run.EUID, run.EGID = ev.UID, ev.GID, ev.EUID, ev.EGID
	if env != nil {
		run.EnvPosture = a.scrub.EnvPosture(env)
	}

	// Security / isolation posture (P4) — compact identifiers copied as-is;
	// the cgroup path is reduced to a hash so a long raw path never lands
	// (spec §8 Isolation).
	run.SeccompMode = ev.SeccompMode
	run.CapabilitiesEff = ev.CapabilitiesEff
	run.AppArmorLabel = ev.AppArmorLabel
	run.SELinuxLabel = ev.SELinuxLabel
	run.ContainerID = ev.ContainerID
	run.PIDNamespace = ev.PIDNamespace
	run.MountNamespace = ev.MountNamespace
	run.NetNamespace = ev.NetNamespace
	if ev.CgroupPath != "" {
		run.CgroupHash = HashString(ev.CgroupPath)
	}

	if ev.HasMetrics {
		applyMetrics(run, &ev)
		a.appendMetricSample(run, &ev)
	}

	// Service membership (capture budget, plan §4.2): re-inherit from the
	// parent as it is NOW (a parent detached as a service after this child
	// forked still owns it), so resolveAttribution knows whether an env
	// token on this run is a service member's inherited environment.
	if inherited := a.serviceRootFromParent(run.ParentProcessKey); inherited != "" {
		run.ServiceRootKey = inherited
	}
	a.resolveAttribution(run, ev.SessionToken)
	// A service-table executable in a session starts a service of its own.
	if a.isService != nil && run.ServiceRootKey == "" && run.Attribution.SessionID != "" && a.isService(run.ExeBasename) {
		run.ServiceRootKey = run.ProcessKey
	}
	return run, ChangeCreated
}

// resolveAttribution applies the §9.2 ordered rules to a run at exec time.
// Boundary first (resets + stops inheritance), then the strongest direct
// identity wins, otherwise whatever was inherited at fork survives. Order of
// the direct-identity checks:
//
//  1. env-token (§5.5 P-B6) — a session-id env var that resolves to an existing
//     session. Checked FIRST because it is namespace-independent: it identifies
//     the session directly, so it must preempt a (possibly colliding) pid seed
//     across the OS boundary, where a Windows-captured pid can numerically
//     collide with an unrelated WSL pidbridge entry. On a native host it agrees
//     with the pid seed (same session), so order is harmless there.
//  2. pid seed (§9.2.1/3) — a direct pidbridge / adapter hit on the root pid.
//
// sessionToken is the value the capturer recovered from SessionTokenEnvKeys
// (empty for most processes / non-EV tools).
func (a *Attributor) resolveAttribution(run *ProcessRun, sessionToken string) {
	if run.PID == 1 || a.boundaries[run.ExeBasename] {
		run.IsBoundary = true
		run.Attribution = Attribution{Source: AttrNone, Confidence: ConfNone}
		// A boundary is not the end of the story only if it is itself a
		// directly-identified AI-tool root — fall through to the direct checks,
		// which (pathologically) would re-attribute and clear the boundary.
	}
	if a.tokenSeed != nil && sessionToken != "" {
		if s, ok := a.tokenSeed(sessionToken); ok && s.SessionID != "" {
			// THE ENV TOKEN STOPS AT A SERVICE ROOT (capture budget, plan
			// §4.2). Environment variables are inherited by everything, so a
			// service the agent started (Docker Desktop restarted from a tool
			// call) hands the session token to every process it spawns for as
			// long as it runs. The token proves where the environment came
			// from, not that the session is driving the process: inside a
			// service subtree that already inherits this session, the run
			// keeps its INHERITED attribution (still the session's, so the
			// service stays tracked under it, per the operator ruling) instead
			// of becoming a fresh direct identity, and the service marking
			// (ServiceRootKey) is never cleared. An init/relay boundary is
			// still cleared below, today's behaviour for the agent itself.
			if run.ServiceRootKey != "" && run.ServiceRootKey != run.ProcessKey &&
				run.Attribution.SessionID == s.SessionID {
				return
			}
			run.IsBoundary = false
			run.Attribution = Attribution{
				SessionID:  s.SessionID,
				Tool:       s.Tool,
				ProjectID:  s.ProjectID,
				Source:     orDefault(s.Source, AttrEnvToken),
				Confidence: orDefaultConf(s.Confidence, ConfHigh),
			}
			return
		}
	}
	if a.seed != nil {
		if s, ok := a.seed(run.PID); ok && s.SessionID != "" {
			run.IsBoundary = false
			run.Attribution = Attribution{
				SessionID:  s.SessionID,
				Tool:       s.Tool,
				ProjectID:  s.ProjectID,
				Source:     orDefault(s.Source, AttrBridge),
				Confidence: orDefaultConf(s.Confidence, ConfHigh),
			}
			return
		}
	}
	// No direct identity: keep the inherited attribution (set at fork), unless
	// this is a boundary (already reset above).
}

// exit finalizes a process and detaches it from the tree (bounding memory
// to live processes). Returns the finished run for the update upsert, or
// ChangeNone if we never tracked it (e.g. exit before any fork/exec we saw).
func (a *Attributor) exit(ev RawEvent) (*ProcessRun, Change) {
	key := ""
	if ev.HasStartTime {
		key = ProcessKey(ev.BootID, ev.PID, ev.StartTimeTicks)
	}
	if key == "" || a.runs[key] == nil {
		if lk, ok := a.livePID[ev.PID]; ok {
			key = lk
		}
	}
	run := a.runs[key]
	if run == nil {
		return nil, ChangeNone
	}
	run.Exited = true
	run.ExitedAt = ev.Timestamp
	run.LastSeenAt = ev.Timestamp
	run.ExitCode = ev.ExitCode
	run.ExitSignal = ev.ExitSignal
	if !run.StartedAt.IsZero() && !ev.Timestamp.IsZero() {
		run.DurationMs = ev.Timestamp.Sub(run.StartedAt).Milliseconds()
	}
	if ev.HasMetrics {
		applyMetrics(run, &ev)
		a.appendMetricSample(run, &ev)
	}

	// Detach: free the pid and stop tracking. The returned pointer stays
	// valid for the Observer to persist; we just no longer hold it.
	delete(a.runs, key)
	if a.livePID[ev.PID] == key {
		delete(a.livePID, ev.PID)
	}
	return run, ChangeUpdated
}

// EvictOldestLive drops the oldest-started tracked run when the tree
// exceeds max, returning the number evicted. A bound for never-exiting
// processes (spec §15 high-volume handling); the Observer calls it after
// each batch. max <= 0 disables eviction.
func (a *Attributor) EvictOldestLive(max int) int {
	if max <= 0 || len(a.runs) <= max {
		return 0
	}
	evicted := 0
	for len(a.runs) > max {
		var oldestKey string
		var oldest time.Time
		for k, r := range a.runs {
			if oldestKey == "" || r.StartedAt.Before(oldest) {
				oldestKey, oldest = k, r.StartedAt
			}
		}
		if oldestKey == "" {
			break
		}
		r := a.runs[oldestKey]
		delete(a.runs, oldestKey)
		if a.livePID[r.PID] == oldestKey {
			delete(a.livePID, r.PID)
		}
		evicted++
	}
	return evicted
}

// inherit copies a parent's attribution to a child as AttrInherited,
// preserving confidence but never inheriting from a boundary (§9.2.6) or
// an unattributed parent.
func inherit(parent *ProcessRun) Attribution {
	if parent.IsBoundary || parent.Attribution.SessionID == "" {
		return Attribution{Source: AttrNone, Confidence: ConfNone}
	}
	return Attribution{
		SessionID:  parent.Attribution.SessionID,
		Tool:       parent.Attribution.Tool,
		ProjectID:  parent.Attribution.ProjectID,
		Source:     AttrInherited,
		Confidence: parent.Attribution.Confidence,
	}
}

func orDefault(s, def AttributionSource) AttributionSource {
	if s == "" {
		return def
	}
	return s
}

func orDefaultConf(c, def Confidence) Confidence {
	if c == "" {
		return def
	}
	return c
}

// basename is procmodel.Basename (one owner of the slash-agnostic rule).
func basename(p string) string { return procmodel.Basename(p) }
