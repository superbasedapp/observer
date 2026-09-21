package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/pidbridge"
	"github.com/marmutapp/superbased-observer/internal/processobs"
	"github.com/marmutapp/superbased-observer/internal/processobs/bridge"
	"github.com/marmutapp/superbased-observer/internal/processobs/linuxebpf"
	"github.com/marmutapp/superbased-observer/internal/processobs/poll"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// processObserverMaxTracked caps the Attributor's live process tree as a
// leak guard. The live set is naturally bounded (exits detach), so this only
// matters if exits are somehow missed; well above any real process table.
const processObserverMaxTracked = 8192

// runProcessObserver is the daemon-resident Process Observability service
// (docs/process-observability.md §6). It is gated on
// [observer.process].enabled (opt-in, default off) and FAIL-OPEN at every
// step: a missing/unsupported backend, a privilege failure, or any runtime
// error degrades to a WARN and returns nil — it must never cancel the
// proxy/watcher/dashboard (acceptance criterion 6). Mirrors the guard-cloud /
// otel sibling goroutines: loads its own config+DB, returns nil on any miss.
func runProcessObserver(ctx context.Context, configPath string) error {
	cfg, db, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return nil
	}
	defer cleanup()
	if !cfg.Observer.Process.Enabled {
		return nil
	}
	logger := newLogger(cfg.Observer.LogLevel)

	// Shared status handle for per-process network byte accounting. The
	// capture backend is its only writer; the Observer's health snapshot reads
	// it so `observer doctor` and the dashboard can tell "measured zero bytes"
	// from "not measured at all".
	netAccounting := &processobs.NetworkAccounting{}
	netAccounting.Set(processobs.NetworkAccountingOff, "not enabled ([observer.process.network].process_bytes)")

	backend, transportUnavailable, berr := selectProcessBackend(cfg.Observer.Process, filepath.Dir(cfg.Observer.DBPath), logger, netAccounting)
	if berr != nil {
		logger.Warn("process observability: no backend — capture disabled (daemon continues)",
			"backend", cfg.Observer.Process.Backend, "reason", berr.Error())
		return nil
	}

	st := store.New(db)
	// Read-only seam onto the session_pid_bridge: the SessionStart hook owns
	// the writes; here we only Lookup a (root) pid → session. Descendants are
	// attributed by tree inheritance inside the Attributor, not by lookup.
	bridge := pidbridge.New(db)
	seed := func(pid int) (processobs.Seed, bool) {
		e, ok, lerr := bridge.Lookup(ctx, pid)
		if lerr != nil || !ok {
			return processobs.Seed{}, false
		}
		return processobs.Seed{
			SessionID:  e.SessionID,
			Tool:       e.Tool,
			Source:     processobs.AttrBridge,
			Confidence: processobs.ConfHigh,
		}, true
	}

	// One scrubber instance, shared by the Attributor (argv/path/env scrub at
	// exec) and the DeepEnricher (env-posture policy for the targeted environ
	// read). The DeepEnricher (poll/enrich_linux.go) is the post-attribution,
	// per-new-process seam that feeds /proc/<pid>/environ → env posture and,
	// when [observer.process.executable].hash_enabled, the exe content hash —
	// sensitive/expensive reads done once per persisted run, not whole-table
	// every poll (spec §8.1, §8 Executable, §19 Q6). It is nil on non-Linux.
	scrubber := buildProcessScrubber(cfg.Observer.Process)
	deepEnricher := poll.NewDeepEnricher(
		scrubber,
		cfg.Observer.Process.Executable.HashEnabled,
		cfg.Observer.Process.Executable.MaxHashFileSizeMB,
	)

	// A backend whose events can't be attributed at capture time (the cross-OS
	// bridge — §5.5) forces unattributed capture so the Windows rows persist
	// for the deferred CorrelateCrossOS pass to join them to a session.
	captureUnattributed := cfg.Observer.Process.CaptureUnattributed
	if uc, ok := backend.(processobs.UnattributedCapturer); ok && uc.RequiresUnattributedCapture() {
		captureUnattributed = true
		logger.Info("process observability: backend requires unattributed capture (deferred cross-OS attribution)",
			"backend", backend.Name())
	}

	// EV (§5.5 P-B6): the capturer recovers an allowlisted session-id env var
	// (e.g. CLAUDE_CODE_SESSION_ID) for new processes; this seam resolves it to
	// a session by direct equality, attributing the whole env-inheriting subtree
	// at HIGH confidence — namespace-independent, so it works across the WSL↔
	// Windows boundary where the pidbridge pid seed cannot. A miss falls back to
	// the medium CorrelateCrossOS pass.
	attributor := processobs.NewAttributor(seed, scrubber, nil)
	attributor.SetMetricPolicy(resolveMetricPolicy(cfg.Observer.Process, logger))
	attributor.SetTokenLookup(func(token string) (processobs.Seed, bool) {
		s, ok, lerr := st.SessionSeedByID(ctx, token)
		if lerr != nil || !ok {
			return processobs.Seed{}, false
		}
		return s, true
	})

	// Never capture the observer daemon's OWN processes as unattributed AI
	// activity (§3.1). Include the running binary's basename (so a renamed
	// install still self-excludes) plus the canonical names, covering the
	// cross-OS bridge's Windows `observer.exe` too.
	ownBasenames := []string{"observer", "observer.exe"}
	if exe, eerr := os.Executable(); eerr == nil {
		if base := filepath.Base(exe); base != "" {
			ownBasenames = append(ownBasenames, base)
		}
	}

	obs := processobs.NewObserver(processobs.Options{
		Backend:             backend,
		Attributor:          attributor,
		DeepEnricher:        deepEnricher,
		Sink:                st,
		EventSink:           st,
		CaptureUnattributed: captureUnattributed,
		ExcludeOwnBasenames: ownBasenames,
		// Always capture UNATTRIBUTED AI-tool subtrees (codex/cursor/… on a
		// native host where no pidbridge seed or env-token resolves) so the
		// deferred CorrelateCrossOS cwd pass can join them to a session. This
		// is the native-Linux counterpart to the bridge's whole-table
		// unattributed capture, but bounded to AI subtrees — the rest of the
		// process table is still dropped. Gives every adapter (not just
		// Claude Code) process attribution.
		CaptureUnattributedAISubtree: true,
		BatchSize:                    cfg.Observer.Process.BatchSize,
		MaxTracked:                   processObserverMaxTracked,
		NetworkAccounting:            netAccounting,
		// "You asked for the cross-OS feed and it is not running" travels as
		// a PLAIN VALUE from the one place that knows it, never as a wrapper
		// around the backend — see processobs.Options.TransportUnavailableReason
		// for the capability-loss that wrapping caused.
		TransportUnavailableReason: transportUnavailable,
	})

	// Refresh the active-session project roots that gate cwd-anchored capture
	// (extends process attribution to EVERY adapter — the generic-interpreter
	// tools like hermes-as-python / pi / roo-code / in-IDE Copilot that present
	// no branded launcher but run workers in the project dir). Seed once, then
	// on a ticker; best-effort, a query error just leaves the AI-subtree signal.
	refreshRoots := func() {
		if roots, rerr := st.ActiveSessionRoots(ctx, 60); rerr == nil {
			obs.SetActiveSessionRoots(roots)
		}
	}
	refreshRoots()
	go func() {
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				refreshRoots()
			}
		}
	}()

	// Periodic background cross-OS correlation sweep (§9.2.5). The deferred
	// CorrelateCrossOS join — the pass that makes an unattributed process row
	// VISIBLE to a session (sets session_id) — otherwise runs ONLY lazily: the
	// dashboard Processes drawer poll (30s debounced) or `observer process
	// tree`. Until a human looks, captured rows stay invisible to
	// ProcessRunsForSession (audit 2026-07-15 root-cause #2). This re-runs that
	// SAME store seam (idempotent, confidence-guarded UPDATE — so it never
	// fights the lazy trigger; whichever runs first, the other is a no-op) over
	// the recent-active session set, so attribution converges without a viewer.
	// Bounded to sessions active in the last 60 min; a query error skips the
	// tick. Only reached when capture is enabled + a backend was selected, so a
	// disabled install never sweeps. Logs at DEBUG — no per-tick INFO spam.
	correlateInterval := resolveCorrelateInterval(cfg.Observer.Process)
	go func() {
		t := time.NewTicker(correlateInterval)
		defer t.Stop()
		actionCursors := make(map[string]actionSweepCursor)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				swept, attributed, cerr := sweepCrossOSCorrelation(ctx, st, 60, logger)
				if cerr != nil {
					logger.Debug("process observability: correlation sweep — active-session query failed", "err", cerr)
				} else if swept > 0 {
					logger.Debug("process observability: background correlation sweep",
						"sessions", swept, "newly_attributed", attributed)
				}
				consumeLaunchSeeds(ctx, st, bridge, logger)
				// Runs AFTER the cross-OS sweep in the same tick, so a process
				// row that just gained a session_id above can be turn-linked
				// to its run_command action in this same pass. Already inside
				// the capture-enabled+backend-selected guard above, so a
				// disabled install never sweeps.
				linkedSessions, linked, lerr := sweepActionCorrelation(ctx, st, 60, logger, actionCursors)
				if lerr != nil {
					logger.Debug("process observability: action-correlation sweep — active-session query failed", "err", lerr)
				} else if linked > 0 {
					logger.Debug("process observability: background action-correlation sweep",
						"sessions", linkedSessions, "newly_linked", linked)
				}
			}
		}
	}()

	netMode, netReason := netAccounting.Status()
	logger.Info("process observability: starting",
		"backend", backend.Name(), "network_accounting", netMode, "network_accounting_reason", netReason)

	// Publish the runtime health where the out-of-process surfaces can read
	// it (see diag.ProcessHealth for why a file). This must be a REFRESHING
	// publisher, not a one-shot write at start: the eBPF backend decides
	// whether per-process network accounting attached inside its Start, which
	// runs below inside obs.Run — so the mode known at this point is still
	// the pessimistic pre-attach guess.
	stopHealth := publishProcessHealth(ctx, cfg.Observer.DBPath,
		func() processobs.HealthSnapshot { return obs.Health().Snapshot() }, logger)
	defer stopHealth()

	if rerr := obs.Run(ctx); rerr != nil && !errors.Is(rerr, context.Canceled) {
		// Backend Start failure (unsupported OS / missing CAP_BPF / no /proc)
		// or a fatal runtime error — degraded, never propagated. The DB-derived
		// gauges + `observer doctor` still report persisted state.
		h := obs.Health().Snapshot()
		logger.Warn("process observability: backend stopped — capture degraded (daemon continues)",
			"backend", h.BackendName, "err", rerr)
	}
	return nil
}

// processHealthRecord maps the Observer's in-memory health snapshot onto the
// on-disk record the out-of-process surfaces read. It is a boundary mapping
// on purpose: internal/diag stays free of processobs types, so the file is a
// plain wire shape rather than a leaked struct (CLAUDE.md rule 2).
// The transport half is flattened to plain scalars for the same reason: the
// backend-agnostic processobs.TransportStats does not cross into diag either,
// and the TRI-state is carried explicitly so a reader can tell "no dial-in
// transport was requested" from "one was requested and could not start" from
// "a transport nobody has ever connected to". Those are three different facts
// and two of them used to render as the same silence.
func processHealthRecord(h processobs.HealthSnapshot) diag.ProcessHealth {
	r := diag.ProcessHealth{
		Backend:                 h.BackendName,
		BackendUp:               h.BackendUp,
		QueueDepth:              h.QueueDepth,
		LastError:               h.LastError,
		NetworkAccountingMode:   h.NetworkAccountingMode,
		NetworkAccountingReason: h.NetworkAccountingReason,
		Unattributed:            h.Unattributed,
		SinkRetained:            h.SinkRetained,
		SinkFlushMaxMs:          h.SinkFlushMaxMs,
		QueueDepthMax:           h.QueueDepthMax,
		HandoffDepthMax:         h.HandoffDepthMax,
		FlushBacklogHits:        h.FlushBacklogHits,
	}
	// The capture-YIELD half. It used to be omitted entirely, which left every
	// out-of-process surface unable to tell "nothing spawned" from "every batch
	// was discarded on a locked database" — the state the 2026-08-26 capture
	// anomaly sat in undiagnosed (task 9d). The DropReason keys are flattened
	// to plain strings here, at the same boundary that flattens the transport
	// half, so diag keeps a wire shape instead of a leaked processobs type.
	if len(h.Dropped) > 0 {
		r.Dropped = make(map[string]int64, len(h.Dropped))
		for reason, n := range h.Dropped {
			r.Dropped[string(reason)] = n
		}
	}
	if len(h.AttributedByTool) > 0 {
		r.AttributedByTool = make(map[string]int64, len(h.AttributedByTool))
		for tool, n := range h.AttributedByTool {
			r.AttributedByTool[tool] = n
			// Attributed is DERIVED here rather than carried as its own
			// counter: one owner for the total means the breakdown and the
			// headline can never disagree (CLAUDE.md rule 4).
			r.Attributed += n
		}
	}
	switch h.TransportState {
	case processobs.TransportStateConfigured:
		r.TransportState = processobs.TransportStateConfigured
		r.TransportAddr = h.Transport.Addr
		r.TransportConnections = h.Transport.Connections
		r.TransportAuthFailures = h.Transport.AuthFailures
		// The refusal REASON is the only thing that may be presented as the
		// cause of a refusal; dropping it here would leave the surfaces with
		// a bare counter and force them back to guessing "bad token".
		r.TransportLastAuthError = h.Transport.LastAuthError
		// Its bounded twin travels with it — the text surfaces read the
		// reason, the metrics exporter reads the class, and neither has to
		// re-derive the other by matching on words.
		r.TransportLastAuthErrorClass = h.Transport.LastAuthErrorClass
		r.TransportConnected = h.Transport.Connected
		r.TransportLastConnectAt = h.Transport.LastConnectAt
		r.TransportLastDisconnectAt = h.Transport.LastDisconnectAt
		// The capturer's own decode counters travel WITH their presence flag.
		// Copying the counters without it would turn "no decoder ever
		// reported" into "zero events were refused" the moment the record hit
		// disk — the exact absence-rendered-as-zero inversion the flag exists
		// to stop.
		r.TransportCapturerDecodeReported = h.Transport.CapturerDecodeReported
		r.TransportCapturerDropped = h.Transport.CapturerDecode.NetworkDropped
		r.TransportCapturerUnsupportedVersion = h.Transport.CapturerDecode.NetworkUnsupportedVersion
		// The positive half of the same report, under the same flag. Without
		// it the record can only say what the decoder REFUSED, and a provider
		// whose event ids were renumbered refuses nothing while classifying
		// nothing — a clean-looking record for a decoder measuring zero.
		r.TransportCapturerDecoded = h.Transport.CapturerDecode.NetworkDecoded
		r.TransportCapturerIgnored = h.Transport.CapturerDecode.NetworkIgnored
		r.TransportCapturerDecodeAt = h.Transport.CapturerDecodeAt
	case processobs.TransportStateUnavailable:
		r.TransportState = processobs.TransportStateUnavailable
		r.TransportUnavailableReason = h.TransportUnavailableReason
	}
	return r
}

// publishProcessHealth republishes the Observer's runtime health beside the
// DB every diag.ProcessHealthRefreshInterval, so `observer doctor` and the
// `observer metrics` exporter — both separate processes that cannot read this
// daemon's memory — can report whether per-process network accounting is
// actually live, and why not when it is not.
//
// It REFRESHES rather than writing once because the interesting state
// settles late: the eBPF backend records the accounting outcome inside its
// Start, and an ETW capturer that fails to elevate does the same. The
// returned stop func removes the record and waits for the goroutine, so a
// daemon that exits leaves nothing behind for doctor to misread as live.
// Every failure is best-effort: a health file that cannot be written must
// never affect capture.
func publishProcessHealth(ctx context.Context, dbPath string, snapshot func() processobs.HealthSnapshot, logger *slog.Logger) func() {
	dir := diag.ProcessHealthDir(dbPath)
	if dir == "" || snapshot == nil {
		return func() {}
	}
	stopCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var (
			path   string
			warned bool
		)
		publish := func() {
			p, err := diag.WriteProcessHealth(dir, processHealthRecord(snapshot()))
			if err != nil {
				if !warned && logger != nil {
					logger.Warn("process observability: could not publish runtime health — `observer doctor` and /metrics will report that no daemon is reporting",
						"dir", dir, "err", err)
					warned = true
				}
				return
			}
			path = p
		}
		publish()
		t := time.NewTicker(diag.ProcessHealthRefreshInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				_ = diag.RemoveProcessHealth(path)
				return
			case <-stopCh:
				_ = diag.RemoveProcessHealth(path)
				return
			case <-t.C:
				publish()
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() { close(stopCh) })
		<-done
	}
}

// selectProcessBackend resolves [observer.process].backend to a concrete
// Backend, or an error explaining why none is available (the caller then
// fail-opens). The poll backend (§5.4) and the real-time linux_ebpf backend
// (§5.2, fail-opens to poll when uncapable) are implemented; endpointsecurity
// is still a stub. "auto" PREFERS the eBPF stack when the box can load BPF
// (capability-probed; usually false for the unprivileged daemon → poll),
// composing it with poll (metric sampler + initial snapshot, dedup on
// process_key) + the bridge. Branching is on the configured capability, not host
// identity (the backend's own Start probe decides OS support and fail-opens).
//
// The ETW feed is HYBRID (plan option C), and deliberately not a `backend`
// alternative: whatever baseline the switch below picks, an enabled
// [observer.process.etw] block ADDS the accept listener as a second child. The
// zero-privilege poll/bridge baseline is untouched, and an install where no
// elevated capturer ever connects behaves exactly as it does today.
//
// observerDir is the directory holding the observer DB — where the listener's
// shared token is generated/persisted. netStatus is the shared handle the
// byte-capable backend writes its per-process network-accounting state to; nil
// is tolerated (nothing listens).
//
// The second return value is the reason a REQUESTED dial-in transport is not
// running (empty in the normal case). It is returned BESIDE the backend, not
// attached to it: the previous shape wrapped the backend in a decorator that
// answered processobs.TransportUnavailableSource, and embedding an interface
// promotes only that interface's methods — so every OPTIONAL capability the
// baseline implemented (UnattributedCapturer above all, which is what makes
// cross-OS process rows persist at all) stopped being visible to a type
// assertion. Returning a value keeps the assembled backend untouched, and no
// future capability can be lost by a decorator nobody remembered to update.
func selectProcessBackend(pc config.ProcessConfig, observerDir string, logger *slog.Logger, netStatus *processobs.NetworkAccounting) (processobs.Backend, string, error) {
	// Pessimistic default: per-process byte counters only exist on the eBPF
	// backend, so every other selection leaves them UNMEASURED. The eBPF path
	// overwrites this with the real outcome when it attaches.
	if pc.Network.ProcessBytes {
		netStatus.Set(processobs.NetworkAccountingUnavailable,
			"per-process byte counters need the linux_ebpf backend, which is not active")
	}
	pollMS, bridgeMS := resolveProcessPollIntervals(pc)
	pollOpts := poll.Options{Interval: time.Duration(pollMS) * time.Millisecond}
	// The cross-OS capturer reports its OWN per-process network-accounting
	// status in its hello frame (an ETW capture that could not elevate, or one
	// that is live), so on a bridge deployment the handle's truth comes from
	// Windows rather than from this host's pessimistic guess. It is handed over
	// only where the bridge is the sole byte-capable source — see
	// bridgeOptsNoNet below for the one place it is not.
	bridgeOpts := bridge.Options{
		WindowsBinaryPath: pc.WindowsBinaryPath,
		PollIntervalMS:    bridgeMS,
		Logger:            logger,
		NetworkAccounting: netStatus,
	}
	// One owner, again: when the ETW accept feed is enabled it is the
	// byte-capable source on this topology (the spawned bridge capturer is the
	// NON-elevated one and can never count bytes), so it takes the handle and
	// the spawn bridge gives it up. Without this, a poll-only capturer's
	// honest "off" would clobber the elevated capturer's live "tcp".
	if pc.ETW.Enabled {
		bridgeOpts.NetworkAccounting = nil
	}
	// Same bridge, minus ownership of the shared status handle. One owner per
	// piece of state (CLAUDE.md rule 4): when the eBPF stack is running, the
	// eBPF backend owns the handle, and a Windows capturer reporting "off"
	// would otherwise clobber a locally-true "tcp".
	bridgeOptsNoNet := bridgeOpts
	bridgeOptsNoNet.NetworkAccounting = nil
	onChildErr := func(name string, err error) {
		logger.Warn("process observability: composite child unavailable (capture continues with the rest)", "child", name, "err", err)
	}
	// newComposite runs the Linux /proc poll backend AND the Windows cross-OS
	// bridge together (fan-in), so a daemon on the canonical WSL topology
	// captures BOTH WSL-native AND Windows AI-tool processes — a single backend
	// sees only one OS's process table. Fail-open per child inside the composite.
	newComposite := func() processobs.Backend {
		return processobs.NewComposite([]processobs.Backend{
			poll.New(pollOpts),
			bridge.New(bridgeOpts),
		}, onChildErr)
	}
	// ebpfOwnsNetwork records that the eBPF backend took ownership of the
	// shared network-accounting handle, so the ETW listener does not also
	// write it (one owner per piece of state, CLAUDE.md rule 4). It is set by
	// newEBPFComposite, which runs inside the switch below — always before
	// withETW is applied to its result.
	ebpfOwnsNetwork := false
	// newEBPFComposite is the real-time stack: the eBPF backend (§5.2, Linux
	// lifecycle — catches the sub-poll-interval processes the poller misses) PLUS
	// the poll backend, which serves as the metric sampler + initial-snapshot
	// source (eBPF only sees execs AFTER attach; poll's first tick attributes
	// already-running roots) + the survivor metric refresh eBPF can't tick. The
	// two share a boot-id namespace, so a process seen by both UPSERTS on
	// process_key (pinned by store TestPersistRunsUpsertExecThenExit) rather than
	// doubling. The Windows bridge joins on WSL (distinct boot-id). Only built
	// when linuxebpf.Available passed.
	newEBPFComposite := func() processobs.Backend {
		ebpfOwnsNetwork = true
		eb := linuxebpf.New(linuxebpf.Options{
			Logger:            logger,
			NetworkAccounting: pc.Network.ProcessBytes,
			NetworkStatus:     netStatus,
		})
		// Per-process network bytes are measured by the eBPF backend but
		// SAMPLED by the poll backend (it owns the metric-refresh stream), so
		// the counters travel through the NetworkSampler capability seam — a
		// capability check, never a backend-name check (CLAUDE.md rule 3).
		netPollOpts := pollOpts
		if ns, ok := eb.(processobs.NetworkSampler); ok {
			netPollOpts.NetworkBytes = ns.NetworkBytes
		}
		children := []processobs.Backend{
			eb,
			poll.New(netPollOpts),
		}
		if bridge.AvailableInWSL(pc.WindowsBinaryPath) {
			children = append(children, bridge.New(bridgeOptsNoNet))
		}
		return processobs.NewComposite(children, onChildErr)
	}

	// withETW appends the accept-mode listener to whatever baseline the switch
	// below chose. Fail-open at every step: a bind conflict, a token that
	// cannot be written, or a disabled block all leave the CAPTURE baseline
	// exactly as it was.
	//
	// Fail-open is not fail-silent, though. When the operator ASKED for the
	// cross-OS feed and it did not come up, the baseline is returned UNTOUCHED
	// alongside the reason, so the health record can say "you asked for ETW
	// and it is not running" instead of printing exactly what an install that
	// never enabled ETW prints — a bind conflict on the listen address being
	// the likeliest way to get here. The baseline is deliberately not wrapped:
	// see this function's doc comment.
	withETW := func(base processobs.Backend) (processobs.Backend, string) {
		if !pc.ETW.Enabled {
			// backend = "etw" is itself a request for the feed, and on its own
			// it starts nothing. Silence would make that config typo permanent
			// and invisible.
			if pc.Backend == "etw" {
				return base, `[observer.process.etw].enabled is false, so no accept listener was started ` +
					`(backend = "etw" alone does not start one — set [observer.process.etw].enabled = true)`
			}
			return base, ""
		}
		// The eBPF backend owns the network handle when it is running (it
		// measures THIS host's bytes and has already attached); the listener
		// then reports events only. Otherwise the listener owns it.
		lnStatus := netStatus
		if ebpfOwnsNetwork {
			lnStatus = nil
		}
		ln, lerr := newProcessBridgeListener(pc, observerDir, logger, lnStatus)
		if lerr != nil {
			logger.Warn("process observability: ETW accept listener unavailable — continuing without the elevated cross-OS feed",
				"addr", pc.ETW.ListenAddr, "err", lerr)
			lnStatus.Set(processobs.NetworkAccountingUnavailable,
				"the cross-OS process capturer listener could not start: "+lerr.Error())
			// The network-accounting handle above is deliberately nil when the
			// eBPF backend owns it (one owner per piece of state), so on that
			// host it carries NO signal at all — this reason is the only
			// operator-visible trace of the failure.
			return base, lerr.Error()
		}
		logger.Info("process observability: ETW accept listener ready — waiting for an elevated capturer to connect",
			"addr", ln.Addr())
		return processobs.NewComposite([]processobs.Backend{base, ln}, onChildErr), ""
	}

	// autoBackend is the "best available for this host" baseline: prefer the
	// real-time eBPF stack when this box can actually load BPF
	// (capability-probed; the unprivileged daemon usually can't, so this is
	// normally false → poll). When eBPF is available, compose it with poll
	// (metrics + initial snapshot, dedup on process_key) + the bridge.
	// Otherwise the legacy path: poll+bridge on WSL, else the single poll
	// backend (Linux /proc or, on a Windows host, the ToolHelp snapshot).
	autoBackend := func() processobs.Backend {
		if linuxebpf.Available(logger) {
			logger.Info("process observability: auto selected linux_ebpf — real-time capture + poll metric sampler")
			return newEBPFComposite()
		}
		if bridge.AvailableInWSL(pc.WindowsBinaryPath) {
			return newComposite()
		}
		return poll.New(pollOpts)
	}

	switch pc.Backend {
	case "off":
		return nil, "", errors.New("backend set to off")
	case "poll":
		b, reason := withETW(poll.New(pollOpts))
		return b, reason, nil
	case "bridge":
		// Cross-OS bridge (§5.5): exec the Windows observer.exe over WSL
		// interop. Start fail-opens if not under WSL or the binary is missing.
		b, reason := withETW(bridge.New(bridgeOpts))
		return b, reason, nil
	case "both":
		// Explicit: Linux poll + Windows bridge together (see newComposite).
		b, reason := withETW(newComposite())
		return b, reason, nil
	case "auto":
		b, reason := withETW(autoBackend())
		return b, reason, nil
	case "linux_ebpf":
		// Explicitly request the real-time Linux stack (§5.2): catches the
		// sub-poll-interval processes the /proc poller misses. The P0 gate is
		// privilege + kernel: loading BPF needs CAP_BPF+CAP_PERFMON and a
		// BPF-capable kernel, which the unprivileged daemon usually lacks — so
		// probe and FAIL OPEN to the poll path rather than disabling capture.
		if !linuxebpf.Available(logger) {
			logger.Info("process observability: linux_ebpf unavailable (needs CAP_BPF+CAP_PERFMON and a BPF-capable kernel) — falling back to poll capture")
			if bridge.AvailableInWSL(pc.WindowsBinaryPath) {
				b, reason := withETW(newComposite())
				return b, reason, nil
			}
			b, reason := withETW(poll.New(pollOpts))
			return b, reason, nil
		}
		logger.Info("process observability: linux_ebpf backend active — real-time fork/exec/exit capture + poll metric sampler")
		b, reason := withETW(newEBPFComposite())
		return b, reason, nil
	case "etw":
		// ETW (§5.2) is an ELEVATED, OPTIONAL, ADDITIVE feed — never a
		// baseline. What it contributes (per-process network bytes, W2) rides
		// on top of the process trees the zero-privilege poll/bridge stack
		// already captures, and it arrives over a socket a capturer may never
		// dial. So this case selects the same baseline "auto" would and ADDS
		// the listener; it never trades working capture for a feed that might
		// not show up (plan option C, hybrid).
		if !pc.ETW.Enabled {
			logger.Warn(`process observability: backend = "etw" but [observer.process.etw].enabled is false — ` +
				"no accept listener is started (set it to true); capture continues on the poll/bridge baseline")
		}
		b, reason := withETW(autoBackend())
		return b, reason, nil
	case "endpointsecurity":
		return nil, "", errors.New("endpointsecurity backend not yet implemented (P6)")
	default:
		return nil, "", fmt.Errorf("unknown process backend %q", pc.Backend)
	}
}

// NOTE — there is deliberately NO decorator here. The reason a requested
// dial-in transport is missing used to be carried by wrapping the assembled
// backend in a type that embedded processobs.Backend and added
// TransportUnavailableReason. That is a capability shredder: embedding an
// INTERFACE promotes only that interface's method set, so `backend.(X)` for
// every optional capability X the wrapped value implements — UnattributedCapturer,
// NetworkSampler, TransportStatsSource — fails on the wrapper. The concrete
// harm was silent and total: runProcessObserver probes UnattributedCapturer
// to decide whether cross-OS process rows are captured at all, so on the two
// ordinary configurations that reach the wrapper (a bridge/both/auto baseline
// whose ETW listener loses the :8823 bind, and backend = "etw" with the block
// disabled) Windows process rows simply stopped being persisted — on exactly
// the path whose purpose is to report a failure LOUDLY.
//
// The replacement is a plain string returned beside the backend
// (selectProcessBackend's second result → processobs.Options.TransportUnavailableReason).
// It cannot lose a capability, and it cannot lose one that has not been
// invented yet either — which an explicit-forwarding decorator would, the
// next time someone adds a capability and does not think of this file
// (CLAUDE.md rule 6). TestSelectProcessBackendPreservesBackendCapabilities
// fails if a wrapper ever comes back.

// resolveProcessPollIntervals turns the [observer.process] config into the
// concrete (Linux-poll, Windows-bridge) snapshot cadences in milliseconds.
// PollIntervalMS is the single operator-facing "process poll rate"; a value
// <= 0 falls back to the 2000 ms default. BridgePollIntervalMS is an optional
// per-bridge override: <= 0 inherits the resolved poll interval so one knob
// controls both sources unless the operator deliberately splits them.
func resolveProcessPollIntervals(pc config.ProcessConfig) (pollMS, bridgeMS int) {
	pollMS = pc.PollIntervalMS
	if pollMS <= 0 {
		pollMS = 2000
	}
	bridgeMS = pc.BridgePollIntervalMS
	if bridgeMS <= 0 {
		bridgeMS = pollMS
	}
	return pollMS, bridgeMS
}

// resolveMetricPolicy turns [observer.process.metrics] into the live-chart
// ring policy, applying the "0 = inherit the default" contract the other
// process intervals use.
//
// It also enforces the honesty rule about the sampling ceiling: a metric
// sample can never be fresher than the poll that produces it, so a
// sample_interval_ms BELOW poll_interval_ms cannot deliver the resolution it
// names. We do NOT silently raise the poll rate (that is the operator's CPU
// budget to spend) and we do NOT silently clamp the config; we WARN once at
// start, naming both numbers, and let the ring append every poll.
func resolveMetricPolicy(pc config.ProcessConfig, logger *slog.Logger) processobs.MetricPolicy {
	p := processobs.DefaultMetricPolicy()
	if pc.Metrics.SampleIntervalMS > 0 {
		p.SampleInterval = time.Duration(pc.Metrics.SampleIntervalMS) * time.Millisecond
	}
	if pc.Metrics.WindowSeconds > 0 {
		p.Window = time.Duration(pc.Metrics.WindowSeconds) * time.Second
	}
	if pc.Metrics.MaxSamples > 0 {
		p.MaxSamples = pc.Metrics.MaxSamples
	}
	if pc.Metrics.PersistIntervalMS != 0 {
		p.PersistInterval = time.Duration(pc.Metrics.PersistIntervalMS) * time.Millisecond
	}
	if pc.Metrics.PersistMaxSamples != 0 {
		p.PersistMaxSamples = pc.Metrics.PersistMaxSamples
	}
	pollMS, _ := resolveProcessPollIntervals(pc)
	pollInterval := time.Duration(pollMS) * time.Millisecond
	if logger != nil && p.SampleInterval < pollInterval {
		logger.Warn("process observability: metrics.sample_interval_ms is below the process poll interval — samples cannot be fresher than the poll that produces them; raise poll_interval_ms too (it costs a /proc scan) or the extra resolution is not real",
			"sample_interval_ms", p.SampleInterval.Milliseconds(),
			"poll_interval_ms", pollInterval.Milliseconds())
	}
	return p
}

// resolveCorrelateInterval turns [observer.process].correlate_interval_ms into
// the background cross-OS correlation sweep cadence. A value <= 0 falls back to
// the 90s default — the same "0 = inherit the default" contract the poll
// intervals use.
func resolveCorrelateInterval(pc config.ProcessConfig) time.Duration {
	ms := pc.CorrelateIntervalMS
	if ms <= 0 {
		ms = 90000
	}
	return time.Duration(ms) * time.Millisecond
}

// sweepCrossOSCorrelation runs ONE background cross-OS correlation pass: it
// joins every recent-active session's captured process rows to that session via
// the SAME idempotent, confidence-guarded CorrelateCrossOS store seam the lazy
// dashboard/CLI trigger uses (so the two never fight — whichever runs first, the
// other is a no-op). It is what makes an unattributed process row VISIBLE to a
// session without a human opening the Processes drawer. Returns how many
// sessions were swept and how many rows were newly attributed. A per-session
// correlate error is logged at DEBUG and skipped, never fatal (fail-open); an
// active-session query error is returned to the caller. windowMinutes bounds the
// session set to recent activity.
func sweepCrossOSCorrelation(ctx context.Context, st *store.Store, windowMinutes int, logger *slog.Logger) (sessions, attributed int, err error) {
	ids, err := st.ActiveSessionIDs(ctx, windowMinutes)
	if err != nil {
		return 0, 0, err
	}
	for _, id := range ids {
		n, aerr := st.CorrelateCrossOS(ctx, id)
		if aerr != nil {
			if logger != nil {
				logger.Debug("process observability: correlation sweep — correlate failed", "session", id, "err", aerr)
			}
			continue
		}
		sessions++
		attributed += n
	}
	return sessions, attributed, nil
}

// actionSweepCursor is the per-session watermark sweepActionCorrelation uses
// to skip a session with nothing new since its last look (see
// store.SessionActionCursor). unlinked is the count of turn-unlinked
// process_runs (advances on INSERT or cross-OS UPDATE, self-heals after a
// linking pass); action is the highest run_command action id.
type actionSweepCursor struct {
	unlinked int64
	action   int64
}

// sweepActionCorrelation runs ONE background process→action correlation pass:
// for each recent-active session it drives the SAME idempotent
// store.CorrelateProcessActions seam the lazy Processes-drawer poll and
// `observer process tree` already trigger on demand (so they never fight —
// whichever runs first, the other is a no-op). It is the turn-level sibling
// of sweepCrossOSCorrelation: where that pass makes an unattributed process
// row VISIBLE to a session, this one links an already-session-attributed
// process to the run_command turn that spawned it, filling
// process_runs.action_id/turn_index without a human opening the drawer.
//
// cursors is a per-session watermark (the count of turn-unlinked process_runs
// + the run_command actions.id high-water mark, from store.SessionActionCursor)
// that the
// caller owns across ticks: a session whose watermark hasn't moved since the
// last sweep has no new processes or run_command actions, so the (relatively
// expensive) correlate pass is skipped — this keeps a marathon long-running
// session from being re-scanned every tick once it has converged. The
// watermark is updated even when a pass links nothing (e.g. only ambiguous
// residue remains), so that session isn't re-scanned until something actually
// changes. Entries for sessions no longer in the active window are pruned
// from cursors so the map cannot grow unbounded across a long daemon run.
//
// A per-session cursor or correlate error is logged at DEBUG and skipped,
// never fatal (fail-open); an active-session query error is returned to the
// caller. windowMinutes bounds the session set to recent activity.
func sweepActionCorrelation(ctx context.Context, st *store.Store, windowMinutes int, logger *slog.Logger, cursors map[string]actionSweepCursor) (sessions, linked int, err error) {
	ids, err := st.ActiveSessionIDs(ctx, windowMinutes)
	if err != nil {
		return 0, 0, err
	}
	active := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		active[id] = struct{}{}
	}
	for _, id := range ids {
		unlinkedRuns, actionMark, cerr := st.SessionActionCursor(ctx, id)
		if cerr != nil {
			if logger != nil {
				logger.Debug("process observability: action-correlation sweep — cursor failed", "session", id, "err", cerr)
			}
			continue
		}
		if prev, ok := cursors[id]; ok && prev.unlinked == unlinkedRuns && prev.action == actionMark {
			// Nothing new since the last sweep — skip the expensive pass.
			continue
		}
		n, lerr := st.CorrelateProcessActions(ctx, id)
		if lerr != nil {
			if logger != nil {
				logger.Debug("process observability: action-correlation sweep — correlate failed", "session", id, "err", lerr)
			}
			continue
		}
		// Store the POST-link unlinked count: the pass just linked n rows (moving
		// them out of the unlinked set) and added no actions, so the settled mark
		// is unlinkedRuns-n. Storing the pre-link count instead would make the
		// very next tick see the count drop as "changed" and re-run a no-op pass.
		// A concurrent capture INSERT between the read and here just makes the
		// real count higher than this next tick, correctly triggering one more
		// sweep.
		cursors[id] = actionSweepCursor{unlinked: unlinkedRuns - int64(n), action: actionMark}
		sessions++
		linked += n
	}
	for id := range cursors {
		if _, ok := active[id]; !ok {
			delete(cursors, id)
		}
	}
	return sessions, linked, nil
}

// launchSeedStaleTTL bounds how long an unconsumed launch seed survives. It
// must exceed the matcher's full window (back-skew + forward window); beyond
// that a seed can no longer be matched reliably and only lingers because its
// launcher died before retracting it (SIGKILL, crash).
const launchSeedStaleTTL = time.Hour

// consumeLaunchSeeds is the daemon half of launcher attribution (migration
// 086): it expires stale seeds, pairs pending seeds against recently ingested
// sessions with the pure processobs.MatchLaunchSeeds rule, and for each match
// writes the authoritative HIGH-confidence session_pid_bridge row before
// claiming (deleting) the seed.
//
// An EXISTING bridge row for a pid always wins: hook-written rows
// (claude-code/codex/cursor/hermes) stay byte-authoritative and the seed is
// merely claimed away. Fail-open throughout — any error degrades to the lazy
// CorrelateCrossOS path and is logged at DEBUG, never fatal to the sweep.
func consumeLaunchSeeds(ctx context.Context, st *store.Store, bridge *pidbridge.Store, logger *slog.Logger) {
	if _, err := st.ExpireStaleLaunchSeeds(ctx, launchSeedStaleTTL); err != nil && logger != nil {
		logger.Debug("process observability: launch-seed expiry failed", "err", err)
	}
	seeds, err := st.PendingLaunchSeeds(ctx, processobs.LaunchSeedBackSkew+processobs.LaunchSeedForwardWindow)
	if err != nil {
		if logger != nil {
			logger.Debug("process observability: launch-seed query failed", "err", err)
		}
		return
	}
	if len(seeds) == 0 {
		return
	}
	refs, err := st.RecentSessionRefsForLaunchMatch(ctx, 60)
	if err != nil {
		if logger != nil {
			logger.Debug("process observability: launch-seed session query failed", "err", err)
		}
		return
	}
	// The deterministic half (migration 091 / task 9f): resolve the terminal
	// run each dashboard-launched seed carries to the session that run was
	// observed to produce. A failure here is NON-FATAL by design — the matcher
	// simply falls back to the pre-091 heuristic for every seed, which is what
	// a bare-shell launch gets anyway.
	runSessions, rerr := st.LaunchSeedRunSessions(ctx, launchSeedRunIDs(seeds), termrun.MinLinkConfidence)
	if rerr != nil && logger != nil {
		logger.Debug("process observability: launch-seed run binding unavailable (falling back to heuristic matching)", "err", rerr)
	}
	matches := processobs.MatchLaunchSeeds(seeds, refs, nil, runSessions)
	byPID := make(map[int]processobs.LaunchSeed, len(seeds))
	for _, s := range seeds {
		byPID[s.PID] = s
	}
	for pid, sessionID := range matches {
		seed := byPID[pid]
		if _, ok, lerr := bridge.Lookup(ctx, pid); lerr == nil && ok {
			// An existing writer (hook ancestor-walk) owns this pid already.
			_, _ = st.ClaimLaunchSeed(ctx, pid)
			continue
		}
		if werr := bridge.Write(ctx, pidbridge.Entry{
			PID:       pid,
			SessionID: sessionID,
			Tool:      seed.Tool,
			CWD:       seed.CWD,
		}); werr != nil {
			if logger != nil {
				logger.Debug("process observability: launch-seed bridge write failed", "pid", pid, "err", werr)
			}
			continue
		}
		if _, cerr := st.ClaimLaunchSeed(ctx, pid); cerr != nil && logger != nil {
			logger.Debug("process observability: launch-seed claim failed", "pid", pid, "err", cerr)
		} else if logger != nil {
			logger.Debug("process observability: launch seed consumed",
				"pid", pid, "tool", seed.Tool, "session", sessionID)
		}
	}
}

// launchSeedRunIDs projects the non-empty terminal run ids off a seed batch.
// Most seeds carry none (every launch the daemon did not spawn), so this keeps
// the store seam from being asked about runs that do not exist.
func launchSeedRunIDs(seeds []processobs.LaunchSeed) []string {
	out := make([]string, 0, len(seeds))
	for _, s := range seeds {
		if s.RunID != "" {
			out = append(out, s.RunID)
		}
	}
	return out
}

// buildProcessScrubber maps the [observer.process] config into the pure
// FieldScrubber, injecting the existing secret scrubber as the redactor so
// argv/env/path previews never carry credentials (spec §12.2).
func buildProcessScrubber(pc config.ProcessConfig) *processobs.FieldScrubber {
	return &processobs.FieldScrubber{
		ArgvMode:        pc.Argv.Mode,
		MaxPreviewBytes: pc.Argv.MaxPreviewBytes,
		StoreArgCount:   pc.Argv.StoreArgCount,
		EnvEnabled:      pc.Env.Enabled,
		EnvAllowlist:    pc.Env.Allowlist,
		StorePathHash:   pc.Env.StorePathHash,
		Redact: func(s string) string {
			masked, _ := scrub.MaskSecrets(s, func(scrub.TypedFinding) bool { return true })
			return masked
		},
	}
}
