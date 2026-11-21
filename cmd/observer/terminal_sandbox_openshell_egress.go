//go:build !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BurntSushi/toml"
	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/ingest/otlp"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxnet"
	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// terminal_sandbox_openshell_egress.go is the openshell driver's egress and
// audit lane (lane O3, rule W4: one egress owner per run):
//
//   - the run's network input for the planner's network rule compiler
//     (openShellRunNet: the effective host list, the CIDRs, the proxy's
//     upstream hosts, the host's addresses and Observer's own binary), and
//     the egress file the daemon reads back to name a denial;
//   - the host helper's network profile: always the model-proxy forward
//     alone (openShellHelperEgress), so Observer's egress gateway never
//     runs beside OpenShell's proxy, whatever the tier;
//   - the launch refusal (openShellEgressRefusal): a host list the rules
//     cannot carry refuses at Create, and the internet tier is refused
//     unless the run's gateway exports OCSF events to the loopback
//     receiver (external mode, decision D3: Observer reads the user's
//     gateway config and never writes it, and names the keys when one is
//     missing; managed mode: Observer writes its private gateway's export
//     itself and reads that config back, lane OC);
//   - the daemon's loopback OCSF receiver (OTLP gRPC on
//     sandboxopenshell.OCSFReceiverListen, started beside the reaper while
//     openshell is listed), which maps each denied connection of a run's
//     box into lane N1's refusal audit through the relay's own refusal
//     hook (openShellRefusalSink), so the one receiver applies the one
//     flood bound and the one store seam.

// openShellEgressFile is the run's egress facts file in its run dir
// (sandboxopenshell.RunEgress, owner-only): written at compose, read by the
// daemon's OCSF receiver. Never anything the box reports.
const openShellEgressFile = "egress.json"

// openShellSandboxIDFile is the run's OpenShell sandbox id in its run dir,
// written by the host helper once the box answers `sandbox get`.
const openShellSandboxIDFile = "sandbox-id"

// openShellHelperEgress is the host helper's network profile for a run on
// tier: the model-proxy forward on every tier that has one, never the
// egress gateway (W4: OpenShell's proxy owns the internet tier's egress
// through the compiled network rules).
func openShellHelperEgress(tier sandbox.Egress) sandbox.Egress {
	if tier == sandbox.EgressInternet {
		return sandbox.EgressProxyOnly
	}
	return tier
}

// openShellHostAddrsFn lists the host's own addresses (a variable for
// tests).
var openShellHostAddrsFn = func() []netip.Addr {
	ips, err := sandboxnet.InterfaceIPs()
	if err != nil {
		return nil
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, a.Unmap())
		}
	}
	return out
}

// openShellRunNet is a run's network input and its egress facts, from the
// effective [terminal.sandbox] block (organization pins applied by
// config.Load), the proxy's upstream hosts and Observer's binary. The host
// list is parsed by sandboxnet's own validator first, the one the gateway
// rows use, so the two sides read one list.
func openShellRunNet(cfg config.TerminalSandboxConfig, tier vocab.Tier, providerHosts []string, observerBin string) (sandboxopenshell.NetInput, sandboxopenshell.RunEgress, error) {
	rules, err := agentEgressRules(cfg)
	if err != nil {
		return sandboxopenshell.NetInput{}, sandboxopenshell.RunEgress{}, sandboxRefusalError{msg: "terminal_sandbox: " + err.Error()}
	}
	in := sandboxopenshell.NetInput{
		Hosts: rules.Entries(), NoHost: cfg.PinnedNoEgressHost != "",
		AllowCIDRs: append([]string(nil), cfg.EgressAllowCIDRs...), ProviderHosts: append([]string(nil), providerHosts...),
		Binaries: []string{observerBin},
	}
	if tier == vocab.TierInternet {
		in.HostAddrs = openShellHostAddrsFn()
	}
	re := sandboxopenshell.RunEgress{
		Tier: tier, Hosts: in.Hosts, NoHost: in.NoHost, AllowCIDRs: in.AllowCIDRs,
		ProviderHosts: in.ProviderHosts, HostAddrs: in.HostAddrs,
	}
	return in, re, nil
}

// openShellOCSFExportAt is the ONE D3 probe of a gateway's OCSF export: it
// reads the OCSF keys of the gateway config at the path it is given (the
// platform file's reader, owner-checked, never written; a variable for
// tests). The path is an argument so a gateway Observer runs itself (lane
// O2's managed gateway) is probed through the same function with its own
// config file (audit finding O3-A9).
var openShellOCSFExportAt = openShellOCSFExport

// openShellOCSFConfigPathFn names the user's own gateway config (the file
// the package's user service reads), the one an external-mode launch
// probes. A variable for tests.
var openShellOCSFConfigPathFn = openShellUserGatewayConfigPath

// openShellOCSFGateway is what the D3 probe needs to know about the
// gateway a launch is pinned to: its mode, and in managed mode the private
// gateway's own config path (the probe's openShellManagedStep records it).
type openShellOCSFGateway struct {
	Mode              string
	ManagedConfigPath string
}

// openShellOCSFSourceRow is one row of the D3 probe's source table: which
// config file says whether the launch's gateway exports OCSF, and what the
// refusal tells the user to do when it does not.
type openShellOCSFSourceRow struct {
	name  string
	match func(g openShellOCSFGateway) bool
	path  func(g openShellOCSFGateway) string
	// fix is the refusal's remedy, after the export reason.
	fix string
}

// openShellOCSFSourceRows is walked top-down; the last row matches every
// gateway (lane OC). Managed mode reads the managed gateway's own
// config, which Observer writes with the export (openShellGatewayOCSFEndpoint),
// so it reads present unless the running gateway was started from an older
// config; external mode reads the user's own config, which Observer never
// writes (decision D3).
var openShellOCSFSourceRows = []openShellOCSFSourceRow{
	{
		name:  "managed: the private gateway's own config",
		match: func(g openShellOCSFGateway) bool { return g.Mode == sandboxopenshell.GatewayManaged },
		path:  func(g openShellOCSFGateway) string { return g.ManagedConfigPath },
		fix:   "Observer writes its private gateway's config with the export itself, so the running private gateway was started from an older config (or its config was changed by hand): it restarts with the export once no run holds it (`observer sandbox status` shows its state); launch again then",
	},
	{
		name:  "external: the user's own gateway config",
		match: func(openShellOCSFGateway) bool { return true },
		path:  func(openShellOCSFGateway) string { return openShellOCSFConfigPathFn() },
		fix:   "Observer never writes your gateway's config, so add the keys, restart the gateway, and launch again",
	},
}

// openShellOCSFSource returns the first source row matching g.
func openShellOCSFSource(g openShellOCSFGateway) openShellOCSFSourceRow {
	for _, r := range openShellOCSFSourceRows {
		if r.match(g) {
			return r
		}
	}
	return openShellOCSFSourceRows[len(openShellOCSFSourceRows)-1]
}

// openShellUserGatewayConfigPath is the user's own gateway config path
// ("" when the home is unknown).
func openShellUserGatewayConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return openShellGatewayConfigPath(os.Getenv, home)
}

// openShellManagedOCSFEndpoint is the OCSF export endpoint Observer writes
// into its own managed gateway's config (lane OC): the daemon's loopback
// receiver, which this lane starts beside the reaper whenever the row is
// listed. It is loopback by construction (RenderGatewayConfig refuses any
// other), and the receiver's own spelling (OCSFReceiverEndpoint) is the
// one value both the render and the D3 probe compare against.
func openShellManagedOCSFEndpoint() string { return sandboxopenshell.OCSFReceiverEndpoint() }

// openShellOCSFReceiverFactsFn gathers the receiver facts a launch is gated
// on (the platform file's reader; a variable for tests).
var openShellOCSFReceiverFactsFn = openShellOCSFReceiverFacts

// openShellGatewayOTLPTOML is the slice of the gateway's config the OCSF
// probe reads ([openshell.gateway.otlp] and its ocsf table), nothing else.
type openShellGatewayOTLPTOML struct {
	OpenShell struct {
		Gateway struct {
			OTLP struct {
				Endpoint string `toml:"endpoint"`
				OCSF     struct {
					Enabled  bool   `toml:"enabled"`
					Endpoint string `toml:"endpoint"`
				} `toml:"ocsf"`
			} `toml:"otlp"`
		} `toml:"gateway"`
	} `toml:"openshell"`
}

// openShellOCSFExportFrom decodes the gateway config's OCSF export keys;
// Read is false when the file could not be read or decoded. path is named
// in every reason.
func openShellOCSFExportFrom(path string, b []byte, readErr error) sandboxopenshell.OCSFExport {
	if readErr != nil {
		return sandboxopenshell.OCSFExport{Path: path}
	}
	var c openShellGatewayOTLPTOML
	if _, err := toml.Decode(string(b), &c); err != nil {
		return sandboxopenshell.OCSFExport{Path: path}
	}
	o := c.OpenShell.Gateway.OTLP
	return sandboxopenshell.OCSFExport{Read: true, Enabled: o.OCSF.Enabled, Endpoint: o.OCSF.Endpoint, OTLPEndpoint: o.Endpoint, Path: path}
}

// openShellEgressRefusal checks a launch's egress before anything is
// prepared: the network rules must compile for the tier (a host list they
// cannot carry, a host alias, a provider host or no list on internet
// refuses), and the internet tier, which the row claims is audited, needs
// both sides of the audit: the gateway's OCSF export pointed at the
// receiver (D3, read from the config of the gateway the launch is pinned
// to: the managed gateway's own in managed mode, the user's own, never
// written, in external mode; openShellOCSFSourceRows), and the receiver
// itself actually listening and this daemon's own, with its refusal audit
// wired (audit finding O3-A1: a config file alone never says whether
// anything receives). It returns the posture note's egress fields.
func openShellEgressRefusal(cfg config.TerminalSandboxConfig, tier vocab.Tier, providerHosts []string, observerBin, stateDir string, gw openShellOCSFGateway) (string, error) {
	in, _, err := openShellRunNet(cfg, tier, providerHosts, observerBin)
	if err != nil {
		return "", err
	}
	rules, err := sandboxopenshell.CompileNetRules(tier, in)
	if err != nil {
		return "", sandboxRefusalError{msg: "terminal_sandbox: " + err.Error()}
	}
	src := openShellOCSFSource(gw)
	export, why := sandboxopenshell.ClassifyOCSFExport(openShellOCSFExportAt(src.path(gw)), sandboxopenshell.OCSFReceiverEndpoint())
	recv, rwhy := sandboxopenshell.ClassifyOCSFReceiver(openShellOCSFReceiverFactsFn(stateDir))
	if tier == vocab.TierInternet {
		if export != sandboxopenshell.OCSFExportPresent {
			return "", sandboxRefusalError{msg: fmt.Sprintf("terminal_sandbox: the openshell row audits every refused connection on the internet tier, and %s; %s (or use egress = %q)", why, src.fix, vocab.TierProxyOnly)}
		}
		if recv != sandboxopenshell.OCSFReceiverListening {
			return "", sandboxRefusalError{msg: fmt.Sprintf("terminal_sandbox: the openshell row audits every refused connection on the internet tier, and its OCSF receiver is %s: %s (or use egress = %q)", recv, rwhy, vocab.TierProxyOnly)}
		}
	}
	hosts := 0
	for _, r := range rules {
		hosts += len(r.Endpoints)
	}
	return fmt.Sprintf(" network_rules=%d ocsf_export=%s ocsf_receiver=%s", hosts, export, recv), nil
}

// openShellOCSFMarkerName is the daemon's receiver marker in the row's
// state dir: written (owner-only, replaced atomically) only while this
// daemon holds the receiver's listener, removed when it stops. A launching
// process reads it and checks, through the kernel's socket table, that the
// process it names really holds the listening socket.
const openShellOCSFMarkerName = "ocsf-receiver.json"

// openShellOCSFMarker is the marker's body.
type openShellOCSFMarker struct {
	V         int    `json:"v"`
	PID       int    `json:"pid"`
	Addr      string `json:"addr"`
	SinkReady bool   `json:"sink_ready"`
}

// openShellWriteEgress writes the run's egress facts into its run dir.
func openShellWriteEgress(runDir string, re sandboxopenshell.RunEgress) error {
	b, err := json.Marshal(re)
	if err != nil {
		return fmt.Errorf("terminal_sandbox: openshell egress file: %w", err)
	}
	return openShellWriteExcl(filepath.Join(runDir, openShellEgressFile), b)
}

// openShellReadSmall reads a small file of a run dir (no symlink).
func openShellReadSmall(p string, limit int64) ([]byte, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > limit {
		return nil, fmt.Errorf("%s is not a small regular file", p)
	}
	return os.ReadFile(p) //nolint:gosec // G304: a file of a run dir the daemon made
}

// openShellRefusalSink is the relay's refusal hook (lane N1's receiver),
// set when the daemon's relay starts serving; nil drops.
var openShellRefusalSink atomic.Pointer[func(sandboxrelayd.RunRecord, sandboxrelay.EgressRefusalReport)]

func init() {
	sandboxEgressRefusalSources = append(sandboxEgressRefusalSources, func(sink func(sandboxrelayd.RunRecord, sandboxrelay.EgressRefusalReport)) {
		if sink == nil {
			openShellRefusalSink.Store(nil)
		} else {
			openShellRefusalSink.Store(&sink)
		}
		processOpenShellOCSF.sinkChanged(sink != nil)
	})
	sandboxEgressRefusalDropSources = append(sandboxEgressRefusalDropSources, func(drop func(sandboxrelayd.RunRecord, egressRefusalDropCount)) {
		if drop == nil {
			openShellRefusalDropSink.Store(nil)
		} else {
			openShellRefusalDropSink.Store(&drop)
		}
	})
}

// openShellRefusalDropSink is the refusal audit's dropped-count hook (audit
// finding O3-W2), set beside openShellRefusalSink; nil writes nothing.
var openShellRefusalDropSink atomic.Pointer[func(sandboxrelayd.RunRecord, egressRefusalDropCount)]

// OCSF ingest bounds.
const (
	// openShellOCSFRescan is the least time between two scans of the run
	// dirs for an id the receiver does not know yet.
	openShellOCSFRescan = time.Second
	// openShellOCSFSeen bounds the metadata uids remembered for dedupe
	// (OpenShell delivers at least once).
	openShellOCSFSeen = 4096
	// openShellOCSFMaxRecv bounds one OTLP message (OpenShell batches at
	// most 1 MiB).
	openShellOCSFMaxRecv = 4 << 20
	// openShellOCSFPerRunPerSecond bounds the denials of ONE known run the
	// handler maps and hands on in one wall-clock second. The bound is per
	// run, after parsing, so neither junk exports nor another run's volume
	// can starve a run's denials (audit finding O3-V1); the excess is
	// counted per run, logged as one summary line and written to the
	// run's dropped count beside its refusal rows (audit finding O3-W2).
	openShellOCSFPerRunPerSecond = 100
	// The hold for denials of a box whose id is not recorded yet (audit
	// findings O3-A7, O3-V2, O3-W1, OC-A1): bounded per claimed box id and
	// in total, never per connection (a local sender takes a new source
	// port for every connection, so a connection bound bounds nothing),
	// and never evicting an entry for a denial of an id first seen after
	// its own (see insertLocked).
	openShellOCSFHoldTotal  = 512
	openShellOCSFHoldPerBox = 16
	// openShellOCSFPendingTTL is how long a held denial is kept.
	openShellOCSFPendingTTL = 15 * time.Second
	// openShellOCSFRateKeys bounds the rate windows kept; past it the
	// windows of earlier seconds are pruned.
	openShellOCSFRateKeys = 4096
	// openShellOCSFDroppedIDs bounds the claimed box ids whose held
	// denials were dropped, remembered for openShellOCSFDroppedIDTTL so a
	// drop is charged to the run once its id is recorded (audit finding
	// O3-W2). Past the bound the claimed id is not remembered, and the drop
	// is counted as uncertain against every run then waiting for its box
	// id (audit finding OC-A1): a real box's denial can only be such a
	// run's, so its run never reads as complete.
	openShellOCSFDroppedIDs   = 4096
	openShellOCSFDroppedIDTTL = 2 * time.Minute
	// openShellOCSFRecordKeep is how long the box id of a run no longer
	// named, and a run's relay record, are kept after they were last seen,
	// so drops summarized after a run ended still land under the run id
	// its rows carry (audit finding OC-A3); openShellOCSFRecords bounds
	// the records kept.
	openShellOCSFRecordKeep = 10 * time.Minute
	openShellOCSFRecords    = 1024
)

// openShellOCSFRetry is how long the handler waits before it looks again
// for the box of a held denial (a variable for tests).
var openShellOCSFRetry = 2 * time.Second

// openShellOCSFSummaryEvery is how often the dropped counts are logged and
// written (a variable for tests).
var openShellOCSFSummaryEvery = time.Minute

// openShellOCSFRunHeld reports whether a run dir is held by its host
// helper, so a run dir with no box id yet is a run waiting for its box (a
// variable for tests; off Linux nothing is held).
var openShellOCSFRunHeld = openShellRunHeld

// openShellOCSFRun is a known box: its run id and egress facts.
type openShellOCSFRun struct {
	runID  string
	egress sandboxopenshell.RunEgress
}

// openShellRateWin is one key's count in one wall-clock second.
type openShellRateWin struct {
	sec int64
	n   int
}

// openShellDroppedID is the drops of one claimed box id not known yet: n
// in all, win of them counted since the last summary (audit finding
// OC-A8), the last at last.
type openShellDroppedID struct {
	n, win int
	last   time.Time
}

// openShellOCSFEnded is a box id the run dirs no longer name, kept for the
// summary.
type openShellOCSFEnded struct {
	run openShellOCSFRun
	at  time.Time
}

// openShellOCSFRecord is a run's relay record as last read.
type openShellOCSFRecord struct {
	rec sandboxrelayd.RunRecord
	at  time.Time
}

// openShellOCSFIngest is the receiver's handler state: the box id to run
// map, the dedupe window, the per-run rate windows, the dropped counts,
// the denials held for a box not known yet and which runs already logged
// their first event. One per receiver.
type openShellOCSFIngest struct {
	stateDir, observerDir string
	now                   func() time.Time
	sink                  func() func(sandboxrelayd.RunRecord, sandboxrelay.EgressRefusalReport)
	// dropSink writes a run's dropped-denial counts beside its refusal
	// rows (nil: not written; audit finding O3-W2).
	dropSink func() func(sandboxrelayd.RunRecord, egressRefusalDropCount)
	logger   *slog.Logger

	mu       sync.Mutex
	boxes    map[string]openShellOCSFRun
	lastScan time.Time
	// pendingRuns are the runs whose host helper holds their run dir and
	// whose box id is not recorded yet, as of the last scan; ended the box
	// ids a scan no longer names, and records the relay records last read,
	// by run (audit finding OC-A3).
	pendingRuns []string
	ended       map[string]openShellOCSFEnded
	records     map[string]openShellOCSFRecord
	seen        map[string]struct{}
	order       []string
	pending     []openShellOCSFPending
	retrying    bool
	runRate     map[string]*openShellRateWin
	// dropped counts each run's denials dropped since the last summary
	// (its rate bound, or held denials of its box dropped before its id was
	// recorded); uncertain the drops that may be each run's (audit finding
	// OC-A1); unattributed the dropped records of box ids no run names
	// (yet), and droppedIDs those ids, charged to their run once it does.
	dropped      map[string]int
	uncertain    map[string]int
	unattributed int
	droppedIDs   map[string]openShellDroppedID
	summaryArmed bool
	firstLogged  map[string]bool
}

// openShellOCSFPending is a denial held for a box the run dirs did not name
// yet (the host helper records the id once the box answers).
type openShellOCSFPending struct {
	d     sandboxopenshell.OCSFDenial
	first time.Time
}

func newOpenShellOCSFIngest(stateDir, observerDir string, logger *slog.Logger) *openShellOCSFIngest {
	return &openShellOCSFIngest{
		stateDir: stateDir, observerDir: observerDir, now: time.Now, logger: logger,
		sink: func() func(sandboxrelayd.RunRecord, sandboxrelay.EgressRefusalReport) {
			if p := openShellRefusalSink.Load(); p != nil {
				return *p
			}
			return nil
		},
		dropSink: func() func(sandboxrelayd.RunRecord, egressRefusalDropCount) {
			if p := openShellRefusalDropSink.Load(); p != nil {
				return *p
			}
			return nil
		},
		boxes: map[string]openShellOCSFRun{}, seen: map[string]struct{}{},
		ended: map[string]openShellOCSFEnded{}, records: map[string]openShellOCSFRecord{},
		runRate: map[string]*openShellRateWin{},
		dropped: map[string]int{}, uncertain: map[string]int{}, droppedIDs: map[string]openShellDroppedID{}, firstLogged: map[string]bool{},
	}
}

// allowLocked counts one event for key in the current second and reports
// whether it is within limit. g.mu is held.
func (g *openShellOCSFIngest) allowLocked(m map[string]*openShellRateWin, key string, limit int) bool {
	sec := g.now().Unix()
	w := m[key]
	if w == nil {
		if len(m) >= openShellOCSFRateKeys {
			for k, o := range m {
				if o.sec < sec {
					delete(m, k)
				}
			}
		}
		w = &openShellRateWin{sec: sec}
		m[key] = w
	}
	if w.sec != sec {
		w.sec, w.n = sec, 0
	}
	w.n++
	return w.n <= limit
}

// handle is the receiver's logs handler. Every record is parsed first (a
// bounded body); a denial of a box a run dir names is handed on within its
// run's own rate bound, and a denial of a box not named yet is held within
// the hold's bounds. Nothing is limited before parsing, so empty or junk
// exports cost no real denial. It never fails the export.
func (g *openShellOCSFIngest) handle(_ context.Context, req *collogspb.ExportLogsServiceRequest) error {
	if g.sink() == nil {
		return nil
	}
	for _, rl := range req.GetResourceLogs() {
		res := openShellOTLPAttrs(rl.GetResource().GetAttributes())
		for _, sl := range rl.GetScopeLogs() {
			for _, lr := range sl.GetLogRecords() {
				rec := sandboxopenshell.OCSFRecord{
					Body: lr.GetBody().GetStringValue(), Attrs: openShellOTLPAttrs(lr.GetAttributes()), Resource: res,
				}
				if ns := lr.GetTimeUnixNano(); ns > 0 && ns < 1<<62 {
					rec.Time = time.Unix(0, int64(ns)).UTC() //nolint:gosec // G115: bounded above
				}
				d, kind := sandboxopenshell.ParseOCSFRecord(rec)
				if kind == sandboxopenshell.OCSFDeniedUnnamed {
					g.countUnnamed(d)
					continue
				}
				if kind != sandboxopenshell.OCSFDenied {
					continue
				}
				if run, ok := g.box(d.SandboxID, false); ok {
					g.deliverBounded(d, run)
					continue
				}
				g.hold(d)
			}
		}
	}
	return nil
}

// countUnnamed counts a real denial whose destination name cannot be
// recorded (a wildcard, an underscore, a non-printable name: the parser's
// OCSFDeniedUnnamed) as its run's dropped denial, so the run's audit says
// it is incomplete instead of the denial vanishing (O5 audit finding
// O5-A6). The name never reaches the refusal page, so no wildcard grant is
// offered. A box no run dir names yet is counted the way a dropped held
// record is (countDropLocked). A uid seen before is not counted twice.
func (g *openShellOCSFIngest) countUnnamed(d sandboxopenshell.OCSFDenial) {
	if g.duplicate(d.UID) {
		return
	}
	run, known := g.box(d.SandboxID, false)
	g.mu.Lock()
	defer g.mu.Unlock()
	if known {
		g.dropped[run.runID]++
		g.armSummaryLocked()
		return
	}
	g.countDropLocked(d.SandboxID)
}

// deliverBounded hands a denial of a known run on within the run's own
// per-second bound, counting the excess for the summary.
func (g *openShellOCSFIngest) deliverBounded(d sandboxopenshell.OCSFDenial, run openShellOCSFRun) {
	g.mu.Lock()
	within := g.allowLocked(g.runRate, run.runID, openShellOCSFPerRunPerSecond)
	if !within {
		g.dropped[run.runID]++
		g.armSummaryLocked()
	}
	g.mu.Unlock()
	if within {
		g.deliver(d, run)
	}
}

// armSummaryLocked schedules the dropped-count summary. g.mu is held.
func (g *openShellOCSFIngest) armSummaryLocked() {
	if g.summaryArmed {
		return
	}
	g.summaryArmed = true
	time.AfterFunc(openShellOCSFSummaryEvery, g.summarize)
}

// countDropLocked counts one dropped record of a box id no run names yet:
// unattributed, and remembered under its claimed id (bounded) so the
// summary charges it to the run whose box it turns out to be. When the
// table of claimed ids is full the drop is counted as uncertain against
// every run waiting for its box id (audit finding OC-A1), rescanning the
// run dirs first when the last scan is older than openShellOCSFRescan.
// g.mu is held.
func (g *openShellOCSFIngest) countDropLocked(id string) {
	g.unattributed++
	now := g.now()
	if e, ok := g.droppedIDs[id]; ok || len(g.droppedIDs) < openShellOCSFDroppedIDs {
		e.n++
		e.win++
		e.last = now
		g.droppedIDs[id] = e
	} else {
		if now.Sub(g.lastScan) >= openShellOCSFRescan {
			g.rescanLocked(now)
		}
		for _, run := range g.pendingRuns {
			g.uncertain[run]++
		}
	}
	g.armSummaryLocked()
}

// rescanLocked scans the run dirs again: the box id map, the runs waiting
// for their box id, the box ids no longer named (kept openShellOCSFRecordKeep
// for the summary) and the relay record of each run not read yet; entries
// past openShellOCSFRecordKeep go. g.mu is held.
func (g *openShellOCSFIngest) rescanLocked(now time.Time) {
	g.lastScan = now
	boxes, pending := openShellScanRuns(g.stateDir)
	for id, r := range g.boxes {
		if _, ok := boxes[id]; !ok {
			g.ended[id] = openShellOCSFEnded{run: r, at: now}
		}
	}
	for id, e := range g.ended {
		if _, ok := boxes[id]; ok || now.Sub(e.at) > openShellOCSFRecordKeep {
			delete(g.ended, id)
		}
	}
	g.boxes, g.pendingRuns = boxes, pending
	for run, e := range g.records {
		if now.Sub(e.at) > openShellOCSFRecordKeep {
			delete(g.records, run)
		}
	}
	runs := append([]string{}, pending...)
	for _, r := range boxes {
		runs = append(runs, r.runID)
	}
	for _, run := range runs {
		if e, ok := g.records[run]; ok {
			e.at = now
			g.records[run] = e
		} else if len(g.records) < openShellOCSFRecords {
			if rr, err := sandboxrelayd.ReadRun(g.observerDir, run); err == nil {
				g.records[run] = openShellOCSFRecord{rec: rr, at: now}
			}
		}
	}
}

// runRecord returns a run's relay record: read now, else the one last read
// (the host helper removes it when the run ends; audit finding OC-A3), else
// one naming only the run. A record read is kept for later.
func (g *openShellOCSFIngest) runRecord(runID string) sandboxrelayd.RunRecord {
	rr, err := sandboxrelayd.ReadRun(g.observerDir, runID)
	g.mu.Lock()
	defer g.mu.Unlock()
	if err == nil {
		if _, ok := g.records[runID]; ok || len(g.records) < openShellOCSFRecords {
			g.records[runID] = openShellOCSFRecord{rec: rr, at: g.now()}
		}
		return rr
	}
	if e, ok := g.records[runID]; ok {
		return e.rec
	}
	return sandboxrelayd.RunRecord{RunID: runID}
}

// summarize charges the drops of box ids now recorded (or recorded and
// since ended) to their runs, then logs one line per run whose denials were
// dropped since the last summary and one for the records still
// unattributed, and writes each run's counts to the refusal audit beside
// its rows (audit findings O3-W2, OC-A1, OC-A3), so a run whose rows look
// complete is not silently incomplete.
func (g *openShellOCSFIngest) summarize() {
	g.mu.Lock()
	now := g.now()
	g.rescanLocked(now)
	for id, e := range g.droppedIDs {
		run, ok := g.boxes[id]
		if !ok {
			var en openShellOCSFEnded
			en, ok = g.ended[id]
			run = en.run
		}
		switch {
		case ok:
			g.dropped[run.runID] += e.n
			// Only this window's part was counted unattributed since the
			// last summary (audit finding OC-A8).
			g.unattributed -= e.win
			delete(g.droppedIDs, id)
		case now.Sub(e.last) > openShellOCSFDroppedIDTTL:
			delete(g.droppedIDs, id)
		default:
			e.win = 0
			g.droppedIDs[id] = e
		}
	}
	dropped, uncertain, unattributed := g.dropped, g.uncertain, g.unattributed
	g.dropped, g.uncertain, g.unattributed, g.summaryArmed = map[string]int{}, map[string]int{}, 0, false
	if len(g.droppedIDs) > 0 {
		// Ids not recorded yet may still be: look again next window.
		g.armSummaryLocked()
	}
	g.mu.Unlock()
	set := map[string]bool{}
	for r := range dropped {
		set[r] = true
	}
	for r := range uncertain {
		set[r] = true
	}
	runs := make([]string, 0, len(set))
	for r := range set {
		runs = append(runs, r)
	}
	sort.Strings(runs)
	if write := g.dropSink(); write != nil {
		for _, r := range runs {
			write(g.runRecord(r), egressRefusalDropCount{Dropped: dropped[r], Uncertain: uncertain[r]})
		}
	}
	if g.logger == nil {
		return
	}
	for _, r := range runs {
		g.logger.Warn("terminal_sandbox: openshell: OCSF denials of the run were dropped (its rate bound, or held before its box id was recorded); not in the refusal audit, counted beside its rows", "run", r, "dropped", dropped[r], "uncertain", uncertain[r], "bound_per_second", openShellOCSFPerRunPerSecond, "window", openShellOCSFSummaryEvery.String())
	}
	if unattributed > 0 {
		g.logger.Warn("terminal_sandbox: openshell: OCSF records for box ids no run names were dropped (the hold was full)", "dropped", unattributed, "window", openShellOCSFSummaryEvery.String())
	}
}

// deliver hands one denial of a known run to the relay's refusal hook. The
// first event of each run is logged with the exporting gateway's name and
// the run's pinned gateway: a mismatch is recorded, never dropped, because
// the CLI's registered name and the gateway's own name are not shown equal
// (audit finding O3-V3; live register O3-L1 records whether they match). A
// metadata uid is consumed only here, once the box is known (O3-A7).
func (g *openShellOCSFIngest) deliver(d sandboxopenshell.OCSFDenial, run openShellOCSFRun) {
	sink := g.sink()
	if sink == nil {
		return
	}
	match := sandboxopenshell.OCSFGatewayMatches(d.Gateway, run.egress.Gateway)
	g.mu.Lock()
	first := !g.firstLogged[run.runID]
	g.firstLogged[run.runID] = true
	g.mu.Unlock()
	if first && g.logger != nil {
		lvl := slog.LevelInfo
		if !match {
			lvl = slog.LevelWarn
		}
		g.logger.Log(context.Background(), lvl, "terminal_sandbox: openshell: first OCSF event of the run", "run", run.runID, "event_gateway", d.Gateway, "run_gateway", run.egress.Gateway, "gateway_names_match", match)
	}
	if g.duplicate(d.UID) {
		return
	}
	rule, key, _ := sandboxopenshell.MapOCSFDenial(d, run.egress)
	at := d.At
	if at.IsZero() {
		at = g.now()
	}
	sink(g.runRecord(run.runID), sandboxrelay.EgressRefusalReport{V: sandboxrelay.EgressRefusalVersion, Host: d.Host, Port: d.Port, Rule: rule, Key: key, AtMS: at.UnixMilli()})
}

// hold keeps a denial of a box not named yet and schedules a look again
// (insertLocked's bounds; a drop is counted).
func (g *openShellOCSFIngest) hold(d sandboxopenshell.OCSFDenial) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.insertLocked(openShellOCSFPending{d: d, first: g.now()})
}

// insertLocked puts p into the hold within its bounds, so a flood of
// made-up box ids, from one connection or from many, cannot push out a
// real box's early denial (audit findings O3-V2, O3-W1, OC-A1):
//   - per claimed box id: at most openShellOCSFHoldPerBox; past it p is
//     dropped (a real box's first few are kept);
//   - in total: at most openShellOCSFHoldTotal; past it an entry goes only
//     from an id first seen AFTER p's own: the newest entry of the fullest
//     such id (on a tie the id first seen most recently). When no held id
//     was first seen after p's, p itself is dropped. So a held denial is
//     never pushed out for a denial of an id first seen after its own: a
//     flood that starts after a real box's denials cannot evict any of
//     them, and an earlier id may still grow to its per-id bound by
//     evicting later ones.
//
// Every drop is counted (countDropLocked). g.mu is held.
func (g *openShellOCSFIngest) insertLocked(p openShellOCSFPending) {
	id := p.d.SandboxID
	type idState struct {
		n           int
		firstSeen   time.Time
		newest      int // index into g.pending
		newestFirst time.Time
	}
	ids := map[string]*idState{}
	for i, e := range g.pending {
		s := ids[e.d.SandboxID]
		if s == nil {
			s = &idState{firstSeen: e.first, newest: i, newestFirst: e.first}
			ids[e.d.SandboxID] = s
		}
		s.n++
		if e.first.Before(s.firstSeen) {
			s.firstSeen = e.first
		}
		if !e.first.Before(s.newestFirst) {
			s.newest, s.newestFirst = i, e.first
		}
	}
	pFirst := p.first
	if s := ids[id]; s != nil {
		if s.n >= openShellOCSFHoldPerBox {
			g.countDropLocked(id)
			return
		}
		if s.firstSeen.Before(pFirst) {
			pFirst = s.firstSeen
		}
	}
	if len(g.pending) >= openShellOCSFHoldTotal {
		victim := ""
		for vid, s := range ids {
			if vid == id || !s.firstSeen.After(pFirst) {
				continue // never an id first seen no later than p's own
			}
			v := ids[victim]
			if v == nil || s.n > v.n || (s.n == v.n && (s.firstSeen.After(v.firstSeen) || (s.firstSeen.Equal(v.firstSeen) && vid > victim))) {
				victim = vid
			}
		}
		if victim == "" {
			g.countDropLocked(id)
			return
		}
		vs := ids[victim]
		g.countDropLocked(victim)
		g.pending = append(g.pending[:vs.newest], g.pending[vs.newest+1:]...)
	}
	g.pending = append(g.pending, p)
	if !g.retrying {
		g.retrying = true
		time.AfterFunc(openShellOCSFRetry, g.retry)
	}
}

// retry rescans the run dirs and delivers every held denial whose box is
// now named (within its run's bound); one older than
// openShellOCSFPendingTTL is dropped, and counted.
func (g *openShellOCSFIngest) retry() {
	g.mu.Lock()
	held := g.pending
	g.pending, g.retrying = nil, false
	g.mu.Unlock()
	now := g.now()
	for i, p := range held {
		run, ok := g.box(p.d.SandboxID, i == 0)
		switch {
		case ok:
			g.deliverBounded(p.d, run)
		case now.Sub(p.first) < openShellOCSFPendingTTL:
			g.rehold(p)
		default:
			g.mu.Lock()
			g.countDropLocked(p.d.SandboxID)
			g.mu.Unlock()
		}
	}
}

// rehold puts an entry back as it was (its age kept), through the same
// bounds as hold: a hold that filled meanwhile evicts by insertLocked's
// rule, and the drop is counted (audit finding O3-W1).
func (g *openShellOCSFIngest) rehold(p openShellOCSFPending) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.insertLocked(p)
}

// duplicate reports whether uid was seen (and remembers it).
func (g *openShellOCSFIngest) duplicate(uid string) bool {
	if uid == "" {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.seen[uid]; ok {
		return true
	}
	g.seen[uid] = struct{}{}
	g.order = append(g.order, uid)
	if len(g.order) > openShellOCSFSeen {
		delete(g.seen, g.order[0])
		g.order = g.order[1:]
	}
	return false
}

// box returns the run of a box id, scanning the run dirs again for an id
// it does not know: at most once per openShellOCSFRescan, or at once when
// force (a retry pass).
func (g *openShellOCSFIngest) box(id string, force bool) (openShellOCSFRun, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if r, ok := g.boxes[id]; ok {
		return r, true
	}
	if now := g.now(); force || now.Sub(g.lastScan) >= openShellOCSFRescan {
		g.rescanLocked(now)
	}
	r, ok := g.boxes[id]
	return r, ok
}

// openShellScanRuns maps every run dir's recorded box id to its run, and
// lists the runs whose host helper holds their dir but whose box id is not
// recorded yet (pending, sorted).
func openShellScanRuns(stateDir string) (map[string]openShellOCSFRun, []string) {
	out := map[string]openShellOCSFRun{}
	var pending []string
	root := filepath.Dir(openShellRunDir(stateDir, "x"))
	ents, err := os.ReadDir(root)
	if err != nil {
		return out, nil
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		b, err := openShellReadSmall(filepath.Join(dir, openShellSandboxIDFile), 256)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && openShellOCSFRunHeld(dir) {
				pending = append(pending, e.Name())
			}
			continue
		}
		id := strings.TrimSpace(string(b))
		if !sandboxopenshell.ValidSandboxID(id) {
			continue
		}
		run := openShellOCSFRun{runID: e.Name()}
		if eb, err := openShellReadSmall(filepath.Join(dir, openShellEgressFile), 1<<20); err == nil {
			_ = json.Unmarshal(eb, &run.egress)
		}
		if !run.egress.Tier.Valid() {
			// No egress file: the strictest reading, every denial is
			// tier-none.
			run.egress.Tier = vocab.TierNone
		}
		out[id] = run
	}
	return out, pending
}

// openShellOTLPAttrs flattens OTLP attributes to strings (string, integer
// and boolean values; anything else is left out).
func openShellOTLPAttrs(kvs []*commonpb.KeyValue) map[string]string {
	out := make(map[string]string, len(kvs))
	for _, kv := range kvs {
		v := kv.GetValue()
		switch x := v.GetValue().(type) {
		case *commonpb.AnyValue_StringValue:
			out[kv.GetKey()] = x.StringValue
		case *commonpb.AnyValue_IntValue:
			out[kv.GetKey()] = fmt.Sprint(x.IntValue)
		case *commonpb.AnyValue_BoolValue:
			out[kv.GetKey()] = fmt.Sprint(x.BoolValue)
		}
	}
	return out
}

// openShellOCSFListen is the receiver's address (a variable for tests).
var openShellOCSFListen = sandboxopenshell.OCSFReceiverListen

// openShellOCSFReceiverT is the daemon's one OCSF receiver and the owner
// of its marker file.
type openShellOCSFReceiverT struct {
	mu        sync.Mutex
	recv      *otlp.Receiver
	stateDir  string
	sinkReady bool
	logger    *slog.Logger
}

var processOpenShellOCSF = &openShellOCSFReceiverT{}

// openShellStartOCSFReceiver starts the receiver for stateDir (a no-op when
// it already runs for it) and writes the marker launches are gated on. A
// bind that fails (the port is taken) is logged and leaves no marker, so an
// internet launch is refused with the reason (audit finding O3-A1).
func openShellStartOCSFReceiver(stateDir, observerDir string, logger *slog.Logger) bool {
	rc := processOpenShellOCSF
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.recv != nil && rc.stateDir == stateDir {
		return false
	}
	rc.stopLocked()
	if logger == nil {
		logger = slog.Default()
	}
	rc.logger = logger
	g := newOpenShellOCSFIngest(stateDir, observerDir, logger)
	recv, err := otlp.New(otlp.Options{
		GRPCAddr: openShellOCSFListen, Handler: g.handle, Logger: logger,
		GRPCMaxRecvBytes: openShellOCSFMaxRecv,
	})
	if err != nil {
		logger.Warn("terminal_sandbox: openshell: the OCSF receiver cannot listen; internet-tier launches are refused and refused connections of OpenShell boxes are not recorded", "addr", openShellOCSFListen, "err", err)
		return false
	}
	recv.Start()
	rc.recv, rc.stateDir = recv, stateDir
	rc.syncMarkerLocked()
	logger.Info("terminal_sandbox: openshell: the OCSF receiver is listening", "addr", recv.GRPCAddr(), "endpoint", sandboxopenshell.OCSFReceiverEndpoint())
	return true
}

// openShellStopOCSFReceiver stops the receiver and removes its marker.
func openShellStopOCSFReceiver() {
	rc := processOpenShellOCSF
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.stopLocked()
}

// sinkChanged records whether the relay's refusal hook is wired and
// rewrites the marker.
func (rc *openShellOCSFReceiverT) sinkChanged(ready bool) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.sinkReady = ready
	rc.syncMarkerLocked()
}

// syncMarkerLocked writes the marker while the receiver listens (pid,
// address, whether the refusal audit is wired), owner-only, replaced by a
// rename so a reader never sees half a file.
func (rc *openShellOCSFReceiverT) syncMarkerLocked() {
	if rc.recv == nil || rc.stateDir == "" {
		return
	}
	b, err := json.Marshal(openShellOCSFMarker{V: 1, PID: os.Getpid(), Addr: rc.recv.GRPCAddr(), SinkReady: rc.sinkReady})
	if err != nil {
		return
	}
	if err := os.MkdirAll(rc.stateDir, 0o700); err != nil {
		return
	}
	p := filepath.Join(rc.stateDir, openShellOCSFMarkerName)
	tmp := p + ".tmp"
	_ = os.Remove(tmp)
	if err := openShellWriteExcl(tmp, b); err != nil {
		return
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		if rc.logger != nil {
			rc.logger.Warn("terminal_sandbox: openshell: writing the OCSF receiver marker", "err", err)
		}
	}
}

func (rc *openShellOCSFReceiverT) stopLocked() {
	if rc.recv == nil {
		return
	}
	_ = os.Remove(filepath.Join(rc.stateDir, openShellOCSFMarkerName))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = rc.recv.Shutdown(ctx)
	rc.recv, rc.stateDir = nil, ""
}

// openShellReadOCSFMarker reads the daemon's receiver marker in stateDir.
func openShellReadOCSFMarker(stateDir string) (openShellOCSFMarker, bool) {
	b, err := openShellReadSmall(filepath.Join(stateDir, openShellOCSFMarkerName), 4096)
	if err != nil {
		return openShellOCSFMarker{}, false
	}
	var m openShellOCSFMarker
	if json.Unmarshal(b, &m) != nil || m.V != 1 || m.PID <= 0 {
		return openShellOCSFMarker{}, false
	}
	return m, true
}

// openShellBoxIDPoll is how often the host helper asks for its box's id (a
// variable for tests).
var openShellBoxIDPoll = time.Second

// errOpenShellBoxIDGaveUp says the box's id was not read before the
// recorder's deadline (the box still runs): its denials go unrecorded.
var errOpenShellBoxIDGaveUp = errors.New("the box's OpenShell id was not read in time")

// openShellBoxIDGetter is the host helper's box id question: `sandbox get`
// about the run's pinned target through openShellRunAt, so a managed run's
// get carries the private gateway's registry (its config home) and never
// asks the user's own default gateway (lane OC). Nil when the plan cannot
// render the command.
func openShellBoxIDGetter(runner *extrun.Runner, pf openShellPlanFile) func(ctx context.Context) ([]byte, error) {
	argv, err := sandboxopenshell.GetArgv(pf.Target, pf.Name)
	if err != nil {
		return nil
	}
	return func(ctx context.Context) ([]byte, error) {
		res := openShellRunAt(ctx, runner, pf.Target, openShellCLISpec, argv[1:])
		if res.Outcome != extrun.OutcomeOK {
			return nil, errors.New("sandbox get did not answer")
		}
		return res.Stdout, nil
	}
}

// openShellRecordSandboxID asks the run's pinned gateway for its box's id
// until it answers (or ctx ends) and writes it into the run dir, so the
// daemon's OCSF receiver can tell this run's denials from other boxes'.
// The box exists only once the interactive create got going, so it polls.
// It returns errOpenShellBoxIDGaveUp when ctx's deadline passed (the
// caller tells the run), another error when ctx was cancelled (the box's
// command ended first).
func openShellRecordSandboxID(ctx context.Context, get func(ctx context.Context) ([]byte, error), runDir string) error {
	t := time.NewTicker(openShellBoxIDPoll)
	defer t.Stop()
	for {
		if b, err := get(ctx); err == nil {
			if id, ok := sandboxopenshell.ParseSandboxID(b); ok {
				return openShellWriteExcl(filepath.Join(runDir, openShellSandboxIDFile), []byte(id+"\n"))
			}
		}
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return errOpenShellBoxIDGaveUp
			}
			return errors.New("the box's command ended before its id was read")
		case <-t.C:
		}
	}
}
