package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentsvc"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	otlpingest "github.com/marmutapp/superbased-observer/internal/ingest/otlp"
	"github.com/marmutapp/superbased-observer/internal/planechoice"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// obs_wire_apps.go is the hot-enable of AI Apps in a running daemon
// (first-run plan revision 2, section 3.8; review P-03, P-04). The daemon IS
// the proxy on :8820, so a restart breaks every coding agent routed through
// it; turning AI Apps on therefore must not need one. The design:
//
//  1. When obs is compiled in, every obs dashboard route is registered at
//     dashboard.New behind one gate (an atomic flag; 404 while off, as a
//     route that does not exist answers today). A mux cannot drop a route,
//     which is also why "off" cannot be hot: off writes the config and takes
//     effect at the next start.
//  2. The OTLP receiver goroutine waits on an enable request instead of
//     returning when nothing is on (obs_wire_receiver.go), and binds late.
//  3. appsRuntime.enable is the ONE enable seam: the dashboard button, the
//     CLI (`observer apps on`, through the dashboard route) and the VS Code
//     action all reach it. It activates the obs component, sets the key,
//     opens the obs schema, installs the trace handler behind the
//     receiver's switch, binds the receiver and reports a bind failure, and
//     opens the route gate.
//  4. What a hot enable cannot start is said, never implied (FR-M01): the
//     proxy's admitter and gateway rail are fixed when the proxy is built,
//     and the alert loop and the organization push read their gates at
//     start. pending names them (appsPendingRules); the enable answer, the
//     status and the dashboard show the list, and the admission routes use
//     the proxy's own admission service or none.
//
// It never names an internal/obs type: the obs-owned pieces are the
// build-tagged functions obsRoutePatterns, obsHotDashboardRoutes,
// newObsTraceHandler and newObsLatestTraceReader (obs_wire.go and its stub).
//
// One owner: appsRuntime owns the gate, the route table, the trace switch
// and the receiver control for the daemon's lifetime.

// appsReceiverWait bounds how long an enable waits for the receiver to
// report its bind.
const appsReceiverWait = 30 * time.Second

// appsStatusTTL bounds how often the status read reloads the config and the
// component state (the first-run brief read runs on every page load).
const appsStatusTTL = 2 * time.Second

// appsRuntime is the daemon's one AI Apps hot-enable state.
type appsRuntime struct {
	// ctx is the daemon's lifetime context: what the obs handlers, the
	// online sampler and the routes are built with (never a request ctx).
	ctx        context.Context
	configPath string
	db         *sql.DB
	admission  *obsAdmissionHandle
	logger     *slog.Logger
	// share resolves the organization share posture in force (the push
	// loop's own provider), for the consent sentence; nil = config only.
	share func() store.ShareOptions

	inBuild bool
	traces  *otlpingest.TraceSwitch
	recv    *receiverCtl

	gate     atomic.Bool
	handlers atomic.Pointer[map[string]http.HandlerFunc]
	// bootOn: AI Apps was on when the daemon started (nothing is pending).
	bootOn bool

	enableMu sync.Mutex

	statusMu  sync.Mutex
	statusAt  time.Time
	statusVal planechoice.AppsStatus

	traceMu     sync.Mutex
	traceReader func(context.Context) (*planechoice.LatestTrace, error)
}

// appsRuntimeOptions are newAppsRuntime's inputs.
type appsRuntimeOptions struct {
	Ctx        context.Context
	ConfigPath string
	DB         *sql.DB
	Admission  *obsAdmissionHandle
	Share      func() store.ShareOptions
	Logger     *slog.Logger
	// BootOn: [observability] enabled when the daemon started.
	BootOn bool
}

// newAppsRuntime builds the runtime. It does no I/O.
func newAppsRuntime(o appsRuntimeOptions) *appsRuntime {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Ctx == nil {
		o.Ctx = context.Background()
	}
	a := &appsRuntime{
		ctx: o.Ctx, configPath: o.ConfigPath, db: o.DB, admission: o.Admission,
		share: o.Share, logger: o.Logger, inBuild: appObsCompiledIn(), bootOn: o.BootOn,
		traces: otlpingest.NewTraceSwitch("AI Apps is off on this machine ([observability] enabled = false); turn it on in the dashboard or with `observer apps on` to keep app spans here"),
		recv:   newReceiverCtl(),
	}
	empty := map[string]http.HandlerFunc{}
	a.handlers.Store(&empty)
	return a
}

// gatedRoutes returns one gated dashboard route per obs route pattern, the
// boot routes installed behind the gate (and the gate opened) when AI Apps
// was on at start. In a build without obs it returns nil: nothing to gate.
func (a *appsRuntime) gatedRoutes(boot []dashapi.ExtraRoute) []dashapi.ExtraRoute {
	if a == nil || !a.inBuild {
		return boot
	}
	if len(boot) > 0 {
		a.install(boot)
		a.gate.Store(true)
	}
	seen := map[string]bool{}
	var out []dashapi.ExtraRoute
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, dashapi.ExtraRoute{
			Pattern: p, Handler: a.gated(p),
			Capability: obsRouteCapability(p), Section: obsRouteSection(p),
		})
	}
	for _, p := range obsRoutePatterns() {
		add(p)
	}
	for _, r := range boot {
		add(r.Pattern)
	}
	return out
}

// gated is the handler registered for pattern: 404 while AI Apps is off in
// this process, else the installed handler.
func (a *appsRuntime) gated(pattern string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.gate.Load() {
			http.NotFound(w, r)
			return
		}
		h := (*a.handlers.Load())[pattern]
		if h == nil {
			http.NotFound(w, r)
			return
		}
		h(w, r)
	}
}

// install replaces the route table with routes.
func (a *appsRuntime) install(routes []dashapi.ExtraRoute) {
	m := make(map[string]http.HandlerFunc, len(routes))
	for _, r := range routes {
		if r.Pattern != "" && r.Handler != nil {
			m[r.Pattern] = r.Handler
		}
	}
	a.handlers.Store(&m)
}

// on reports whether AI Apps serves in this process.
func (a *appsRuntime) on() bool { return a != nil && a.gate.Load() }

// obsComponentState reads the obs component's state for configPath.
func obsComponentState(configPath string) planechoice.ComponentState {
	d, ok := componentSnapshotFor(configPath).Decision("obs")
	if !ok {
		return planechoice.ComponentAbsent
	}
	switch d.State {
	case components.StateActive:
		return planechoice.ComponentActive
	case components.StateAvailable:
		return planechoice.ComponentAvailable
	case components.StateAbsent:
		return planechoice.ComponentAbsent
	case components.StateBlocked:
		return planechoice.ComponentBlocked
	}
	return planechoice.ComponentUnknown
}

// obsEditions names the prebuilt editions that compile obs in.
func obsEditions() []string {
	c, ok := components.Get("obs")
	if !ok {
		return nil
	}
	var out []string
	for _, d := range components.Distros() {
		if c.Distros[d].Compiled() {
			out = append(out, string(d))
		}
	}
	return out
}

// errAppsKeyRefused marks a config-key change the posture rules refused.
var errAppsKeyRefused = errors.New("refused")

// setObsEnabledKey writes [observability] enabled through the same checks
// `observer config set` runs (the organization's pins included), under the
// process-wide config lock the dashboard's own writers share.
func setObsEnabledKey(ctx context.Context, configPath string, on bool) error {
	return config.WithConfigLock(func() error {
		resolved, err := config.ResolveGlobalPath(configPath)
		if err != nil {
			return err
		}
		cfg, err := config.Load(config.LoadOptions{GlobalPath: resolved})
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		if cfg.Observability.Enabled == on {
			return nil
		}
		gov, err := configSetGovernance(ctx, cfg)
		if err != nil {
			return fmt.Errorf("%w: %w", errAppsKeyRefused, err)
		}
		plan, err := planConfigSet(cfg, "observability.enabled", fmt.Sprint(on), gov, true)
		if err != nil {
			return fmt.Errorf("%w: %w", errAppsKeyRefused, err)
		}
		return writeConfigSet(resolved, plan)
	})
}

// enable is the one enable seam (plan 3.5 and 3.8). It is idempotent: on a
// daemon already serving AI Apps it re-reads the receiver and answers on.
func (a *appsRuntime) enable(ctx context.Context) planechoice.EnableReport {
	a.enableMu.Lock()
	defer a.enableMu.Unlock()
	defer a.invalidateStatus()
	f := planechoice.EnableFacts{InBuild: a.inBuild, Editions: obsEditions()}
	if !a.inBuild {
		return planechoice.ClassifyEnable(f)
	}
	f.Component = obsComponentState(a.configPath)
	switch f.Component {
	case planechoice.ComponentAbsent, planechoice.ComponentBlocked:
		return planechoice.ClassifyEnable(f)
	case planechoice.ComponentAvailable:
		// The change Settings > Components makes (`observer components add
		// obs`), through the same service and audit row.
		svc, err := newComponentsService(a.configPath, a.db)
		if err == nil {
			_, err = svc.Apply(ctx, componentsvc.Change{Add: []string{"obs"}}, componentsvc.ApplyOptions{Principal: "apps-on"})
		}
		if err != nil {
			if errors.Is(err, componentsvc.ErrManagedByOrg) {
				f.Refused = err.Error()
			} else {
				f.WriteError = "adding the obs component: " + err.Error()
			}
			return planechoice.ClassifyEnable(f)
		}
	}
	if err := setObsEnabledKey(ctx, a.configPath, true); err != nil {
		if errors.Is(err, errAppsKeyRefused) {
			f.Refused = strings.TrimPrefix(err.Error(), errAppsKeyRefused.Error()+": ")
		} else {
			f.WriteError = "setting observability.enabled: " + err.Error()
		}
		return planechoice.ClassifyEnable(f)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: a.configPath})
	if err != nil {
		f.WriteError = "the saved config did not load: " + err.Error()
		return planechoice.ClassifyEnable(f)
	}
	if !cfg.Observability.Enabled {
		f.WriteError = "the saved config still reads AI Apps off (the component gate or an organization pin holds it off)"
		return planechoice.ClassifyEnable(f)
	}
	// The trace handler, behind the receiver's switch (opens the obs schema).
	if !a.traces.On() {
		h := newObsTraceHandler(a.ctx, cfg, a.db, a.logger)
		if h == nil {
			f.WriteError = "the AI Apps store could not be opened (see the daemon log)"
			return planechoice.ClassifyEnable(f)
		}
		a.traces.Set(guardPlaneA(h, a.logger))
	}
	// What this process cannot start now (FR-M01): named in the report and
	// the status, and the admission routes follow it.
	f.Pending = a.pending(cfg)
	// The routes, installed behind the gate (opened only once the receiver
	// listens, so the pages never say "on" while spans would be lost). The
	// admission routes get the proxy's own admission service or none, never
	// one the proxy does not consult (obsHotDashboardRoutes).
	if !a.gate.Load() {
		a.install(obsHotDashboardRoutes(a.ctx, cfg, a.configPath, a.db, a.admission, slices.Contains(f.Pending, appsPendingAdmission), a.logger))
	}
	f.Receiver = a.recv.ensure(ctx, appsReceiverWait)
	if f.Receiver.State == planechoice.ReceiverListening {
		a.gate.Store(true)
	}
	f.Component = planechoice.ComponentActive
	rep := planechoice.ClassifyEnable(f)
	a.logger.Info("apps: enable", "outcome", rep.Outcome, "receiver", f.Receiver.State, "http_addr", f.Receiver.HTTPAddr)
	return rep
}

// appsDisableReport is what disable answers.
type appsDisableReport struct {
	OK bool `json:"ok"`
	// Effective is always "next_start": routes cannot be removed from a
	// running mux (plan 3.8 item 4).
	Effective string `json:"effective"`
	Message   string `json:"message"`
}

// disable writes [observability] enabled = false. It takes effect at the
// next start, and says so.
func (a *appsRuntime) disable(ctx context.Context) (appsDisableReport, error) {
	a.enableMu.Lock()
	defer a.enableMu.Unlock()
	defer a.invalidateStatus()
	if err := setObsEnabledKey(ctx, a.configPath, false); err != nil {
		return appsDisableReport{Effective: "next_start"}, err
	}
	msg := "AI Apps is set to off. It stops at the next start of the daemon."
	if !a.on() {
		msg = "AI Apps is off."
	}
	return appsDisableReport{OK: true, Effective: "next_start", Message: msg}, nil
}

// The names pending reports (the CLI, the enable answer and the dashboard
// print them as they are).
const (
	appsPendingAdmission  = "admission"
	appsPendingEgress     = "egress routing"
	appsPendingProxyTurns = "proxy turn traces"
	appsPendingAlerts     = "alerts"
	appsPendingShareTiers = "organization share tiers"
)

// obsProxyRailInBuild is true when this binary binds Plane A onto the proxy
// (obs_wire_proxy.go sets it): only then can the proxy-side features wait
// for the next start. Without it they never run here, so they are not
// pending either.
var obsProxyRailInBuild bool

// appsPendingRules are the AI Apps features whose wiring runs only when
// the daemon starts (FR-M01): the proxy's admitter and gateway rail are
// fixed when the proxy is built (internal/proxy takes them as construction
// options), the alert loop and the organization push read their gates once
// at start. A hot enable starts none of them. Walked in order; one test per
// row.
var appsPendingRules = []struct {
	name string
	on   func(a *appsRuntime, cfg config.Config) bool
}{
	{appsPendingAdmission, func(_ *appsRuntime, c config.Config) bool { return c.Observability.Admission.Enabled }},
	{appsPendingEgress, func(_ *appsRuntime, c config.Config) bool {
		// Egress composes on the admission verdict: without admission it
		// does not run at any start, so it is not pending.
		return c.Observability.Egress.Enabled && c.Observability.Admission.Enabled
	}},
	{appsPendingProxyTurns, func(_ *appsRuntime, c config.Config) bool {
		return c.Observability.ProxyTurnTraces && obsProxyRailInBuild
	}},
	{appsPendingAlerts, func(_ *appsRuntime, c config.Config) bool { return c.Observability.Alerts.Enabled }},
	{appsPendingShareTiers, func(a *appsRuntime, c config.Config) bool {
		return c.OrgClient.Enabled && len(obsShareTierKeys(a.shareOptions(c))) > 0
	}},
}

// pending names the AI Apps features configured on that only start with
// the daemon, when AI Apps was turned on after start. A daemon that started
// with AI Apps on started them all, so nothing is pending.
func (a *appsRuntime) pending(cfg config.Config) []string {
	if a.bootOn {
		return nil
	}
	var out []string
	for _, r := range appsPendingRules {
		if r.on(a, cfg) {
			out = append(out, r.name)
		}
	}
	return out
}

// obsAdmissionStatusPattern is the admission status route a hot enable
// marks when admission waits for the next start.
const obsAdmissionStatusPattern = "GET /api/obs/admission/status"

// withAdmissionPendingStatus marks the admission status route's answer with
// "pending_next_start": true (FR-M01): admission is on in the config, and
// the proxy's admitter, built at start, starts it at the next start. The
// rest of the answer is what the routes' own service reports (none on a node
// whose proxy runs no admission service: available false, mode off).
func withAdmissionPendingStatus(routes []dashapi.ExtraRoute) []dashapi.ExtraRoute {
	for i, r := range routes {
		if r.Pattern == obsAdmissionStatusPattern && r.Handler != nil {
			routes[i].Handler = admissionStatusPending(r.Handler)
		}
	}
	return routes
}

// admissionStatusPending runs h into a buffer and adds the pending mark to a
// 200 JSON object answer; any other answer passes through unchanged.
func admissionStatusPending(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		buf := &bufferedResponse{header: http.Header{}}
		h(buf, r)
		for k, v := range buf.header {
			w.Header()[k] = v
		}
		body := buf.body.Bytes()
		if buf.status() == http.StatusOK {
			var m map[string]any
			if json.Unmarshal(body, &m) == nil && m != nil {
				m["pending_next_start"] = true
				if out, err := json.Marshal(m); err == nil {
					out = append(out, '\n')
					body = out
					w.Header().Del("Content-Length")
				}
			}
		}
		w.WriteHeader(buf.status())
		_, _ = w.Write(body)
	}
}

// bufferedResponse is an http.ResponseWriter that keeps the answer.
type bufferedResponse struct {
	header http.Header
	code   int
	body   bytes.Buffer
}

func (b *bufferedResponse) Header() http.Header { return b.header }

func (b *bufferedResponse) WriteHeader(code int) {
	if b.code == 0 {
		b.code = code
	}
}

func (b *bufferedResponse) Write(p []byte) (int, error) {
	if b.code == 0 {
		b.code = http.StatusOK
	}
	return b.body.Write(p)
}

func (b *bufferedResponse) status() int {
	if b.code == 0 {
		return http.StatusOK
	}
	return b.code
}

// shareOptions is the share posture in force.
func (a *appsRuntime) shareOptions(cfg config.Config) store.ShareOptions {
	if a.share != nil {
		return a.share()
	}
	return store.ShareOptions{
		ObsSummary: cfg.OrgClient.Share.Obs.Summary, ObsTraces: cfg.OrgClient.Share.Obs.Traces,
		ObsContent: cfg.OrgClient.Share.Obs.Content, ObsEvalSummary: cfg.OrgClient.Share.Obs.EvalSummary,
		ObsAdmission: cfg.OrgClient.Share.Obs.Admission, ObsEvalItems: cfg.OrgClient.Share.Obs.EvalItems,
		ObsEgress: cfg.OrgClient.Share.Obs.Egress,
	}
}

// obsShareTierKeys lists the [org_client.share.obs] keys on in s, in
// planechoice.ShareTiers' vocabulary.
func obsShareTierKeys(s store.ShareOptions) []string {
	rows := []struct {
		on  bool
		key string
	}{
		{s.ObsSummary, "summary"},
		{s.ObsTraces, "traces"},
		{s.ObsContent, "content"},
		{s.ObsEvalSummary, "eval_summary"},
		{s.ObsAdmission, "admission"},
		{s.ObsEvalItems, "eval_items"},
		{s.ObsEgress, "egress"},
	}
	var out []string
	for _, r := range rows {
		if r.on {
			out = append(out, r.key)
		}
	}
	return out
}

// status reports the AI Apps facts the first-run read serves, cached for
// appsStatusTTL (an enable or disable clears the cache).
func (a *appsRuntime) status(ctx context.Context) planechoice.AppsStatus {
	a.statusMu.Lock()
	if !a.statusAt.IsZero() && time.Since(a.statusAt) < appsStatusTTL {
		v := a.statusVal
		a.statusMu.Unlock()
		return v
	}
	a.statusMu.Unlock()
	v := a.readStatus(ctx)
	a.statusMu.Lock()
	a.statusVal, a.statusAt = v, time.Now()
	a.statusMu.Unlock()
	return v
}

func (a *appsRuntime) invalidateStatus() {
	a.statusMu.Lock()
	a.statusAt = time.Time{}
	a.statusMu.Unlock()
}

func (a *appsRuntime) readStatus(ctx context.Context) planechoice.AppsStatus {
	st := planechoice.AppsStatus{InBuild: a.inBuild, HotEnable: true, On: a.on()}
	st.Component = planechoice.ComponentAbsent
	if a.inBuild {
		st.Component = obsComponentState(a.configPath)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: a.configPath})
	if err == nil {
		st.ConfiguredOn = cfg.Observability.Enabled
		st.Consent.AllowNonLoopback = cfg.Ingest.OTel.AllowNonLoopback
		if a.on() {
			st.Pending = a.pending(cfg)
		}
		if cfg.OrgClient.Enabled && a.db != nil {
			if enr, eerr := store.New(a.db).LoadEnrolment(ctx); eerr == nil && enr != nil {
				st.Consent.Enrolled = true
				st.Consent.Org = enr.OrgName
				st.Consent.Tiers = obsShareTierKeys(a.shareOptions(cfg))
			}
		}
	}
	st.Receiver = a.recv.current()
	if st.Receiver.State == "" {
		st.Receiver.State = planechoice.ReceiverNotRunning
	}
	if a.on() {
		if lt, terr := a.latestTrace(ctx); terr == nil {
			st.LatestTrace = lt
		}
	}
	return st
}

// latestTrace reads the newest trace through the obs-owned store, opened
// once (it is only called while AI Apps serves, so the schema exists).
func (a *appsRuntime) latestTrace(ctx context.Context) (*planechoice.LatestTrace, error) {
	a.traceMu.Lock()
	if a.traceReader == nil {
		r, err := newObsLatestTraceReader(a.ctx, a.db)
		if err != nil {
			a.traceMu.Unlock()
			return nil, err
		}
		a.traceReader = r
	}
	read := a.traceReader
	a.traceMu.Unlock()
	return read(ctx)
}

// receiverCtl is the hand-off between the enable seam and the receiver
// goroutine (obs_wire_receiver.go): the goroutine reports every bind
// outcome, and while it has nothing to serve it waits for a request.
type receiverCtl struct {
	reqs    chan chan planechoice.Receiver
	mu      sync.Mutex
	last    planechoice.Receiver
	changed chan struct{}

	// spawn starts the receiver goroutine when the component gate kept it
	// from starting at boot (AI Apps off in an edition that has it, the
	// developer default): the first ensure runs it once (POLISH-F2 F2-1).
	spawnMu sync.Mutex
	spawn   func()
}

func newReceiverCtl() *receiverCtl {
	return &receiverCtl{reqs: make(chan chan planechoice.Receiver), changed: make(chan struct{})}
}

// report records the receiver's latest state.
func (c *receiverCtl) report(r planechoice.Receiver) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if r.At == "" {
		r.At = time.Now().UTC().Format(time.RFC3339)
	}
	c.last = r
	close(c.changed)
	c.changed = make(chan struct{})
}

// current returns the latest reported state ("" State when none yet).
func (c *receiverCtl) current() planechoice.Receiver {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

func (c *receiverCtl) snapshot() (planechoice.Receiver, <-chan struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last, c.changed
}

// await blocks the goroutine until an enable asks it to (try to) serve.
func (c *receiverCtl) await(ctx context.Context) (chan planechoice.Receiver, bool) {
	select {
	case reply := <-c.reqs:
		return reply, true
	case <-ctx.Done():
		return nil, false
	}
}

// ensure asks the goroutine to bind when it is waiting and returns the
// outcome. A receiver already listening answers at once; a goroutine still
// starting is waited for; a request nobody serves within wait reads as no
// answer.
func (c *receiverCtl) ensure(ctx context.Context, wait time.Duration) planechoice.Receiver {
	c.spawnOnce()
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for {
		last, changed := c.snapshot()
		if last.State == planechoice.ReceiverListening {
			return last
		}
		reply := make(chan planechoice.Receiver, 1)
		select {
		case c.reqs <- reply:
			select {
			case r := <-reply:
				return r
			case <-deadline.C:
				return planechoice.Receiver{State: planechoice.ReceiverNoAnswer}
			case <-ctx.Done():
				return planechoice.Receiver{State: planechoice.ReceiverNoAnswer, Error: ctx.Err().Error()}
			}
		case <-changed:
			// The goroutine reported (it was mid-start): look again. A
			// boot-time bind failure is not the answer: the next request
			// retries the bind.
			continue
		case <-deadline.C:
			out := c.current()
			if out.State == "" || out.State == planechoice.ReceiverNotRunning {
				out.State = planechoice.ReceiverNoAnswer
			}
			return out
		case <-ctx.Done():
			return planechoice.Receiver{State: planechoice.ReceiverNoAnswer, Error: ctx.Err().Error()}
		}
	}
}

// appsDashboardBinder is the dashboard's AI Apps seam setter
// (internal/intelligence/dashboard apps_enable.go). A build without the
// dashboard has no such server, and nothing is bound.
type appsDashboardBinder interface {
	SetApps(status func(context.Context) planechoice.AppsStatus,
		enable func(context.Context) planechoice.EnableReport,
		disable func(context.Context) (string, error))
}

// bindAppsDashboard hands the runtime's three seams to the dashboard.
func bindAppsDashboard(srv daemonDashboard, a *appsRuntime) {
	b, ok := srv.(appsDashboardBinder)
	if !ok || a == nil {
		return
	}
	b.SetApps(a.status, a.enable, func(ctx context.Context) (string, error) {
		rep, err := a.disable(ctx)
		return rep.Message, err
	})
}

// setSpawn registers the starter of a receiver goroutine the component gate
// kept from starting at boot. The first ensure runs it, once.
func (c *receiverCtl) setSpawn(fn func()) {
	c.spawnMu.Lock()
	defer c.spawnMu.Unlock()
	c.spawn = fn
}

// spawnOnce runs a registered starter and forgets it, so the receiver
// goroutine is started at most once.
func (c *receiverCtl) spawnOnce() {
	c.spawnMu.Lock()
	fn := c.spawn
	c.spawn = nil
	c.spawnMu.Unlock()
	if fn != nil {
		fn()
	}
}
