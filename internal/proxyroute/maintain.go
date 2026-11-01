package proxyroute

import (
	"fmt"
	"path/filepath"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/routeprov"
)

// maintain.go: managed-node route maintenance (lane P1, operator ruling
// 2026-10-18: "Unless we absolutely can't proxy route for these tools, we
// should fix this"). On a managed node whose organization governs an
// enforcement point that lives in the API proxy, the daemon keeps every
// routable AI tool routed through the Observer proxy and puts a removed route
// back, the way it already keeps and repairs hooks.
//
// The decision is a table (maintainRules) over one inspected row plus two
// facts the daemon resolves at its boundary (the org needs the proxy; the
// proxy is listening and not draining). The write is the row's own guarded
// writer, the same one `observer init` calls, so maintenance changes only the
// route keys, keeps every other byte the writer keeps, refuses every layout
// the writer refuses and records provenance like enrolment does.

// MaintainAction is what route maintenance does for one tool.
type MaintainAction string

const (
	// MaintainSkip: leave the tool's config alone.
	MaintainSkip MaintainAction = "skip"
	// MaintainWrite: write the route through the row's guarded writer.
	MaintainWrite MaintainAction = "write"
)

// MaintainReason is why maintenance chose its action. A closed vocabulary.
type MaintainReason string

// The maintenance reasons, one per maintainRules row.
const (
	ReasonNotRequired      MaintainReason = "not_required"
	ReasonRouted           MaintainReason = "routed"
	ReasonOrgGateway       MaintainReason = "org_gateway"
	ReasonWrongHost        MaintainReason = "wrong_host"
	ReasonNotInstalled     MaintainReason = "not_installed"
	ReasonNotRoutable      MaintainReason = "not_routable"
	ReasonConfigNotCovered MaintainReason = "config_not_covered"
	ReasonNotEvaluated     MaintainReason = "not_evaluated"
	ReasonProxyUnavailable MaintainReason = "proxy_unavailable"
	ReasonRouteMissing     MaintainReason = "route_missing"
	// ReasonRouteFileUnknown: the inspector could not name the tool's route
	// file (RouteUnknown: a relocation variable holds a relative value), so
	// there is no file to write (R-188 F6).
	ReasonRouteFileUnknown MaintainReason = "route_file_unknown"
	// ReasonProviderLane: the tool talks to a third-party provider host the
	// registry row can carry through a proxy route lane; the lane writer
	// routes it there, keeping that host as the lane upstream.
	ReasonProviderLane MaintainReason = "provider_lane"
	// ReasonLaneUnavailable is not a table row: a provider_lane write found
	// the proxy could not install (or does not resolve) the lane, so nothing
	// was written (a route toward a refused lane would fail every request).
	ReasonLaneUnavailable MaintainReason = "lane_unavailable"
	// ReasonOtherPort: the route is a loopback URL at another port than this
	// daemon's proxy listener (T-901). It does not reach this proxy and may
	// be a local forwarder around it, so it is reported as drift and, like a
	// wrong host, never overwritten.
	ReasonOtherPort MaintainReason = "other_port"
	// ReasonPortMoved: the route is at another loopback port, but Observer
	// provably wrote it (RouteStatus.OrgWrittenExact: the organization's
	// provenance record holds exactly this value, which differs from what
	// this daemon would write only in the port), so the proxy port changed
	// since. Maintenance moves it to this daemon's port (D-745).
	ReasonPortMoved MaintainReason = "port_moved"
	// ReasonInactiveProvider: the route is in the file, but the tool's active
	// provider is another one (RouteInactiveProvider, CLI-3), so its turns do
	// not reach the proxy. Report only: the writer writes the route, not the
	// developer's provider choice, so writing again would change nothing.
	ReasonInactiveProvider MaintainReason = "inactive_provider"
	// ReasonClientAuthForm: the route is the organization's route to this
	// proxy in the other form than the one the daemon writes (plain while
	// the daemon writes the proxy client token form, or the reverse after
	// the token was switched off; OSH-R-009). Maintenance rewrites it in
	// place to the daemon's form, only while the proxy serves.
	ReasonClientAuthForm MaintainReason = "client_auth_form"
)

// MaintainInput is everything the decision needs for one tool.
type MaintainInput struct {
	// Required: the organization governs an enforcement point that lives in
	// the API proxy (govern.Effective.RequiresProxyRoute), resolved live at
	// the boundary. False on every individual node.
	Required bool
	// ProxyHealthy: the daemon's own proxy answers its liveness probe and is
	// not draining for an update. A route is never written toward a proxy
	// that is not serving, because the tool would get ConnectionRefused.
	ProxyHealthy bool
	// ProxyPort is the daemon's own proxy listener port; 0 does not compare
	// a loopback route's port.
	ProxyPort int
	// Status is the tool's inspected route.
	Status RouteStatus
	// WantClientAuth: the daemon writes routes in the proxy client token
	// form (its registrar holds a token, RegisterOptions.ClientToken).
	WantClientAuth bool
}

// MaintainDecision is the table's verdict for one tool.
type MaintainDecision struct {
	Action MaintainAction
	Reason MaintainReason
}

type maintainRule struct {
	match  func(in MaintainInput) bool
	action MaintainAction
	reason MaintainReason
}

// maintainRules is the route-maintenance table, walked top-down; the first
// match wins. One test case per row (maintain_test.go).
var maintainRules = []maintainRule{
	{func(in MaintainInput) bool { return !in.Required }, MaintainSkip, ReasonNotRequired},
	// A route Observer provably wrote, left at an old port by a [proxy].port
	// change, is moved to this daemon's port (D-745), only while the proxy
	// serves.
	{func(in MaintainInput) bool {
		return maintainedOtherPort(in) && in.Status.OrgWrittenExact && !in.ProxyHealthy
	}, MaintainSkip, ReasonProxyUnavailable},
	{func(in MaintainInput) bool { return maintainedOtherPort(in) && in.Status.OrgWrittenExact }, MaintainWrite, ReasonPortMoved},
	// Anything else at another loopback port may be a local forwarder: never
	// overwritten.
	{maintainedOtherPort, MaintainSkip, ReasonOtherPort},
	{func(in MaintainInput) bool { return in.Status.State == RouteUnknown }, MaintainSkip, ReasonRouteFileUnknown},
	// The organization's own route in the other form (plain vs client
	// token) is converted, never a route the developer wrote: the writer
	// records the route as the organization's, which would hand the
	// developer's route to the Leave rules.
	{func(in MaintainInput) bool { return clientAuthFormChange(in) && !in.ProxyHealthy }, MaintainSkip, ReasonProxyUnavailable},
	{clientAuthFormChange, MaintainWrite, ReasonClientAuthForm},
	{func(in MaintainInput) bool { return in.Status.State == RouteOurs }, MaintainSkip, ReasonRouted},
	{func(in MaintainInput) bool { return in.Status.State == RouteInactiveProvider }, MaintainSkip, ReasonInactiveProvider},
	{func(in MaintainInput) bool { return in.Status.State == RouteOrgGateway }, MaintainSkip, ReasonOrgGateway},
	// A wrong host is redirection evidence: report it, never overwrite it,
	// unless it is a third-party provider the row carries through a route
	// lane, which keeps that host as the upstream (the traffic still reaches
	// the provider the developer chose).
	{func(in MaintainInput) bool { return in.Status.State == RouteDrifted && !in.Status.LaneWritable }, MaintainSkip, ReasonWrongHost},
	{func(in MaintainInput) bool { return in.Status.State == RouteDrifted && !in.ProxyHealthy }, MaintainSkip, ReasonProxyUnavailable},
	{func(in MaintainInput) bool { return in.Status.State == RouteDrifted }, MaintainWrite, ReasonProviderLane},
	{func(in MaintainInput) bool { return !in.Status.ArtifactPresent }, MaintainSkip, ReasonNotInstalled},
	{func(in MaintainInput) bool { return in.Status.Routability == RoutabilityNotRoutable }, MaintainSkip, ReasonNotRoutable},
	{func(in MaintainInput) bool { return in.Status.Routability == RoutabilityConfigNotCovered }, MaintainSkip, ReasonConfigNotCovered},
	{func(in MaintainInput) bool { return in.Status.Routability != RoutabilityWritable }, MaintainSkip, ReasonNotEvaluated},
	{func(in MaintainInput) bool { return !in.ProxyHealthy }, MaintainSkip, ReasonProxyUnavailable},
	{func(MaintainInput) bool { return true }, MaintainWrite, ReasonRouteMissing},
}

// maintainedOtherPort reports a loopback route at another port than this
// daemon's proxy listener, read the way the maintained drift reading does.
func maintainedOtherPort(in MaintainInput) bool {
	return otherPort(in.Status, DriftPolicy{Mode: DriftModeMaintained, ProxyPort: in.ProxyPort})
}

// clientAuthFormChange reports an organization-written route to this proxy
// whose writer writes the client token form and whose form differs from the
// one the daemon writes.
func clientAuthFormChange(in MaintainInput) bool {
	st := in.Status
	return st.State == RouteOurs && st.ClientAuthWritable && st.OrgRouted &&
		st.ClientAuth != in.WantClientAuth
}

// DecideMaintenance walks maintainRules for one tool.
func DecideMaintenance(in MaintainInput) MaintainDecision {
	for _, r := range maintainRules {
		if r.match(in) {
			return MaintainDecision{Action: r.action, Reason: r.reason}
		}
	}
	return MaintainDecision{Action: MaintainSkip, Reason: ReasonNotRequired}
}

// MaintainOptions configures one maintenance pass.
type MaintainOptions struct {
	// Required is the org posture (see MaintainInput.Required).
	Required bool
	// ProxyHealthy is probed before the pass and again right before each
	// write. Nil reads as "not healthy": no write.
	ProxyHealthy func() bool
	// Allow filters tools (the component gate: an inactive adapter is never
	// written). Nil allows every tool.
	Allow func(tool string) bool
	// Now stamps a repair or a port move. Nil uses time.Now.
	Now func() time.Time
	// InstallLane makes the route lane id (upstream root) resolvable in the
	// running proxy and reports an error when it cannot. A provider_lane
	// write happens only after it succeeds, so the tool is never pointed at
	// a lane the proxy would refuse. Nil: no lane write happens.
	InstallLane func(id, root string) error
}

// MaintainResult is what one pass did for one tool.
type MaintainResult struct {
	Tool       string
	ConfigPath string
	Decision   MaintainDecision
	// Written: the route was written in this pass.
	Written bool
	// Repaired: the route was written AND Observer had routed this tool
	// before (a provenance record existed), so it had been removed.
	Repaired bool
	// Error is the writer's refusal or failure; the config is unchanged.
	Error error
}

// MaintainRoutes runs one managed route-maintenance pass over the inspection
// table for this registrar's home. The registrar must be a real (not dry-run)
// registrar whose Writer is routeprov.WriterManaged, so leaving the
// organization, or the organization turning maintenance off
// (ReleaseManagedRoutes), removes exactly the routes maintenance wrote.
func (r *Registrar) MaintainRoutes(opts MaintainOptions) []MaintainResult {
	if r.opts.DryRun {
		return nil
	}
	healthy := func() bool { return opts.ProxyHealthy != nil && opts.ProxyHealthy() }
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	prov := inspectProvenance(r.opts.HomeDir)
	proxyUp := opts.Required && healthy()
	var out []MaintainResult
	for _, ri := range routeInspectors() {
		if opts.Allow != nil && !opts.Allow(ri.tool) {
			continue
		}
		st := ApplyActiveProvider([]RouteStatus{inspectOne(ri, r.inspectEnv(), nil, prov)})[0]
		d := DecideMaintenance(MaintainInput{Required: opts.Required, ProxyHealthy: proxyUp, ProxyPort: r.opts.ProxyPort, Status: st, WantClientAuth: r.opts.ClientToken != ""})
		res := MaintainResult{Tool: ri.tool, ConfigPath: st.ConfigPath, Decision: d}
		if d.Action == MaintainWrite {
			// Re-check right before touching the file: the proxy can start
			// draining between the pass's probe and this write.
			write := ri.write
			if d.Reason == ReasonProviderLane {
				write = ri.laneWrite
			}
			switch {
			case !healthy():
				res.Decision = MaintainDecision{Action: MaintainSkip, Reason: ReasonProxyUnavailable}
			case d.Reason == ReasonPortMoved:
				// An in-place edit of the route value only: the lane a lane
				// route addresses is keyed by its id, not the port, so it
				// stays installed.
				if err := r.moveRoutePort(ri.tool, st.ConfigPath, now()); err != nil {
					res.Error = err
				} else {
					res.Written = true
				}
			case d.Reason == ReasonProviderLane && !r.prepareLane(ri, opts.InstallLane, &res):
				res.Decision = MaintainDecision{Action: MaintainSkip, Reason: ReasonLaneUnavailable}
			default:
				w := write(r)
				if w.Error == nil && w.Added && w.LaneID != "" && opts.InstallLane != nil {
					// The file can change between the dry run and the write; the
					// lane the route now addresses must resolve either way.
					if err := opts.InstallLane(w.LaneID, w.LaneRoot); err != nil {
						res.Error = err
					}
				}
				switch {
				case w.Error != nil:
					res.Error = w.Error
				case w.Added:
					res.Written = true
					// A form change rewrites a route that is there: not a
					// repair of a removed one.
					res.Repaired = st.WasRouted && d.Reason != ReasonClientAuthForm
					if res.Repaired {
						if err := r.stampRepair(ri.tool, w.ConfigPath, now()); err != nil {
							res.Error = err
						}
					}
				}
			}
		}
		out = append(out, res)
	}
	return out
}

// prepareLane dry-runs ri's lane writer and installs the lane it would
// address before anything is written. False (with res.Error set when there
// was a failure to report) means no write may happen.
func (r *Registrar) prepareLane(ri routeInspector, install func(id, root string) error, res *MaintainResult) bool {
	if ri.laneWrite == nil || install == nil {
		return false
	}
	dry, err := NewRegistrar(RegisterOptions{ProxyPort: r.opts.ProxyPort, HomeDir: r.opts.HomeDir, DryRun: true})
	if err != nil {
		res.Error = err
		return false
	}
	plan := ri.laneWrite(dry)
	if plan.Error != nil || !plan.Added || plan.LaneID == "" {
		res.Error = plan.Error
		return false
	}
	if err := install(plan.LaneID, plan.LaneRoot); err != nil {
		res.Error = err
		return false
	}
	return true
}

// stampRepair marks the provenance record of a route maintenance just put
// back. The writer has already recorded the write (Note), so the record is
// there; a failure here leaves the route in place and is reported.
func (r *Registrar) stampRepair(tool, path string, at time.Time) error {
	pp := r.ProvenancePath()
	f, err := loadProvenance(pp)
	if err != nil {
		return err
	}
	rec := f.Find(tool, path)
	if rec == nil {
		return fmt.Errorf("proxyroute.stampRepair: no provenance record for %s", tool)
	}
	rec.RepairedAt = at.UTC().Format(time.RFC3339)
	return saveProvenance(pp, f)
}

// RouteActKind is what a recent route act was.
type RouteActKind string

const (
	// RouteActWritten: Observer's enrolment wrote the route (a first write).
	RouteActWritten RouteActKind = "written"
	// RouteActRepaired: the managed daemon put a removed route back.
	RouteActRepaired RouteActKind = "repaired"
)

// RouteAct is one recent route write the managed-integrity probe reports.
type RouteAct struct {
	Tool       string
	ConfigPath string
	Kind       RouteActKind
	At         time.Time
}

// RecentRouteActs reads the route-provenance file under homeDir and returns
// the routes Observer's enrolment (the CLI enrol or managed maintenance)
// wrote or repaired within window of now, newest first. Read-only. A record
// another writer owns (init, Settings > Setup, a launcher) is the developer's
// own act and is not reported.
func RecentRouteActs(homeDir string, now time.Time, window time.Duration) []RouteAct {
	f, err := loadProvenance(filepath.Join(homeDir, ".observer", ProvenanceFileName))
	if err != nil {
		return nil
	}
	within := func(stamp string) (time.Time, bool) {
		t, perr := time.Parse(time.RFC3339, stamp)
		if perr != nil || now.Sub(t) > window {
			return time.Time{}, false
		}
		return t, true
	}
	var out []RouteAct
	for _, rec := range f.Records {
		if !routeprov.OrgOwned(rec.Writer) {
			continue
		}
		if at, ok := within(rec.RepairedAt); ok {
			out = append(out, RouteAct{Tool: rec.Tool, ConfigPath: rec.ConfigPath, Kind: RouteActRepaired, At: at})
			continue
		}
		if at, ok := within(rec.WrittenAt); ok {
			out = append(out, RouteAct{Tool: rec.Tool, ConfigPath: rec.ConfigPath, Kind: RouteActWritten, At: at})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	return out
}

// ManagedRoutesMaintained reports whether the managed daemon has written any
// AI tool route on this machine that is still recorded (a WriterManaged
// provenance record): the evidence a separate process such as `observer
// doctor` has that this daemon keeps routes through its proxy.
func ManagedRoutesMaintained(homeDir string) bool {
	f, err := loadProvenance(filepath.Join(homeDir, ".observer", ProvenanceFileName))
	if err != nil {
		return false
	}
	for _, rec := range f.Records {
		if rec.Writer == routeprov.WriterManaged {
			return true
		}
	}
	return false
}
