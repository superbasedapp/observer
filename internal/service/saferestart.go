package service

// saferestart.go is the decision `observer service restart` makes before it
// restarts the daemon (SR-12, lane sr-restart). The daemon IS the proxy, so
// a restart while an AI tool routes through it gives that tool
// ConnectionRefused (CLAUDE.md, "never stop the daemon while the proxy route
// is active"). The safe order is route OFF, stop, relaunch, route ON, as one
// operation; this table picks how the daemon is restarted (its service
// manager, or the daemon's own in-place re-exec when nothing supervises it),
// whether the routes are taken off first, and when the command must refuse.
// The cmd layer gathers the inputs and performs the plan.

// RestartManager is the service manager on this host.
type RestartManager string

// The closed RestartManager vocabulary.
const (
	// ManagerNone: no supported service manager (Windows, a container, a
	// host without systemd).
	ManagerNone RestartManager = "none"
	// ManagerSystemd: systemd (a --user or --system unit).
	ManagerSystemd RestartManager = "systemd"
	// ManagerLaunchd: macOS launchd (the per-user LaunchAgent).
	ManagerLaunchd RestartManager = "launchd"
)

// RestartInputs is what the cmd layer observed before a restart.
type RestartInputs struct {
	// Manager is the host's service manager.
	Manager RestartManager
	// UnitInstalled: Observer's unit (or LaunchAgent) exists.
	UnitInstalled bool
	// UnitActive: the service manager runs the daemon now.
	UnitActive bool
	// DashboardAnswers: a running daemon serving this config's database
	// answers on its dashboard (the in-place restart is asked there).
	DashboardAnswers bool
	// ProxyServing: the daemon's proxy answers its liveness probe. When it
	// does not, no AI tool is served through it and no route is taken off.
	ProxyServing bool
	// InPlaceSupported: this OS lets the daemon re-exec itself in place
	// (execve; not native Windows).
	InPlaceSupported bool
	// DaemonChild: this command runs inside a session the daemon launched
	// (a dashboard terminal, an attached launcher session). Stopping the
	// daemon ends that session, and this command with it, half way.
	DaemonChild bool
	// OrgMaintainsRoutes: a managed node whose organization maintains the AI
	// tools' proxy routes (route posture maintain). The daemon puts a removed
	// route back while its proxy serves and reports it to the organization.
	OrgMaintainsRoutes bool
	// OrgUnknown: whether the organization maintains the routes could not be
	// read (the config, the org lock or the governance state). The daemon of
	// a node whose organization does would write a removed route back as the
	// organization's, so the restart refuses rather than guess.
	OrgUnknown bool
	// ProxyExpected: the daemon's configuration runs the API proxy
	// (capture.proxy is active).
	ProxyExpected bool
	// KeepRoutes: the operator asked to restart with the routes left on
	// (--keep-routes).
	KeepRoutes bool
	// ListenerHandover: the running daemon says (on its dashboard) that its
	// in-place restart hands its proxy's listening socket to the new process
	// image, and, when a service manager runs it, it runs exactly the command
	// the installed unit or agent does (InvocationDigest), so an in-place
	// restart brings back what the manager would start (L-168).
	ListenerHandover bool
}

// Running reports whether a daemon appears to run.
func (in RestartInputs) Running() bool {
	return in.UnitActive || in.DashboardAnswers || in.ProxyServing
}

// RestartMechanism is how the daemon is restarted.
type RestartMechanism string

// The closed RestartMechanism vocabulary.
const (
	// RestartRefuse: do nothing; the plan's Reason says why.
	RestartRefuse RestartMechanism = "refuse"
	// RestartViaSystemd: systemctl restart (or start) observer.service.
	RestartViaSystemd RestartMechanism = "systemd"
	// RestartViaLaunchd: launchctl kickstart -k (or start) the LaunchAgent.
	RestartViaLaunchd RestartMechanism = "launchd"
	// RestartInPlace: ask the running daemon (no service manager runs it) to
	// shut down gracefully and re-exec itself, keeping its terminal, log,
	// arguments and environment (the dashboard restart).
	RestartInPlace RestartMechanism = "in_place"
	// RestartNothing: no daemon runs and no unit is installed.
	RestartNothing RestartMechanism = "nothing"
)

// RestartPlan is the table's answer.
type RestartPlan struct {
	Mechanism RestartMechanism
	// StartOnly: the unit is installed but not running, so the manager
	// starts it (no running proxy, nothing to take off).
	StartOnly bool
	// HoldRoutes: take the routes that reach this proxy off first and put
	// them back once the new proxy serves.
	HoldRoutes bool
	// Handover: the in-place restart hands the proxy's listening socket to
	// the new process image, so the port keeps answering throughout (a
	// connection made meanwhile waits in the socket's backlog and the new
	// daemon serves it) and no route is taken off.
	Handover bool
	// Rule names the table row that decided.
	Rule string
	// Reason is the refusal, or what the plan does, in plain words.
	Reason string
}

type restartRule struct {
	name   string
	match  func(in RestartInputs) bool
	plan   func(in RestartInputs) RestartPlan
	reason string
}

func hold(in RestartInputs) bool { return in.ProxyServing && !in.KeepRoutes }

// restartRules is the ordered decision table (CLAUDE.md rule 5); the first
// match wins. One test case per row (saferestart_test.go).
var restartRules = []restartRule{
	{
		name:  "daemon launched this shell",
		match: func(in RestartInputs) bool { return in.DaemonChild && in.Running() },
		plan:  func(RestartInputs) RestartPlan { return RestartPlan{Mechanism: RestartRefuse} },
		reason: "this command is running inside a session the Observer daemon started (a dashboard terminal or an attached launcher session). " +
			"Stopping the daemon ends that session, and this command with it, before the routes are back on. " +
			"Run it from a terminal the daemon did not start",
	},
	{
		// L-168 (ii): the port keeps answering, so nothing is taken off and
		// neither the organization's routes nor the resolved port matter.
		// Above the service-manager rows: execve keeps the main pid, so
		// systemd and launchd see no restart at all.
		name:  "running, hands its proxy over in place",
		match: func(in RestartInputs) bool { return in.DashboardAnswers && in.InPlaceSupported && in.ListenerHandover },
		plan: func(RestartInputs) RestartPlan {
			return RestartPlan{Mechanism: RestartInPlace, Handover: true}
		},
		reason: "the daemon restarts itself in place and hands its proxy's listening socket to the new process, " +
			"so the proxy port keeps answering throughout and no route is taken off",
	},
	{
		name:  "organization maintains routes",
		match: func(in RestartInputs) bool { return in.OrgMaintainsRoutes && in.ProxyServing && !in.KeepRoutes },
		plan:  func(RestartInputs) RestartPlan { return RestartPlan{Mechanism: RestartRefuse} },
		reason: "your organization maintains this machine's proxy routes, so they are not Observer's to take off: the daemon would put them back " +
			"and report each one to your organization as a removed route. Restart between AI turns with the routes left on " +
			"(observer service restart --keep-routes); the proxy is back within seconds",
	},
	{
		name:  "organization route posture unreadable",
		match: func(in RestartInputs) bool { return in.OrgUnknown && in.ProxyServing && !in.KeepRoutes },
		plan:  func(RestartInputs) RestartPlan { return RestartPlan{Mechanism: RestartRefuse} },
		reason: "Observer could not read whether your organization maintains this machine's proxy routes, and where it does, the daemon " +
			"would write the routes a restart takes off back as your organization's. Restart between AI turns with the routes left on " +
			"(observer service restart --keep-routes), or fix what could not be read",
	},
	{
		name: "proxy not at the resolved port",
		match: func(in RestartInputs) bool {
			return in.DashboardAnswers && in.ProxyExpected && !in.ProxyServing && !in.KeepRoutes
		},
		plan: func(RestartInputs) RestartPlan { return RestartPlan{Mechanism: RestartRefuse} },
		reason: "the daemon answers on its dashboard, but nothing answers on the proxy port Observer resolved for it, so Observer cannot " +
			"tell which AI tools route through it. Name the daemon's own config (--config), or restart between AI turns with the routes " +
			"left on (observer service restart --keep-routes)",
	},
	{
		name:  "systemd runs it",
		match: func(in RestartInputs) bool { return in.Manager == ManagerSystemd && in.UnitActive },
		plan: func(in RestartInputs) RestartPlan {
			return RestartPlan{Mechanism: RestartViaSystemd, HoldRoutes: hold(in)}
		},
		reason: "systemd runs the daemon, so systemd restarts it",
	},
	{
		name:  "launchd runs it",
		match: func(in RestartInputs) bool { return in.Manager == ManagerLaunchd && in.UnitActive },
		plan: func(in RestartInputs) RestartPlan {
			return RestartPlan{Mechanism: RestartViaLaunchd, HoldRoutes: hold(in)}
		},
		reason: "launchd runs the daemon, so launchd restarts it",
	},
	{
		name:  "running, restarts in place",
		match: func(in RestartInputs) bool { return in.DashboardAnswers && in.InPlaceSupported },
		plan: func(in RestartInputs) RestartPlan {
			return RestartPlan{Mechanism: RestartInPlace, HoldRoutes: hold(in)}
		},
		reason: "no service manager runs the daemon, so it restarts itself in place (same terminal, log and arguments)",
	},
	{
		name:  "running, cannot restart in place",
		match: func(in RestartInputs) bool { return in.DashboardAnswers },
		plan:  func(RestartInputs) RestartPlan { return RestartPlan{Mechanism: RestartRefuse} },
		reason: "no service manager runs the daemon and it cannot restart itself in place on this operating system " +
			"(a Windows daemon, including one started at sign-in, is not run by a service manager Observer can restart). " +
			"Restart it between AI turns: quit it (Ctrl-C in its terminal, or quit superbased) and start it again (observer start); " +
			"routes a restart left off go back on once its proxy answers",
	},
	{
		name:  "proxy without a dashboard",
		match: func(in RestartInputs) bool { return in.ProxyServing },
		plan:  func(RestartInputs) RestartPlan { return RestartPlan{Mechanism: RestartRefuse} },
		reason: "a daemon serves the proxy, but no service manager runs it and it answers no dashboard to restart itself through. " +
			"Stop it (Ctrl-C in its terminal) and run `observer start` again between AI turns",
	},
	{
		name:  "systemd unit stopped",
		match: func(in RestartInputs) bool { return in.Manager == ManagerSystemd && in.UnitInstalled },
		plan: func(RestartInputs) RestartPlan {
			return RestartPlan{Mechanism: RestartViaSystemd, StartOnly: true}
		},
		reason: "the service is installed but not running, so it is started (no proxy runs, so no route is taken off)",
	},
	{
		name:  "launchd agent stopped",
		match: func(in RestartInputs) bool { return in.Manager == ManagerLaunchd && in.UnitInstalled },
		plan: func(RestartInputs) RestartPlan {
			return RestartPlan{Mechanism: RestartViaLaunchd, StartOnly: true}
		},
		reason: "the agent is installed but not running, so it is started (no proxy runs, so no route is taken off)",
	},
	{
		name:   "nothing running",
		match:  func(RestartInputs) bool { return true },
		plan:   func(RestartInputs) RestartPlan { return RestartPlan{Mechanism: RestartNothing} },
		reason: "no Observer daemon is running for this configuration and no service is installed; start one with `observer start`",
	},
}

// DecideRestart walks restartRules top-down and returns the first match.
func DecideRestart(in RestartInputs) RestartPlan {
	for _, r := range restartRules {
		if r.match(in) {
			p := r.plan(in)
			p.Rule, p.Reason = r.name, r.reason
			return p
		}
	}
	return RestartPlan{Mechanism: RestartNothing, Rule: "none"}
}
