package hookliveness

import (
	"sort"
	"time"
)

// Activity is one hook_activity row: how often (tool, event) fired for one
// session. SessionID "" is the unattributed bucket.
type Activity struct {
	Tool       string
	Event      string
	SessionID  string
	Count      int64
	FirstAt    time.Time
	LastAt     time.Time
	EnvClasses map[string]string
}

// EventSpec is one registry hook binding of a tool (internal/integration
// HookBinding, reduced to what liveness needs).
type EventSpec struct {
	// Native is the vendor's event name, the spelling activity rows carry.
	Native string
	// Registered is true when Observer writes the event into the vendor
	// config today.
	Registered bool
	// SessionKey is true when the event's payload carries a session id.
	SessionKey bool
}

// Session is one captured session the watcher or proxy recorded.
type Session struct {
	ID        string
	Surface   string
	StartedAt time.Time
}

// ToolInput is everything Classify judges one tool on.
type ToolInput struct {
	Tool     string
	Events   []EventSpec
	Activity []Activity
	Sessions []Session
	// DisabledSwitches names the vendor file switches (internal/hookdisable)
	// that turn this tool's hooks off on this node.
	DisabledSwitches []string
}

// Options are the node-wide inputs of one classification.
type Options struct {
	// Epoch is the first hook activity this node recorded under any tool
	// (zero when it has none): a session that started before it cannot be
	// judged, because activity was not being recorded yet.
	Epoch time.Time
	// Now is the classification time.
	Now time.Time
	// Settle is how long after a session starts before it is judged, so a
	// session whose first hooks are still in the spool is not called silent.
	// Zero means DefaultSettle.
	Settle time.Duration
}

// DefaultSettle covers the spool's drain interval and grace several times
// over (5 s ticker, 2 s grace).
const DefaultSettle = 2 * time.Minute

// Severity orders verdicts for rendering.
type Severity int

const (
	// SeverityNone is a tool with nothing to report (no hook surface, idle).
	SeverityNone Severity = iota
	// SeverityOK is a tool whose hooks are proven to fire.
	SeverityOK
	// SeverityInfo is a limit of what can be proven, not a fault.
	SeverityInfo
	// SeverityWarn is a tool whose hooks should be firing and are not.
	SeverityWarn
)

// Rule names one row of the tool rule table.
type Rule string

// The tool rules, in table order.
const (
	RuleNoHookSurface      Rule = "no_hook_surface"
	RuleDisabledSwitch     Rule = "hooks_disabled_switch"
	RuleNotYetObserved     Rule = "not_yet_observed"
	RuleIdle               Rule = "idle"
	RuleNeverSeen          Rule = "hooks_never_seen"
	RuleNoSessionKey       Rule = "no_session_key"
	RuleUnattributedOnly   Rule = "unattributed_only"
	RuleSessionIDsUnjoined Rule = "session_ids_unjoined"
	RuleSilentOnSurface    Rule = "hooks_silent_on_surface"
	RuleSilentSomeSessions Rule = "hooks_silent_some_sessions"
	RuleOK                 Rule = "ok"
)

// EventRule names one row of the per-event rule table.
type EventRule string

// The event rules, in table order.
const (
	EventSeenUnregistered EventRule = "seen_unregistered"
	EventNotRegistered    EventRule = "not_registered"
	EventSeen             EventRule = "seen"
	EventSeenUnattributed EventRule = "seen_unattributed"
	EventNeverSeen        EventRule = "never_seen"
)

// EventVerdict is one event's state on one tool.
type EventVerdict struct {
	Event string
	Rule  EventRule
	Count int64
}

// Verdict is one tool's liveness.
type Verdict struct {
	Tool     string
	Rule     Rule
	Severity Severity
	// JudgedSessions are the captured sessions the rule was decided over
	// (started after the epoch and settled); SilentSessions the ones with no
	// attributed hook activity; SilentSurfaces the surfaces on which every
	// judged session was silent (sorted). ExampleSilent is one silent id.
	JudgedSessions int
	SilentSessions int
	SilentSurfaces []string
	ExampleSilent  string
	// Unattributed is the invocation count in the unattributed bucket.
	Unattributed int64
	// Events is the per-event verdict, registered events first in binding
	// order, then unregistered events seen, sorted.
	Events []EventVerdict
	// EnvSessions counts, per env variable name and class, the distinct
	// attributed sessions whose hooks saw that class (CC-2 route truth).
	EnvSessions map[string]map[string]int
	// DisabledSwitches echoes the input, for the rendered reason.
	DisabledSwitches []string
	// OutOfFileSwitches names the switches outside any file that would
	// explain silence (OutOfFileSwitches), for never_seen and silent rules.
	OutOfFileSwitches []string
}

// OutOfFileSwitches lists, per tool, the command-line or environment
// switches that turn hooks off and live in no file internal/hookdisable can
// read (review W-3b). Data for the rendered reason only: no rule branches on
// it.
var OutOfFileSwitches = map[string][]string{
	"dimcode":     {"--no-hooks", "DIM_DISABLE_HOOKS"},
	"cortex-code": {"--setting-sources"},
	"vtcode":      {"vtcode exec (headless runs skip hooks)"},
	"autohand":    {"--bare"},
}

// facts are the derived quantities the rules read.
type facts struct {
	registered     int
	sessionKey     bool
	activityTotal  int64
	unattributed   int64
	attributed     map[string]bool
	judged         []Session
	silent         []Session
	joined         bool
	silentSurfaces []string
	epochZero      bool
	switches       int
}

// toolRule is one row of the tool rule table, walked top-down.
type toolRule struct {
	rule     Rule
	severity Severity
	match    func(f facts) bool
}

var toolRules = []toolRule{
	{RuleNoHookSurface, SeverityNone, func(f facts) bool { return f.registered == 0 && f.activityTotal == 0 }},
	{RuleDisabledSwitch, SeverityWarn, func(f facts) bool { return f.switches > 0 }},
	{RuleNotYetObserved, SeverityInfo, func(f facts) bool { return f.epochZero }},
	{RuleIdle, SeverityNone, func(f facts) bool { return len(f.judged) == 0 && f.activityTotal == 0 }},
	{RuleNeverSeen, SeverityWarn, func(f facts) bool { return f.activityTotal == 0 }},
	{RuleNoSessionKey, SeverityInfo, func(f facts) bool { return !f.sessionKey && len(f.attributed) == 0 }},
	{RuleUnattributedOnly, SeverityInfo, func(f facts) bool { return len(f.attributed) == 0 }},
	{RuleSessionIDsUnjoined, SeverityInfo, func(f facts) bool { return len(f.judged) > 0 && !f.joined }},
	{RuleSilentOnSurface, SeverityWarn, func(f facts) bool { return len(f.silentSurfaces) > 0 }},
	{RuleSilentSomeSessions, SeverityInfo, func(f facts) bool { return len(f.silent) > 0 }},
	{RuleOK, SeverityOK, func(facts) bool { return true }},
}

// eventFacts are what the event rules read.
type eventFacts struct {
	registered   bool
	attributed   int64
	unattributed int64
}

type eventRule struct {
	rule  EventRule
	match func(e eventFacts) bool
}

var eventRules = []eventRule{
	{EventSeenUnregistered, func(e eventFacts) bool { return !e.registered && e.attributed+e.unattributed > 0 }},
	{EventNotRegistered, func(e eventFacts) bool { return !e.registered }},
	{EventSeen, func(e eventFacts) bool { return e.attributed > 0 }},
	{EventSeenUnattributed, func(e eventFacts) bool { return e.unattributed > 0 }},
	{EventNeverSeen, func(eventFacts) bool { return true }},
}

func decideEvent(e eventFacts) EventRule {
	for _, r := range eventRules {
		if r.match(e) {
			return r.rule
		}
	}
	return EventNeverSeen
}

// Classify judges one tool.
func Classify(in ToolInput, opts Options) Verdict {
	f, events, env := derive(in, opts)
	v := Verdict{
		Tool:             in.Tool,
		JudgedSessions:   len(f.judged),
		SilentSessions:   len(f.silent),
		SilentSurfaces:   f.silentSurfaces,
		Unattributed:     f.unattributed,
		Events:           events,
		EnvSessions:      env,
		DisabledSwitches: in.DisabledSwitches,
	}
	if len(f.silent) > 0 {
		v.ExampleSilent = f.silent[0].ID
	}
	for _, r := range toolRules {
		if r.match(f) {
			v.Rule, v.Severity = r.rule, r.severity
			break
		}
	}
	if v.Rule == RuleNeverSeen || v.Rule == RuleSilentOnSurface || v.Rule == RuleSilentSomeSessions {
		v.OutOfFileSwitches = OutOfFileSwitches[in.Tool]
	}
	return v
}

// ClassifyAll judges every tool, sorted by severity (worst first) then tool.
func ClassifyAll(ins []ToolInput, opts Options) []Verdict {
	out := make([]Verdict, 0, len(ins))
	for _, in := range ins {
		out = append(out, Classify(in, opts))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		return out[i].Tool < out[j].Tool
	})
	return out
}

func derive(in ToolInput, opts Options) (facts, []EventVerdict, map[string]map[string]int) {
	settle := opts.Settle
	if settle == 0 {
		settle = DefaultSettle
	}
	f := facts{attributed: map[string]bool{}, epochZero: opts.Epoch.IsZero(), switches: len(in.DisabledSwitches)}
	registered := map[string]bool{}
	var order []string
	for _, e := range in.Events {
		if !e.Registered {
			continue
		}
		f.registered++
		if e.SessionKey {
			f.sessionKey = true
		}
		if !registered[e.Native] {
			registered[e.Native] = true
			order = append(order, e.Native)
		}
	}
	perEvent := map[string]*eventFacts{}
	env := map[string]map[string]map[string]bool{}
	for _, a := range in.Activity {
		ef := perEvent[a.Event]
		if ef == nil {
			ef = &eventFacts{registered: registered[a.Event]}
			perEvent[a.Event] = ef
		}
		f.activityTotal += a.Count
		if a.SessionID == "" {
			f.unattributed += a.Count
			ef.unattributed += a.Count
			continue
		}
		ef.attributed += a.Count
		f.attributed[a.SessionID] = true
		for name, class := range a.EnvClasses {
			if env[name] == nil {
				env[name] = map[string]map[string]bool{}
			}
			if env[name][class] == nil {
				env[name][class] = map[string]bool{}
			}
			env[name][class][a.SessionID] = true
		}
	}

	bySurface := map[string][2]int{} // judged, silent
	for _, s := range in.Sessions {
		// A session with attributed activity is observed whatever its start:
		// its own first hook fires after it starts, so the session that set
		// the epoch starts before it. Only a session WITHOUT activity is
		// left unjudged before the epoch or inside the settle margin.
		observed := f.attributed[s.ID]
		if f.epochZero || (!observed && (s.StartedAt.Before(opts.Epoch) || opts.Now.Sub(s.StartedAt) < settle)) {
			continue
		}
		f.judged = append(f.judged, s)
		c := bySurface[s.Surface]
		c[0]++
		if f.attributed[s.ID] {
			f.joined = true
		} else {
			f.silent = append(f.silent, s)
			c[1]++
		}
		bySurface[s.Surface] = c
	}
	for surface, c := range bySurface {
		if c[0] > 0 && c[0] == c[1] {
			if surface == "" {
				surface = "unknown"
			}
			f.silentSurfaces = append(f.silentSurfaces, surface)
		}
	}
	sort.Strings(f.silentSurfaces)

	var events []EventVerdict
	for _, name := range order {
		ef := perEvent[name]
		if ef == nil {
			ef = &eventFacts{registered: true}
		}
		events = append(events, EventVerdict{Event: name, Rule: decideEvent(*ef), Count: ef.attributed + ef.unattributed})
	}
	var extra []string
	for name, ef := range perEvent {
		if !ef.registered {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	for _, name := range extra {
		ef := perEvent[name]
		events = append(events, EventVerdict{Event: name, Rule: decideEvent(*ef), Count: ef.attributed + ef.unattributed})
	}

	var envOut map[string]map[string]int
	for name, classes := range env {
		if envOut == nil {
			envOut = map[string]map[string]int{}
		}
		envOut[name] = map[string]int{}
		for class, sessions := range classes {
			envOut[name][class] = len(sessions)
		}
	}
	return f, events, envOut
}
