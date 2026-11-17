package secassess

import (
	"sort"
	"strings"
)

// Validator row V14: evidence from the request helper's log (depth plan W5b).
//
// The agent says how it knows (a finding's basis: "seen in a request" or "read
// from code"). Observer separately computes whether the helper's log backs the
// finding, in one of three words:
//
//	logged       a request the helper logged returned the indicated response in
//	             that copy of the application for the attack request and not for
//	             its control request. Shown as "Helper log matches".
//	unlogged     nothing in the log backs the finding, with a closed reason.
//	             Shown as "No log".
//	not_started  the application did not start, so nothing ran.
//
// What this is and is not. The log is a file in the live, agent-writable
// project tree. The agent runs as the same user with python and an editor and
// no Observer process sits between the helper and the target, so the log is a
// record the agent could have written by hand; Observer never calls it
// authentic, observed or confirmed. What the check does is narrower and it is
// all it claims: (1) the helper's two files hash to the bytes Observer wrote
// before the agent started (a changed helper or settings file makes every
// finding unlogged, because the agent could have changed what the helper
// logs); (2) the log reads like one the helper wrote (ids are line numbers,
// times never go backwards, no field the helper does not write); (3) a finding
// must be differential: it names an attack request and a control request and a
// condition that holds for the attack response and not for the control's.
// A log written by hand with the helper intact passes all three, and the
// words, the card and the plan say so.
//
// Three limits of those checks, stated here because the words cannot hold them:
//
//   - The hash check is of the files' state when the run is validated, not a
//     record of what happened in between. An agent that edits probe.py or raises
//     the budget in probe.json, sends requests, and puts the original bytes
//     back reads as "intact". No file time is kept either: a modification time
//     can be set back, and a check on it would only catch the careless edit.
//   - The "role" a record carries ("control", "attack") is the agent's own tag
//     and is not compared with the indicator: a finding names its two requests
//     by id and the card shows what the log marked each as, so a request tagged
//     "attack" can serve as the control and the reader sees it.
//   - A log read while the helper still runs may end in a line that was cut
//     short; the service reads it once more before the log counts as
//     inconsistent (ReadProbeFacts).

// EvidenceState is Observer's reading of a finding's evidence.
type EvidenceState string

// The evidence states.
const (
	EvidenceLogged     EvidenceState = "logged"
	EvidenceUnlogged   EvidenceState = "unlogged"
	EvidenceNotStarted EvidenceState = "not_started"
)

// The reason codes an unlogged or not-started finding carries. The web has one
// sentence for each (a test ties the two lists).
const (
	ReasonTargetNotStarted = "target_not_started"
	ReasonHelperOff        = "probe_helper_off"
	ReasonHelperWithheld   = "helper_withheld"
	ReasonHelperChanged    = "helper_changed"
	ReasonHelperMissing    = "helper_missing"
	ReasonLogAbsent        = "log_absent"
	ReasonLogUnreadable    = "log_unreadable"
	ReasonLogTooLarge      = "log_too_large"
	ReasonLogInconsistent  = "log_inconsistent"
	ReasonNoProbe          = "no_probe"
	ReasonProbeNotInLog    = "probe_not_in_log"
	ReasonProbeNotSent     = "probe_not_sent"
	ReasonProbeNoResponse  = "probe_no_response"
	ReasonNoIndicator      = "no_indicator"
	ReasonNoControl        = "no_control"
	ReasonNoCondition      = "no_condition"
	ReasonConditionNotMet  = "condition_not_met"
	ReasonNotDifferential  = "not_differential"
	// ReasonNotReplayed and ReasonConditionStillHolds belong to a retest result
	// (depth plan W7.2): the request named as the attack was not the helper's
	// replay of the finding, and a result that says the weakness is gone while the
	// log holds the earlier condition for the replayed request.
	ReasonNotReplayed         = "not_replayed"
	ReasonConditionStillHolds = "condition_still_holds"
	// ReasonReplayIncomplete: a result that says the weakness is gone for a finding
	// whose stored request had values hidden, so the replay was not the original request.
	ReasonReplayIncomplete = "replay_incomplete"
)

// EvidenceReasons lists every reason code, in the order the table can raise
// them.
var EvidenceReasons = []string{
	ReasonTargetNotStarted, ReasonHelperOff, ReasonHelperWithheld, ReasonHelperChanged, ReasonHelperMissing,
	ReasonLogAbsent, ReasonLogUnreadable, ReasonLogTooLarge, ReasonLogInconsistent,
	ReasonNoProbe, ReasonProbeNotInLog, ReasonProbeNotSent, ReasonProbeNoResponse,
	ReasonNoIndicator, ReasonNoControl, ReasonNoCondition, ReasonConditionNotMet, ReasonNotDifferential,
	ReasonNotReplayed, ReasonConditionStillHolds, ReasonReplayIncomplete,
}

// evCtx is what one finding's evidence is decided from.
type evCtx struct {
	started bool
	helper  string // the HelperState word
	mode    string
	log     string // the log state word
	byID    map[string]*ProbeRecord
	f       *PTFinding
	// cited are the probe ids the finding names, in order, without repeats.
	cited []string
	// attack and control are the indicator's records, nil when absent from the
	// log; view turns a record into the form a condition is checked against.
	attack, control *ProbeRecord
	view            func(*ProbeRecord) probeView
	// replay is the finding id a retest result's attack request must be the
	// helper's replay of ("" for a penetration test finding).
	replay string
	// hidden says a retest finding's stored request had values hidden.
	hidden bool
}

// probeView is the part of a record a condition is checked against, in the
// same cleaned form the condition's own text went through. bodies holds the
// forms the body is looked at in (bodyViewRows, matchviews.go) and headers the
// response headers in the form the card shows them (credential-named values
// hidden, headers.go).
type probeView struct {
	status  int
	bodies  []string
	headers []ProbeHeader
}

// evRow is one row of the evidence table: the first row whose Hit holds decides
// the finding's evidence. Every row has a test case.
type evRow struct {
	ID     string
	Reason string
	State  EvidenceState
	Hit    func(*evCtx) bool
}

// evidenceRows is the V14 table, top to bottom.
var evidenceRows = []evRow{
	{"E1", ReasonTargetNotStarted, EvidenceNotStarted, func(c *evCtx) bool { return !c.started }},
	{"E2", ReasonHelperOff, EvidenceUnlogged, func(c *evCtx) bool { return c.mode != HelperOn && c.mode != HelperWithheld }},
	{"E3", ReasonHelperWithheld, EvidenceUnlogged, func(c *evCtx) bool { return c.mode == HelperWithheld }},
	{"E4", ReasonHelperChanged, EvidenceUnlogged, func(c *evCtx) bool { return c.helper == HelperChanged }},
	{"E5", ReasonHelperMissing, EvidenceUnlogged, func(c *evCtx) bool { return c.helper == HelperMissing }},
	{"E6", ReasonLogAbsent, EvidenceUnlogged, func(c *evCtx) bool { return c.log == LogFileAbsent || c.log == LogFileNotRead }},
	{"E7", ReasonLogUnreadable, EvidenceUnlogged, func(c *evCtx) bool { return c.log == LogFileUnreadable }},
	{"E8", ReasonLogTooLarge, EvidenceUnlogged, func(c *evCtx) bool { return c.log == LogFileTooLarge }},
	{"E9", ReasonLogInconsistent, EvidenceUnlogged, func(c *evCtx) bool { return c.log == LogFileInconsistent }},
	{"E10", ReasonNoProbe, EvidenceUnlogged, func(c *evCtx) bool { return len(c.cited) == 0 }},
	{"E11", ReasonProbeNotInLog, EvidenceUnlogged, func(c *evCtx) bool { return c.anyCited(func(r *ProbeRecord) bool { return r == nil }) }},
	{"E12", ReasonProbeNotSent, EvidenceUnlogged, func(c *evCtx) bool {
		return c.anyCited(func(r *ProbeRecord) bool { return r != nil && !r.Sent })
	}},
	{"E13", ReasonProbeNoResponse, EvidenceUnlogged, func(c *evCtx) bool {
		return c.anyCited(func(r *ProbeRecord) bool { return r != nil && r.Sent && r.Status <= 0 })
	}},
	{"E14", ReasonNoIndicator, EvidenceUnlogged, func(c *evCtx) bool { return c.f.Indicator == nil || c.f.Indicator.Attack == "" }},
	{"E15", ReasonNoControl, EvidenceUnlogged, func(c *evCtx) bool {
		return c.f.Indicator.Control == "" || c.f.Indicator.Control == c.f.Indicator.Attack
	}},
	{"E16", ReasonNoCondition, EvidenceUnlogged, func(c *evCtx) bool { return c.f.Indicator.When == nil || c.f.Indicator.When.Empty() }},
	{"E17", ReasonConditionNotMet, EvidenceUnlogged, func(c *evCtx) bool { return !c.holds(c.attack) }},
	{"E18", ReasonNotDifferential, EvidenceUnlogged, func(c *evCtx) bool { return c.holds(c.control) }},
	{"E19", "", EvidenceLogged, func(*evCtx) bool { return true }},
}

// anyCited reports whether pred holds for the log's record of any cited id (nil
// for an id the log does not hold).
func (c *evCtx) anyCited(pred func(*ProbeRecord) bool) bool {
	for _, id := range c.cited {
		if pred(c.byID[id]) {
			return true
		}
	}
	return false
}

// holds reports whether the finding's condition holds for a record.
func (c *evCtx) holds(r *ProbeRecord) bool {
	if r == nil {
		return false
	}
	return c.f.Indicator.When.holdsView(c.view(r))
}

// Holds reports whether every part of the condition that is set holds for a
// logged response. An empty condition holds for nothing.
func (m PTMatch) Holds(status int, body string, headers []ProbeHeader) bool {
	return m.holdsView(probeView{status: status, bodies: bodyForms(body, nil), headers: headers})
}

func (m PTMatch) holdsView(p probeView) bool {
	if m.Empty() {
		return false
	}
	if m.Status != 0 && p.status != m.Status {
		return false
	}
	for _, s := range m.BodyContains {
		if !anyContains(p.bodies, s) {
			return false
		}
	}
	for _, s := range m.BodyNotContains {
		if anyContains(p.bodies, s) {
			return false
		}
	}
	for _, n := range m.HeaderPresent {
		if !hasHeader(p.headers, n) {
			return false
		}
	}
	for _, n := range m.HeaderAbsent {
		if hasHeader(p.headers, n) {
			return false
		}
	}
	for _, h := range m.HeaderContains {
		if !headerHolds(p.headers, h) {
			return false
		}
	}
	return true
}

// hasHeader reports whether a header of that name is among hs.
func hasHeader(hs []ProbeHeader, name string) bool {
	for _, h := range hs {
		if strings.EqualFold(h.N, name) {
			return true
		}
	}
	return false
}

// headerHolds reports whether a header of that name has a value that contains
// the text.
func headerHolds(hs []ProbeHeader, want PTHeader) bool {
	for _, h := range hs {
		if strings.EqualFold(h.N, want.Name) && strings.Contains(strings.ToLower(h.V), strings.ToLower(want.Value)) {
			return true
		}
	}
	return false
}

// EvidenceReport is what V14 found, for the card: the helper's state, the
// log's, the counts of its records and the findings by evidence.
type EvidenceReport struct {
	Mode   string `json:"mode"`
	Helper string `json:"helper"`
	Log    string `json:"log"`
	// Records, Sent, Refused and Requests count the log (ProbeLogSummary); a log
	// that was not used reads zero.
	Records  int `json:"records"`
	Sent     int `json:"sent"`
	Refused  int `json:"refused"`
	Requests int `json:"requests"`
	// Logged, Unlogged and NotStarted count the findings by evidence; ByReason
	// counts the unlogged and not-started ones by their reason code.
	Logged     int            `json:"logged"`
	Unlogged   int            `json:"unlogged"`
	NotStarted int            `json:"not_started"`
	ByReason   map[string]int `json:"by_reason,omitempty"`
}

// evidenceWalk decides one finding's evidence: the first row of the table that
// holds. It returns the state, the reason code and the id of the row.
func evidenceWalk(c *evCtx) (EvidenceState, string, string) {
	for _, r := range evidenceRows {
		if r.Hit(c) {
			return r.State, r.Reason, r.ID
		}
	}
	return EvidenceUnlogged, ReasonNoProbe, "" // unreachable: E19 always holds
}

// citedProbes lists the probe ids a finding names: its evidence list and the
// indicator's two, in order, without repeats.
func citedProbes(f *PTFinding) []string {
	var out []string
	seen := map[string]bool{}
	add := func(id string) {
		if id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for _, id := range f.Evidence {
		add(id)
	}
	if f.Indicator != nil {
		add(f.Indicator.Attack)
		add(f.Indicator.Control)
	}
	return out
}

// CitedProbes lists every probe id the model's findings and coverage rows name,
// sorted by their position in the log (the id's number), without repeats.
func CitedProbes(p *PentestDoc) []string {
	seen := map[string]bool{}
	var ids []string
	add := func(id string) {
		if id != "" && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for i := range p.Findings {
		for _, id := range citedProbes(&p.Findings[i]) {
			add(id)
		}
	}
	for _, c := range p.Coverage {
		for _, id := range c.Probes {
			add(id)
		}
	}
	sort.SliceStable(ids, func(i, j int) bool { return probeNumber(ids[i]) < probeNumber(ids[j]) })
	return ids
}

// probeNumber is the number in a probe id ("p12" is 12); an id that is not "p"
// and digits sorts after the others.
func probeNumber(id string) int {
	n := 0
	if len(id) < 2 || id[0] != 'p' {
		return 1 << 30
	}
	for _, c := range id[1:] {
		if c < '0' || c > '9' || n > 1<<28 {
			return 1 << 30
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// evBase is what row V14 and the retest's evidence row read alike: the
// helper's reading, the log and a record's response in the cleaned form a
// condition is checked against.
type evBase struct {
	rep   *EvidenceReport
	state string
	mode  string
	byID  map[string]*ProbeRecord
	view  func(*ProbeRecord) probeView
}

// evidenceBase reads the helper's facts and the log once for a validation.
func (v *validator) evidenceBase() evBase {
	pf := v.o.Probe
	log := pf.Log
	state := pf.logState()
	if state != LogFileOK {
		log = ProbeLog{}
	}
	rep := &EvidenceReport{Mode: pf.Mode, Helper: pf.HelperState(), Log: state}
	if rep.Mode == "" {
		rep.Mode = HelperOff
	}
	s := log.Summary()
	rep.Records, rep.Sent, rep.Refused, rep.Requests = s.Records, s.Sent, s.Refused, s.Requests
	// A record's response is looked at in the same cleaned form the agent's
	// condition went through, so a text the redactor or the cleaner changed in
	// one is changed in the other. The body is looked at in each form of
	// bodyViewRows; a header value is the form the card shows (a
	// credential-named header's value hidden by its name, as the helper writes
	// it), so a log line with a value the helper would have hidden is compared
	// as the card shows it.
	views := map[*ProbeRecord]probeView{}
	view := func(r *ProbeRecord) probeView {
		if pv, ok := views[r]; ok {
			return pv
		}
		pv := probeView{status: r.Status, bodies: bodyForms(r.BodyExcerpt, func(s string) string { return v.redactClean(s, 1<<20) })}
		for _, h := range r.RespHeaders {
			pv.headers = append(pv.headers, ProbeHeader{N: h.N, V: v.redactClean(hiddenHeaderValue(h.N, h.V, v.o.Redact), 1<<10)})
		}
		views[r] = pv
		return pv
	}
	return evBase{rep: rep, state: state, mode: pf.Mode, byID: log.byID(), view: view}
}

// tally counts one finding's evidence in the report.
func (r *EvidenceReport) tally(st EvidenceState, reason string) {
	switch st {
	case EvidenceLogged:
		r.Logged++
	case EvidenceNotStarted:
		r.NotStarted++
	default:
		r.Unlogged++
	}
	if reason != "" {
		if r.ByReason == nil {
			r.ByReason = map[string]int{}
		}
		r.ByReason[reason]++
	}
}

func ruleV14(v *validator) {
	p := v.pt
	if p == nil {
		return
	}
	b := v.evidenceBase()
	started := p.Target.Start.Started
	for i := range p.Findings {
		f := &p.Findings[i]
		c := &evCtx{started: started, helper: b.rep.Helper, mode: b.mode, log: b.state, byID: b.byID, f: f, cited: citedProbes(f), view: b.view}
		if f.Indicator != nil {
			c.attack, c.control = b.byID[f.Indicator.Attack], b.byID[f.Indicator.Control]
		}
		st, reason, _ := evidenceWalk(c)
		f.EvidenceState, f.EvidenceReason = st, reason
		b.rep.tally(st, reason)
	}
	v.rep.Evidence = b.rep
	promoteCoverage(v, b.rep, b.byID)
}

// usable says the log can back anything: the helper ran and is intact and the
// log reads like the helper's.
func (r *EvidenceReport) usable() bool {
	return r.Mode == HelperOn && r.Helper == HelperIntact && r.Log == LogFileOK
}

// promoteCoverage turns a coverage row the agent marked tested into "tested,
// with a logged request" when the log backs it: a category whose cited probes
// include a request that reached the target, or one the log holds a request
// tagged with. The tag is the agent's own, like the citation; the row says a
// logged request exists for the category, not that the category was covered.
func promoteCoverage(v *validator, rep *EvidenceReport, byID map[string]*ProbeRecord) {
	cov := v.rep.PT
	if cov == nil || !cov.Started || !rep.usable() {
		return
	}
	tagged := map[string]bool{}
	for _, r := range byID {
		if r.Backs() && r.WSTG != "" {
			tagged[r.WSTG] = true
		}
	}
	cited := map[string][]string{}
	for _, c := range v.pt.Coverage {
		cited[c.Category] = c.Probes
	}
	for i := range cov.Rows {
		row := &cov.Rows[i]
		if row.Effective != CovTestedClaimed {
			continue
		}
		backed := tagged[row.Category]
		for _, id := range cited[row.Category] {
			if r := byID[id]; r != nil && r.Backs() {
				backed = true
			}
		}
		if backed {
			row.Effective = CovTestedLogged
			cov.Counts[CovTestedClaimed]--
			cov.Counts[CovTestedLogged]++
		}
	}
	if cov.Counts[CovTestedClaimed] == 0 {
		delete(cov.Counts, CovTestedClaimed)
	}
}
