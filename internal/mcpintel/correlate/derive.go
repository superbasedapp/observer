package correlate

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

// Heuristic window: an MCP action may precede the relay's decision record by
// up to InferWindowBefore (the model emits the tool_use, the client then
// sends the request) and trail it by up to InferWindowAfter (clock skew and
// transcript timestamp rounding).
const (
	InferWindowBefore = 120 * time.Second
	InferWindowAfter  = 5 * time.Second
)

// InferSessionSeparation is how much closer (in time) the best candidate of
// one session must sit to an UNANCHORED call than the best candidate of any
// other session before the call is attributed to that session. Inside the
// separation the call is ambiguous and is attached to no session (it is
// never guessed, and never shown on two sessions).
const InferSessionSeparation = 10 * time.Second

// actionTypeMCPCall / actionTypeUserPrompt are the normalized action types
// (internal/models ActionMCPCall / ActionUserPrompt) - duplicated as data so
// this pure package does not import models.
const (
	actionTypeMCPCall    = "mcp_call"
	actionTypeUserPrompt = "user_prompt"
	actionTypeUnknown    = "unknown"
)

// Derive folds the records into de-duplicated calls, links each call to the
// session through the ordered rules table, and returns the calls whose link
// is not none, oldest first. It never fails: missing data degrades the
// confidence, it never fabricates one.
func Derive(in DeriveInput) Result {
	res := Result{SessionID: in.SessionID, Calls: []Call{}}
	groups, folded := groupRecords(in.Records)
	res.Totals.FoldedDuplicates = folded
	idx := newSessionIndex(in.SessionID, in.Actions)
	idx.addPool(in.Pool, in.AnchoredKeys)

	pend := make([]*pending, 0, len(groups))
	for _, g := range groups {
		if g.call == nil {
			continue // completion-only group: nothing anchors it
		}
		pend = append(pend, g)
	}
	sort.SliceStable(pend, func(i, j int) bool {
		a, b := pend[i].call, pend[j].call
		if a.TS != b.TS {
			return a.TS < b.TS
		}
		return a.CallID < b.CallID
	})
	// Phase 0: every anchored rule for every call (id matches claim their
	// action first, so a heuristic can never steal an exactly-anchored one).
	// Phase 1: the anchored-session heuristics for the calls phase 0
	// deferred, oldest first. Phase 2: the UNANCHORED tier (a relay call that
	// carried no anchor at all), oldest first, after every anchored call has
	// claimed its action.
	deferred := pend
	for phase := phaseAnchored; phase <= phaseUnanchored; phase++ {
		var next []*pending
		for _, p := range deferred {
			if !p.resolve(idx, phase) {
				next = append(next, p)
			}
		}
		deferred = next
	}
	for _, p := range pend {
		if p.drop {
			continue // an unanchored call this session has no claim on
		}
		if p.link.Confidence == None {
			res.Totals.Unlinked++
			if p.link.Method == MethodUnanchoredAmbiguous {
				res.Totals.Ambiguous++
			}
			continue
		}
		p.link.PromptKey = idx.promptFor(p.link)
		p.call.Correlation = p.link
		switch p.link.Confidence {
		case Exact:
			res.Totals.Exact++
		case Inferred:
			res.Totals.Inferred++
		}
		res.Calls = append(res.Calls, *p.call)
	}
	res.Totals.Calls = len(res.Calls)
	if in.Limit > 0 && len(res.Calls) > in.Limit {
		res.Calls, res.Truncated = res.Calls[:in.Limit], true
	}
	return res
}

// pending is one de-duplicated call on its way through the rules.
type pending struct {
	call *Call
	// trusted is true when at least one decision copy came over a trusted
	// carrier; anchors are merged from trusted copies only.
	trusted bool
	// next is the rules-table row a later phase resumes at.
	next int
	link Link
	// drop is set by the unanchored tier for a call that belongs to no
	// candidate set of this session (another session owns it, or nothing
	// here matches): it is neither attached nor counted.
	drop bool
}

// Rule phases: a row runs only in its phase or later, so the rows of an
// earlier phase claim actions before any row of a later one.
const (
	phaseAnchored   = 0 // id / anchor rows
	phaseHeuristic  = 1 // heuristics inside an anchored session
	phaseUnanchored = 2 // the unanchored tier
)

// resolve walks the rules table from p.next in the given phase: it skips a
// row whose applies predicate is false, stops at the first applicable row of
// a LATER phase and reports false (deferred), and otherwise returns true at
// the first match. The last row always matches.
func (p *pending) resolve(idx *sessionIndex, phase int) bool {
	for i := p.next; i < len(rules); i++ {
		r := rules[i]
		if r.applies != nil && !r.applies(p) {
			continue
		}
		if r.phase > phase {
			p.next = i
			return false
		}
		if l, ok := r.match(idx, p); ok {
			if l.Method == "" {
				l.Method = r.name
			}
			p.link = l
			return true
		}
	}
	p.link = Link{Confidence: None, Level: LevelNone, Method: MethodNoAnchor}
	return true
}

// rule is one row of the ordered correlation table (CLAUDE.md #5: decision
// logic is a table walked top-down, one test case per row).
type rule struct {
	name  string
	phase int
	// applies, when set, restricts the row to the calls it holds for; a row
	// that does not apply is skipped (it neither matches nor defers).
	applies func(p *pending) bool
	match   func(idx *sessionIndex, p *pending) (Link, bool)
}

// rules is THE correlation table, walked top-down; the first match wins.
var rules = []rule{
	// 1. A direct OAuth / API-key client, or any carrier the seam does not
	//    trust: its anchors are ignored, the call is never attached.
	{MethodUntrusted, phaseAnchored, nil, func(_ *sessionIndex, p *pending) (Link, bool) {
		return noneLink(), !p.trusted
	}},
	// 2. action_ref names one of THIS session's actions by its key (the
	//    tool-use id): exact, and it outranks a (possibly stale) session env.
	{MethodActionRef, phaseAnchored, nil, func(idx *sessionIndex, p *pending) (Link, bool) {
		a := idx.byKey[p.call.ActionRef]
		if p.call.ActionRef == "" || a == nil {
			return Link{}, false
		}
		idx.claim(a)
		return actionLink(Exact, a), true
	}},
	// 3. action_ref names a message of this session: the single MCP action
	//    of that message (narrowed by tool name) is exact; several -> the
	//    message pins the turn exactly. A protocol record (!invokesTool)
	//    never claims: the message pins its turn.
	{MethodActionRefMessage, phaseAnchored, nil, func(idx *sessionIndex, p *pending) (Link, bool) {
		acts := idx.byMessage[p.call.ActionRef]
		if p.call.ActionRef == "" || len(acts) == 0 {
			return Link{}, false
		}
		if !p.call.invokesTool() {
			return turnLink(Exact, acts[0]), true
		}
		if a := idx.unique(acts, p.call); a != nil {
			idx.claim(a)
			return actionLink(Exact, a), true
		}
		return turnLink(Exact, acts[0]), true
	}},
	// 4. Anchored to ANOTHER session and no action of this one: none.
	{MethodSessionMismatch, phaseAnchored, nil, func(idx *sessionIndex, p *pending) (Link, bool) {
		return noneLink(), p.call.CodingSessionID != "" && p.call.CodingSessionID != idx.sessionID
	}},
	// 5. UNANCHORED tier: a trusted relay call that carried NO anchor at all
	//    (no session, action or turn ref - a client that sends no tool-use id
	//    over a transport with no session env, e.g. OpenCode on the loopback
	//    relay). The node / owner-wide candidate pool decides which session
	//    owns it (unanchoredOwner: the session whose captured tool call names
	//    the call's tool + server closest in time, clearly ahead of every
	//    other session); in THAT session the nearest unclaimed such action is
	//    an inferred action link. A protocol record (!invokesTool) is owned
	//    by server name + time the same way but stays at session level and
	//    never claims. Always terminal: an unanchored call never reaches the
	//    anchored-session rows below.
	{MethodUnanchoredToolTime, phaseUnanchored, func(p *pending) bool { return p.unanchored() }, func(idx *sessionIndex, p *pending) (Link, bool) {
		return idx.resolveUnanchored(p), true
	}},
	// 6. No session anchor (and no action anchor matched above): none.
	{MethodNoAnchor, phaseAnchored, nil, func(_ *sessionIndex, p *pending) (Link, bool) {
		return noneLink(), p.call.CodingSessionID == ""
	}},
	// 7. The session is anchored but the carried action_ref names nothing
	//    here (not ingested yet, or the env session went stale after a
	//    /clear): the session is only INFERRED, never guessed down to a turn.
	{MethodActionRefUnresolved, phaseAnchored, nil, func(_ *sessionIndex, p *pending) (Link, bool) {
		if p.call.ActionRef == "" {
			return Link{}, false
		}
		return Link{Confidence: Inferred, Level: LevelSession}, true
	}},
	// 8. turn_ref pins a turn of this session: exact at turn level, or the
	//    single matching MCP action of that turn at action level (inferred);
	//    a protocol record (!invokesTool) stays at the turn.
	{MethodTurnRef, phaseAnchored, nil, func(idx *sessionIndex, p *pending) (Link, bool) {
		acts := idx.turn(p.call.TurnRef)
		if len(acts) == 0 {
			return Link{}, false
		}
		if !p.call.invokesTool() {
			return turnLink(Exact, acts[0]), true
		}
		if a := idx.unique(acts, p.call); a != nil {
			idx.claim(a)
			l := actionLink(Inferred, a)
			l.Method = MethodTurnRefTool
			return l, true
		}
		return turnLink(Exact, acts[0]), true
	}},
	// 9. Heuristic: the closest unclaimed MCP action with the same tool name
	//    inside the time window of the anchored session (tool invocations
	//    only - a protocol record never claims an action).
	{MethodSessionToolTime, phaseHeuristic, nil, func(idx *sessionIndex, p *pending) (Link, bool) {
		if p.call.Tool == "" || !p.call.invokesTool() {
			return Link{}, false
		}
		a := idx.nearest(p.call, true)
		if a == nil {
			return Link{}, false
		}
		idx.claim(a)
		return actionLink(Inferred, a), true
	}},
	// 10. Heuristic without a captured tool name (below L2): only when ONE
	//    unclaimed MCP action sits inside the window, and only for a tool
	//    invocation (a nameless initialize / notifications/* / tools/list
	//    would otherwise claim the action its session's tools/call owns).
	{MethodSessionTime, phaseHeuristic, nil, func(idx *sessionIndex, p *pending) (Link, bool) {
		if p.call.Tool != "" || !p.call.invokesTool() {
			return Link{}, false
		}
		a := idx.nearest(p.call, false)
		if a == nil {
			return Link{}, false
		}
		idx.claim(a)
		return actionLink(Inferred, a), true
	}},
	// 11. The relay anchored the session and nothing finer resolved.
	{MethodSessionOnly, phaseAnchored, nil, func(_ *sessionIndex, _ *pending) (Link, bool) {
		return Link{Confidence: Exact, Level: LevelSession}, true
	}},
}

func noneLink() Link { return Link{Confidence: None, Level: LevelNone} }

func actionLink(c Confidence, a *indexedAction) Link {
	return Link{Confidence: c, Level: LevelAction, ActionKey: a.Key, MessageID: a.MessageID, TurnIndex: a.TurnIndex, TurnID: a.TurnID}
}

func turnLink(c Confidence, a *indexedAction) Link {
	return Link{Confidence: c, Level: LevelTurn, MessageID: a.MessageID, TurnIndex: a.TurnIndex, TurnID: a.TurnID}
}

// --- grouping (de-dup on call_id) -------------------------------------------

// groupRecords folds records sharing a call_id into one pending call. A
// record with no call_id - or from an UNTRUSTED carrier - is its own group:
// a non-relay caller must never be able to fold its row (and its verdict,
// args or result) into a relay call by reusing that call's id. It returns
// the groups in input order of first appearance and the number of folded
// duplicate records.
func groupRecords(recs []Record) ([]*pending, int) {
	type bucket struct {
		dec, comp []Record
	}
	order := []string{}
	byKey := map[string]*bucket{}
	for i, r := range recs {
		key := r.CallID
		if key == "" || !r.Trusted {
			key = "#" + strconv.Itoa(i)
		}
		b := byKey[key]
		if b == nil {
			b = &bucket{}
			byKey[key] = b
			order = append(order, key)
		}
		if r.Kind == KindCompletion {
			b.comp = append(b.comp, r)
		} else {
			b.dec = append(b.dec, r)
		}
	}
	folded := 0
	out := make([]*pending, 0, len(order))
	for _, key := range order {
		b := byKey[key]
		sortByPrecedence(b.dec)
		sortByPrecedence(b.comp)
		p := &pending{}
		if len(b.dec) > 0 {
			p.call, p.trusted = mergeDecisions(b.dec)
			if len(b.comp) > 0 {
				mergeCompletion(p.call, b.comp)
			}
		}
		if n := len(b.dec) + len(b.comp); n > 0 {
			extra := 0
			if len(b.dec) > 1 {
				extra += len(b.dec) - 1
			}
			if len(b.comp) > 1 {
				extra += len(b.comp) - 1
			}
			folded += extra
			if p.call != nil {
				p.call.FoldedDuplicateRecords = extra
			}
		}
		out = append(out, p)
	}
	return out, folded
}

func sortByPrecedence(rs []Record) {
	sort.SliceStable(rs, func(i, j int) bool {
		ri, rj := rankOf(rs[i].Source), rankOf(rs[j].Source)
		if ri != rj {
			return ri < rj
		}
		if rs[i].Trusted != rs[j].Trusted {
			return rs[i].Trusted
		}
		return rs[i].TS < rs[j].TS
	})
}

func rankOf(s Source) int {
	if r, ok := SourceRank[s]; ok {
		return r
	}
	return len(SourceRank)
}

// mergeDecisions builds the call from its decision copies (already in
// precedence order): descriptive fields from the first copy that carries
// them, anchors from TRUSTED copies only.
func mergeDecisions(dec []Record) (*Call, bool) {
	c := &Call{CallID: dec[0].CallID, TS: dec[0].TS}
	trusted := false
	seen := map[Source]bool{}
	for _, r := range dec {
		if !seen[r.Source] {
			seen[r.Source] = true
			c.Sources = append(c.Sources, r.Source)
		}
		if r.TS != 0 && (c.TS == 0 || r.TS < c.TS) {
			c.TS = r.TS
		}
		first(&c.VirtualServer, r.VirtualServer)
		first(&c.Server, r.Server)
		c.serverNames = appendName(c.serverNames, r.VirtualServer)
		c.serverNames = appendName(c.serverNames, r.Server)
		first(&c.Tool, r.Tool)
		first(&c.Method, r.Method)
		first(&c.Decision, r.Decision)
		first(&c.Reason, r.Reason)
		first(&c.CaptureLevel, r.CaptureLevel)
		if c.ArgsFull == "" && c.ArgsExcerpt == "" && (r.ArgsFull != "" || r.ArgsExcerpt != "") {
			c.ArgsExcerpt, c.ArgsFull, c.ArgsScrubStatus = r.ArgsExcerpt, r.ArgsFull, r.ArgsScrubStatus
		}
		if !r.Trusted {
			continue
		}
		trusted = true
		first(&c.CodingSessionID, r.CodingSessionID)
		first(&c.TurnRef, r.TurnRef)
		first(&c.ActionRef, r.ActionRef)
		first(&c.StoredConfidence, r.StoredConfidence)
	}
	return c, trusted
}

// mergeCompletion joins the completion copies (precedence order) onto c.
func mergeCompletion(c *Call, comp []Record) {
	c.Completed = true
	for _, r := range comp {
		if !containsSource(c.Sources, r.Source) {
			c.Sources = append(c.Sources, r.Source)
		}
		first(&c.ResultStatus, r.ResultStatus)
		if c.LatencyMS == nil {
			c.LatencyMS = r.LatencyMS
		}
		if c.ResultSizeBytes == nil {
			c.ResultSizeBytes = r.ResultSizeBytes
		}
		if c.ResultFull == "" && r.ResultFull != "" {
			c.ResultFull, c.ResultScrubStatus = r.ResultFull, r.ResultScrubStatus
		}
		if c.ErrorFull == "" && r.ErrorFull != "" {
			c.ErrorFull, c.ErrorScrubStatus = r.ErrorFull, r.ErrorScrubStatus
		}
		if c.SchemaTokensEst == nil {
			c.SchemaTokensEst = r.SchemaTokensEst
		}
		if c.ResultTokensEst == nil {
			c.ResultTokensEst = r.ResultTokensEst
		}
		first(&c.TokenizerVersion, r.TokenizerVersion)
		first(&c.AttributionMethod, r.AttributionMethod)
		first(&c.AttributionConfidence, r.AttributionConfidence)
	}
	c.TokensEstimated = c.SchemaTokensEst != nil || c.ResultTokensEst != nil
}

func first(dst *string, v string) {
	if *dst == "" {
		*dst = v
	}
}

func containsSource(ss []Source, s Source) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// --- session index -------------------------------------------------------

type indexedAction struct {
	Action
	mcp          bool
	server, tool string // normalized MCP identity ("" unknown)
	claimed      bool
}

type sessionIndex struct {
	sessionID string
	byKey     map[string]*indexedAction
	byMessage map[string][]*indexedAction
	mcp       []*indexedAction // MCP actions, TS ascending
	all       []*indexedAction // TS ascending
	prompts   []*indexedAction // user prompts, TS ascending
	pool      []*poolEntry     // unanchored candidates, every session, TS ascending
}

func newSessionIndex(sessionID string, acts []Action) *sessionIndex {
	idx := &sessionIndex{sessionID: sessionID, byKey: map[string]*indexedAction{}, byMessage: map[string][]*indexedAction{}}
	for i := range acts {
		a := &indexedAction{Action: acts[i]}
		a.server, a.tool, a.mcp = mcpIdentity(acts[i])
		idx.all = append(idx.all, a)
	}
	sort.SliceStable(idx.all, func(i, j int) bool { return idx.all[i].TS.Before(idx.all[j].TS) })
	for _, a := range idx.all {
		if a.Key != "" {
			if _, dup := idx.byKey[a.Key]; !dup {
				idx.byKey[a.Key] = a
			}
		}
		if a.mcp {
			idx.mcp = append(idx.mcp, a)
			if a.MessageID != "" {
				idx.byMessage[a.MessageID] = append(idx.byMessage[a.MessageID], a)
			}
		}
		if a.ActionType == actionTypeUserPrompt {
			idx.prompts = append(idx.prompts, a)
		}
	}
	return idx
}

// mcpIdentity reports whether the action is an MCP call and its normalized
// (server, tool) identity when the raw name / target carries one.
func mcpIdentity(a Action) (server, tool string, mcp bool) {
	if s, t, ok := tooltax.MCPIdentity(a.RawToolName); ok {
		return normName(s), normName(t), true
	}
	if a.ActionType != actionTypeMCPCall {
		return "", "", false
	}
	if s, t, ok := tooltax.MCPIdentityFromTarget(a.Target); ok {
		return normName(s), normName(t), true
	}
	return "", "", true
}

// normName folds a server / tool name onto the character class AI clients
// use in their namespaced tool names (Claude Code maps every character
// outside [A-Za-z0-9_-] to '_').
func normName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func (idx *sessionIndex) claim(a *indexedAction) { a.claimed = true }

// invocationMethods are the JSON-RPC methods whose record can be the
// invocation behind ONE captured tool-call action. Every other method -
// initialize, notifications/*, tools/list and the other catalogue methods,
// ping, prompts/get, resources/read, tasks/* - is protocol traffic the AI
// client sends on its own: it is never a tool call the model made, so it
// must never claim (and so steal) the action a tools/call belongs to.
var invocationMethods = map[string]bool{"tools/call": true}

// captureL2 is the full capture level (the plain tool name rides only there
// on the node relay, R10.6).
const captureL2 = "L2"

// invokesTool reports whether the call may CLAIM an action (be linked at
// action level). The method decides when a carrier captured it. A record
// with no method (an org copy of a node relay event pushed before the method
// shipped on the wire) is judged from what it does carry: at L2 a tool call
// always names its tool, so a nameless L2 record is protocol traffic; below
// L2 every record's name is withheld, so the call keeps the benefit of the
// doubt. Both surfaces see the same fields, so they reach the same verdict.
func (c *Call) invokesTool() bool {
	if c.Method != "" {
		return invocationMethods[c.Method]
	}
	return c.Tool != "" || c.CaptureLevel != captureL2
}

// toolMatches reports whether action a is the call's tool (a call that
// names no tool matches every MCP action; an action whose identity is
// unknown never matches a named call). serverAgrees reports whether the
// action's server additionally equals the call's server or virtual server:
// a client's config entry key need not equal the registry name, so a server
// disagreement never excludes a tool match - it only breaks ties.
func toolMatches(a *indexedAction, c *Call) (match, serverAgrees bool) {
	if c.Tool == "" {
		return true, false
	}
	if a.tool == "" || a.tool != normName(c.Tool) {
		return false, false
	}
	return true, a.server != "" && (a.server == normName(c.Server) || a.server == normName(c.VirtualServer))
}

// unique returns the single unclaimed MCP action of acts matching the
// call's tool (several tool matches are narrowed to the server-agreeing
// ones); a call that names no tool is determinate only when acts hold
// exactly ONE unclaimed MCP action. nil when zero or several remain.
func (idx *sessionIndex) unique(acts []*indexedAction, c *Call) *indexedAction {
	var hits, agree []*indexedAction
	for _, a := range acts {
		if a.claimed || !a.mcp {
			continue
		}
		m, sa := toolMatches(a, c)
		if !m {
			continue
		}
		hits = append(hits, a)
		if sa {
			agree = append(agree, a)
		}
	}
	switch {
	case len(hits) == 1:
		return hits[0]
	case len(agree) == 1 && c.Tool != "":
		return agree[0]
	}
	return nil
}

// turn returns the MCP actions (TS ascending) of the turn ref names: a
// token_usage.turn_id, a decimal actions.turn_index, or a message id. When
// the turn holds no MCP action it returns one representative action so the
// caller can still report the turn.
func (idx *sessionIndex) turn(ref string) []*indexedAction {
	if ref == "" {
		return nil
	}
	var mcp, any []*indexedAction
	for _, a := range idx.all {
		hit := a.TurnID == ref || a.MessageID == ref ||
			(a.TurnIndex != nil && strconv.FormatInt(*a.TurnIndex, 10) == ref)
		if !hit {
			continue
		}
		if a.mcp {
			mcp = append(mcp, a)
		} else {
			any = append(any, a)
		}
	}
	if len(mcp) > 0 {
		return mcp
	}
	if len(any) > 0 {
		return any[:1]
	}
	return nil
}

// nearest picks the unclaimed MCP action inside the window closest to the
// call (a preceding action wins a tie against a trailing one; a
// server-agreeing action wins an equal-distance tie). named=true requires a
// tool-name match; named=false requires the window to hold exactly ONE
// unclaimed MCP action. A remaining exact tie is ambiguous and yields nil.
func (idx *sessionIndex) nearest(c *Call, named bool) *indexedAction {
	at := time.Unix(c.TS, 0)
	lo, hi := at.Add(-InferWindowBefore), at.Add(InferWindowAfter)
	var best *indexedAction
	var bestD time.Duration
	bestAgree, tie, n := false, false, 0
	for _, a := range idx.mcp {
		if a.claimed || a.TS.IsZero() || a.TS.Before(lo) || a.TS.After(hi) {
			continue
		}
		m, agree := toolMatches(a, c)
		if named && !m {
			continue
		}
		n++
		d := at.Sub(a.TS)
		if d < 0 {
			d = -d + time.Nanosecond // a trailing action loses an equal-distance tie
		}
		switch {
		case best == nil || d < bestD || (d == bestD && agree && !bestAgree):
			best, bestD, bestAgree, tie = a, d, agree, false
		case d == bestD && agree == bestAgree:
			tie = true
		}
	}
	if best == nil || tie || (!named && n != 1) {
		return nil
	}
	return best
}

// promptFor returns the key of the user prompt that opened the linked turn:
// the latest prompt at or before the matched action (same turn index when
// both carry one). Session-level links have none.
func (idx *sessionIndex) promptFor(l Link) string {
	if l.Level != LevelAction && l.Level != LevelTurn {
		return ""
	}
	var anchor *indexedAction
	if l.ActionKey != "" {
		anchor = idx.byKey[l.ActionKey]
	}
	if anchor == nil && l.MessageID != "" {
		if acts := idx.byMessage[l.MessageID]; len(acts) > 0 {
			anchor = acts[0]
		}
	}
	if anchor == nil {
		for _, a := range idx.all {
			if (l.TurnID != "" && a.TurnID == l.TurnID) || (l.TurnIndex != nil && a.TurnIndex != nil && *a.TurnIndex == *l.TurnIndex) || (l.MessageID != "" && a.MessageID == l.MessageID) {
				anchor = a
				break
			}
		}
	}
	if anchor == nil {
		return ""
	}
	var pick *indexedAction
	for _, pr := range idx.prompts {
		if !anchor.TS.IsZero() && pr.TS.After(anchor.TS) {
			break
		}
		if anchor.TurnIndex != nil && pr.TurnIndex != nil && *pr.TurnIndex != *anchor.TurnIndex {
			continue
		}
		pick = pr
	}
	if pick == nil {
		return ""
	}
	return pick.Key
}

// ParseTimestamp reads the TEXT timestamps the node and org action tables
// carry (RFC 3339 with or without fractional seconds, the SQLite
// "YYYY-MM-DD HH:MM:SS" form, or unix seconds / milliseconds). ok=false for
// an empty or unrecognised value.
func ParseTimestamp(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999", "2006-01-02 15:04:05.999999999Z07:00", "2006-01-02 15:04:05.999999999"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		if n > 1e12 {
			return time.UnixMilli(n).UTC(), true
		}
		return time.Unix(n, 0).UTC(), true
	}
	return time.Time{}, false
}
