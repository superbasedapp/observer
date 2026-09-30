package correlate

import (
	"sort"
	"strings"
	"time"
)

// unanchored.go is the UNANCHORED tier of the correlation (backlog item 10,
// 2026-09-27): a TRUSTED relay call that carried no anchor at all - no
// session id, no tool-use id, no turn ref. That is every client that neither
// puts a tool-use id in the MCP request's `_meta` nor runs the relay's stdio
// wrapper with a session env: OpenCode on the loopback relay is the grounded
// case (its relay tool is named "<entry key>_<tool>", e.g.
// "superbased-deepwiki_read_wiki_structure", and it sends no anchor).
//
// The tier works from data both surfaces already hold, never from a client
// name (CLAUDE.md #3): the relay's decision record (its time, upstream tool
// name and server / virtual-server names) and the captured tool-call
// actions of every session of the same node and owner (the Pool). It is
// deliberately independent of which session's panel is asking: a call's
// OWNER is a pure function of the call and the pool actions inside the
// call's own window, so one call can never be shown on two sessions, and
// the node panel and the org drawer (same rows) pick the same owner.

// unanchored reports whether the call carries no anchor at all (and came
// over a trusted carrier - an untrusted one is rule 1's none).
func (p *pending) unanchored() bool {
	return p.trusted && p.call != nil && p.call.CodingSessionID == "" && p.call.ActionRef == "" && p.call.TurnRef == ""
}

// IsUnanchored reports whether a decision record carries no correlation
// anchor. The seams select such records by time window (RecordWindows),
// since nothing else ties them to a session.
func IsUnanchored(r Record) bool {
	return r.CodingSessionID == "" && r.ActionRef == "" && r.TurnRef == ""
}

// Window is one closed [From, To] time range (unix seconds for records;
// the seams format it for text timestamp columns).
type Window struct {
	From, To time.Time
}

// maxWindows bounds the windows one panel queries (the latest are kept).
const maxWindows = 200

// RecordWindows returns the merged time windows in which an unanchored
// relay decision could match one of the session's candidate actions
// (CandidateActionTypes with a name): a call at T matches an action at A
// when A is in [T-InferWindowBefore, T+InferWindowAfter], i.e. T is in
// [A-InferWindowAfter, A+InferWindowBefore]. Actions of other types or
// without a timestamp / name are ignored. Oldest first, at most maxWindows
// (the latest).
func RecordWindows(acts []Action) []Window {
	var ts []time.Time
	for _, a := range acts {
		if !isCandidateType(a.ActionType) || a.TS.IsZero() || projName(a.Target) == "" {
			continue
		}
		ts = append(ts, a.TS)
	}
	return mergeWindows(ts, InferWindowAfter+time.Second, InferWindowBefore+time.Second)
}

// PoolWindows returns the merged windows of candidate action time for the
// unanchored decision records (a record at T admits actions in
// [T-InferWindowBefore, T+InferWindowAfter]; one extra second each side
// absorbs the records' whole-second truncation). Oldest first.
func PoolWindows(recs []Record) []Window {
	var ts []time.Time
	for _, r := range recs {
		if r.Kind != KindDecision || !IsUnanchored(r) || r.TS == 0 {
			continue
		}
		ts = append(ts, time.Unix(r.TS, 0).UTC())
	}
	return mergeWindows(ts, InferWindowBefore+time.Second, InferWindowAfter+time.Second)
}

func mergeWindows(ts []time.Time, before, after time.Duration) []Window {
	if len(ts) == 0 {
		return nil
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
	var out []Window
	for _, t := range ts {
		w := Window{From: t.Add(-before), To: t.Add(after)}
		if n := len(out); n > 0 && !w.From.After(out[n-1].To) {
			if w.To.After(out[n-1].To) {
				out[n-1].To = w.To
			}
			continue
		}
		out = append(out, w)
	}
	if len(out) > maxWindows {
		out = out[len(out)-maxWindows:]
	}
	return out
}

func isCandidateType(t string) bool {
	for _, c := range CandidateActionTypes {
		if t == c {
			return true
		}
	}
	return false
}

// projName is the matchable form of a captured action's display name: the
// normName fold with the separators at both ends trimmed ("" when empty).
func projName(s string) string { return strings.Trim(normName(s), "_") }

func appendName(dst []string, v string) []string {
	n := projName(v)
	if len(n) < 2 {
		return dst
	}
	for _, x := range dst {
		if x == n {
			return dst
		}
	}
	return append(dst, n)
}

// poolEntry is one candidate action of the unanchored pool.
type poolEntry struct {
	sessionID string
	act       *indexedAction
	name      string // projName(target)
}

// addPool indexes the unanchored candidate pool. An action of THIS session
// already indexed from Actions is shared (so a claim by an anchored rule and
// the unanchored tier is one claim); a new one is registered by key so the
// prompt lookup finds it. Actions another trusted record names exactly
// (anchoredKeys) are left out: their call is not unanchored.
func (idx *sessionIndex) addPool(pool []PoolAction, anchoredKeys []string) {
	if len(pool) == 0 {
		return
	}
	anchored := make(map[string]bool, len(anchoredKeys))
	for _, k := range anchoredKeys {
		if k != "" {
			anchored[k] = true
		}
	}
	seen := map[string]bool{}
	for i := range pool {
		pa := pool[i]
		if !isCandidateType(pa.ActionType) || pa.TS.IsZero() || (pa.Key != "" && anchored[pa.Key]) {
			continue
		}
		name := projName(pa.Target)
		if name == "" {
			continue
		}
		if pa.Key != "" {
			k := pa.SessionID + "\x00" + pa.Key
			if seen[k] {
				continue
			}
			seen[k] = true
		}
		e := &poolEntry{sessionID: pa.SessionID, name: name}
		if pa.SessionID == idx.sessionID && pa.Key != "" && idx.byKey[pa.Key] != nil {
			e.act = idx.byKey[pa.Key]
		} else {
			e.act = &indexedAction{Action: pa.Action}
			if pa.SessionID == idx.sessionID && pa.Key != "" {
				idx.byKey[pa.Key] = e.act
			}
		}
		idx.pool = append(idx.pool, e)
	}
	sort.SliceStable(idx.pool, func(i, j int) bool {
		a, b := idx.pool[i], idx.pool[j]
		if !a.act.TS.Equal(b.act.TS) {
			return a.act.TS.Before(b.act.TS)
		}
		if a.sessionID != b.sessionID {
			return a.sessionID < b.sessionID
		}
		return a.act.Key < b.act.Key
	})
}

// poolMatch reports whether a pool action's name names the call. With an
// upstream tool name (L2 capture) the name must END in that tool and the
// part before it must carry one of the call's server names as a whole
// segment run ("superbased-deepwiki_read_wiki_structure" for server
// "deepwiki" + tool "read_wiki_structure"; "mcp__github__get_issue";
// "github:get_issue"); a bare tool name matches only on an action the
// adapter itself classified as an MCP call. Without a tool name (capture
// below L2) a server-name segment is enough - the owner rule then demands a
// single candidate. A protocol record (!invokesTool: initialize,
// notifications/*, tools/list, ...) names no tool call, so a server-name
// segment is all it can match on too; it only ever decides the OWNER
// session and never claims the action.
func poolMatch(e *poolEntry, c *Call) bool {
	if c.Tool == "" || !c.invokesTool() {
		wrapped := "_" + e.name + "_"
		for _, s := range c.serverNames {
			if strings.Contains(wrapped, "_"+s+"_") {
				return true
			}
		}
		return false
	}
	t := projName(c.Tool)
	if t == "" {
		return false
	}
	if e.name == t {
		return e.act.ActionType == actionTypeMCPCall
	}
	if !strings.HasSuffix(e.name, "_"+t) {
		return false
	}
	prefix := "_" + e.name[:len(e.name)-len(t)]
	for _, s := range c.serverNames {
		if strings.Contains(prefix, "_"+s+"_") {
			return true
		}
	}
	return false
}

// distance is the time distance of an action from the call; a trailing
// action loses an equal-distance tie against a preceding one.
func distance(at, ts time.Time) time.Duration {
	d := at.Sub(ts)
	if d < 0 {
		d = -d + time.Nanosecond
	}
	return d
}

func inWindow(at, ts time.Time) bool {
	return !ts.IsZero() && !ts.Before(at.Add(-InferWindowBefore)) && !ts.After(at.Add(InferWindowAfter))
}

// ownerVerdict is the unanchored tier's per-call decision.
type ownerVerdict struct {
	owner     string // "" when no session owns the call
	ambiguous bool   // several sessions, too close to call
	candidate bool   // THIS session holds a matching action in the window
}

// unanchoredOwner decides which session owns an unanchored call. It reads
// only the call and the pool actions in the call's window - never a claim -
// so every panel reaches the same verdict. Rules, in order:
//   - no matching action anywhere: no owner;
//   - a tool invocation with no tool name (below L2): exactly one matching
//     action, else ambiguous (it would claim that action); a protocol record
//     claims none, so only the session rule below applies to it;
//   - the session holding the nearest matching action owns the call when
//     every other session's nearest one is at least InferSessionSeparation
//     farther; otherwise ambiguous (attached to no session).
func (idx *sessionIndex) unanchoredOwner(c *Call) ownerVerdict {
	at := time.Unix(c.TS, 0)
	best := map[string]time.Duration{}
	n := 0
	for _, e := range idx.pool {
		if !inWindow(at, e.act.TS) || !poolMatch(e, c) {
			continue
		}
		n++
		d := distance(at, e.act.TS)
		if cur, ok := best[e.sessionID]; !ok || d < cur {
			best[e.sessionID] = d
		}
	}
	v := ownerVerdict{}
	_, v.candidate = best[idx.sessionID]
	if n == 0 {
		return v
	}
	if c.Tool == "" && c.invokesTool() && n != 1 {
		v.ambiguous = true
		return v
	}
	type sd struct {
		s string
		d time.Duration
	}
	ranked := make([]sd, 0, len(best))
	for s, d := range best {
		ranked = append(ranked, sd{s, d})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].d != ranked[j].d {
			return ranked[i].d < ranked[j].d
		}
		return ranked[i].s < ranked[j].s
	})
	if len(ranked) > 1 && ranked[1].d-ranked[0].d < InferSessionSeparation {
		v.ambiguous = true
		return v
	}
	v.owner = ranked[0].s
	return v
}

// nearestPool is the nearest unclaimed matching action of THIS session in
// the call's window; an exact tie is ambiguous (nil).
func (idx *sessionIndex) nearestPool(c *Call) *indexedAction {
	at := time.Unix(c.TS, 0)
	var best *indexedAction
	var bestD time.Duration
	tie := false
	for _, e := range idx.pool {
		if e.sessionID != idx.sessionID || e.act.claimed || !inWindow(at, e.act.TS) || !poolMatch(e, c) {
			continue
		}
		d := distance(at, e.act.TS)
		switch {
		case best == nil || d < bestD:
			best, bestD, tie = e.act, d, false
		case d == bestD && e.act != best:
			tie = true
		}
	}
	if tie {
		return nil
	}
	return best
}

// resolveUnanchored is rule 5: the unanchored tier's link for this session.
func (idx *sessionIndex) resolveUnanchored(p *pending) Link {
	v := idx.unanchoredOwner(p.call)
	switch {
	case v.owner != "" && v.owner == idx.sessionID:
		if !p.call.invokesTool() {
			// Protocol traffic: attributed to its session, never to an
			// action - so it can never consume the candidate a tools/call of
			// the same session is matched against.
			return Link{Confidence: Inferred, Level: LevelSession, Method: MethodUnanchoredProtocol}
		}
		if a := idx.nearestPool(p.call); a != nil {
			idx.claim(a)
			l := actionLink(Inferred, a)
			l.Method = MethodUnanchoredToolTime
			if p.call.Tool == "" {
				l.Method = MethodUnanchoredServerTime
			}
			return l
		}
		return Link{Confidence: Inferred, Level: LevelSession, Method: MethodUnanchoredSession}
	case v.ambiguous && v.candidate:
		return Link{Confidence: None, Level: LevelNone, Method: MethodUnanchoredAmbiguous}
	case v.owner != "":
		p.drop = true
		return Link{Confidence: None, Level: LevelNone, Method: MethodUnanchoredOther}
	default:
		p.drop = true
		return Link{Confidence: None, Level: LevelNone, Method: MethodUnanchoredNoMatch}
	}
}

// textTSLayout is the second-precision prefix of the RFC 3339 text
// timestamps the node and org action tables carry.
const textTSLayout = "2006-01-02T15:04:05"

// TextRange renders a window as a half-open [from, to) pair of RFC 3339
// prefixes for a TEXT timestamp column: a stored "2026-09-27T09:56:01.123Z"
// sorts at or after its own second's prefix and before the next second's.
// The seam filters with it; the derivation re-checks the parsed time.
func TextRange(w Window) (from, to string) {
	return w.From.UTC().Truncate(time.Second).Format(textTSLayout), w.To.UTC().Truncate(time.Second).Add(time.Second).Format(textTSLayout)
}
