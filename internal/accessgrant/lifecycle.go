package accessgrant

import (
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// Grant statuses (§2.1), derived from time, uses and revocation.
const (
	StatusScheduled = "scheduled"
	StatusActive    = "active"
	StatusExhausted = "exhausted"
	StatusExpired   = "expired"
	StatusRevoked   = "revoked"
)

// Request statuses (§1.4). StatusResolved is the legacy W6 value.
const (
	RequestOpen      = "open"
	RequestGranted   = "granted"
	RequestDeclined  = "declined"
	RequestWithdrawn = "withdrawn"
	RequestLapsed    = "lapsed"
	RequestResolved  = "resolved"
)

// Window is the time-and-uses part of a grant, enough to derive its status.
type Window struct {
	StartsAtNs  int64
	ExpiresAtNs int64 // 0 = perpetual
	MaxUses     int64 // 0 = unlimited
	RevokedAtNs int64 // 0 = not revoked
}

// statusRule is one row of the ordered status table: the first row whose
// condition holds names the status.
type statusRule struct {
	status string
	holds  func(w Window, uses int64, nowNs int64) bool
}

var statusRules = []statusRule{
	{StatusRevoked, func(w Window, _ int64, _ int64) bool { return w.RevokedAtNs > 0 }},
	{StatusExhausted, func(w Window, uses int64, _ int64) bool { return w.MaxUses > 0 && uses >= w.MaxUses }},
	{StatusExpired, func(w Window, _ int64, now int64) bool { return w.ExpiresAtNs > 0 && now >= w.ExpiresAtNs }},
	{StatusScheduled, func(w Window, _ int64, now int64) bool { return now < w.StartsAtNs }},
	{StatusActive, func(Window, int64, int64) bool { return true }},
}

// Status is the server's view of a grant at now (uses = the reconciled count
// the org has seen).
func Status(w Window, uses int64, now time.Time) string {
	n := now.UnixNano()
	for _, r := range statusRules {
		if r.holds(w, uses, n) {
			return r.status
		}
	}
	return StatusActive
}

// Ended reports whether a status is terminal.
func Ended(status string) bool {
	return status == StatusExhausted || status == StatusExpired || status == StatusRevoked
}

// Receipt is the node's record of how it came to hold its grant cache, which
// is what bounds a grant the node can no longer re-verify.
type Receipt struct {
	// ServerNowNs is the body's server clock at build time.
	ServerNowNs int64
	// ReceivedAtNs is the node's wall clock when it accepted that body.
	ReceivedAtNs int64
	// LastVerifiedNs is the node's wall clock at the last VERIFIED 200.
	LastVerifiedNs int64
	// HighWaterNs is the highest node wall clock ever observed; a clock set
	// back below it is read as the high-water mark (GRANT-3).
	HighWaterNs int64
	// MaxOfflineS is the body's offline window (0 = online only).
	MaxOfflineS int64
}

// Node-side refusal reasons (Honoured's second result).
const (
	ReasonOK         = ""
	ReasonNotStarted = "not_started"
	ReasonExpired    = "expired"
	ReasonExhausted  = "exhausted"
	ReasonStale      = "stale"
	ReasonNoReceipt  = "no_receipt"
	// ReasonUnverified: the node's cached grant document no longer verifies
	// (signature, subject or key), so none of its grants is honoured.
	ReasonUnverified = "unverified"
)

// honourRule is one row of the node's honour table, walked top-down.
type honourRule struct {
	reason string
	refuse func(g orgcontract.AccessGrantWire, uses int64, rc Receipt, now int64) bool
}

var honourRules = []honourRule{
	{ReasonNoReceipt, func(_ orgcontract.AccessGrantWire, _ int64, rc Receipt, _ int64) bool {
		return rc.ReceivedAtNs <= 0 || rc.ServerNowNs <= 0
	}},
	{ReasonExhausted, func(g orgcontract.AccessGrantWire, uses int64, _ Receipt, _ int64) bool {
		return g.MaxUses > 0 && uses >= g.MaxUses
	}},
	// Expiry: BOTH the absolute instant and the remaining TTL measured at
	// receipt must still hold; whichever ends first wins (GRANT-3).
	{ReasonExpired, func(g orgcontract.AccessGrantWire, _ int64, rc Receipt, now int64) bool {
		if g.ExpiresAtNs <= 0 {
			return false
		}
		return now >= g.ExpiresAtNs || now-rc.ReceivedAtNs >= g.ExpiresAtNs-rc.ServerNowNs
	}},
	// Start: the LATER of the absolute start and the start measured from
	// receipt (the stricter reading, again).
	{ReasonNotStarted, func(g orgcontract.AccessGrantWire, _ int64, rc Receipt, now int64) bool {
		return now < g.StartsAtNs || now-rc.ReceivedAtNs < g.StartsAtNs-rc.ServerNowNs
	}},
	// Offline: a grant the node cannot re-verify is honoured for at most
	// MaxOffline after the last verified sync (D-087), OnlineOnlyWindow
	// when the org chose online only.
	{ReasonStale, func(_ orgcontract.AccessGrantWire, _ int64, rc Receipt, now int64) bool {
		window := time.Duration(rc.MaxOfflineS) * time.Second
		if window <= 0 {
			window = OnlineOnlyWindow
		}
		return rc.LastVerifiedNs <= 0 || now-rc.LastVerifiedNs >= int64(window)
	}},
}

// EffectiveNow is the instant the node evaluates at: its wall clock, never
// below the high-water mark it has already seen.
func EffectiveNow(rc Receipt, now time.Time) int64 {
	n := now.UnixNano()
	if rc.HighWaterNs > n {
		return rc.HighWaterNs
	}
	return n
}

// Honoured reports whether the node may act on g right now, and why not.
// Every failure is "no grant": enforcement stands.
func Honoured(g orgcontract.AccessGrantWire, usesUsed int64, rc Receipt, now time.Time) (bool, string) {
	n := EffectiveNow(rc, now)
	for _, r := range honourRules {
		if r.refuse(g, usesUsed, rc, n) {
			return false, r.reason
		}
	}
	return true, ReasonOK
}

// Verdict decisions a guard exemption can change (policy.Decision.String()
// spelling; pinned against the guard by its own test). An exempt grant lifts
// either to FLAG; a soften grant only turns a DENY into an ASK.
const (
	DecisionAsk  = "ask"
	DecisionDeny = "deny"
)

// Query is what the guard asks when an ASK/DENY verdict fires (§3.2's
// GrantQuery).
type Query struct {
	RuleID          string
	Lane            string
	CommandClass    string
	OperandHash     string
	ProjectRootHash string
	// Decision is the verdict the grant would change (DecisionAsk or
	// DecisionDeny). Anything else matches nothing.
	Decision string
	// RuleLocked is the node's org lock on the rule (guard override.go): a
	// locked rule is only reachable by a LockOverride grant.
	RuleLocked bool
}

// Cached is one node-cached grant plus its local use count.
type Cached struct {
	Grant    orgcontract.AccessGrantWire
	UsesUsed int64
}

// Hit is the grant that covers a query (§3.2's GrantHit).
type Hit struct {
	GrantID     int64
	Effect      string
	ExpiresAtNs int64
	// UsesLeft is -1 for unlimited.
	UsesLeft int64
	// Narrowness is how many optional match fields the grant pinned.
	Narrowness int
}

// matchField is one optional narrowing field: empty on the grant matches any
// query value; set, it must equal the query's.
type matchField struct {
	grant func(orgcontract.AccessGrantWire) string
	query func(Query) string
	any   func(string) bool
}

var matchFields = []matchField{
	{
		func(g orgcontract.AccessGrantWire) string { return g.Lane }, func(q Query) string { return q.Lane },
		func(v string) bool { return v == "" || v == LaneAll },
	},
	{
		func(g orgcontract.AccessGrantWire) string { return g.CommandClass }, func(q Query) string { return q.CommandClass },
		func(v string) bool { return v == "" },
	},
	{
		func(g orgcontract.AccessGrantWire) string { return g.OperandHash }, func(q Query) string { return q.OperandHash },
		func(v string) bool { return v == "" },
	},
	{
		func(g orgcontract.AccessGrantWire) string { return g.ProjectRootHash }, func(q Query) string { return q.ProjectRootHash },
		func(v string) bool { return v == "" },
	},
}

// effectActs is the effect x decision table: which verdicts an effect may
// change. An unknown effect or decision changes nothing.
var effectActs = map[string]map[string]bool{
	orgcontract.AccessGrantEffectExempt: {DecisionAsk: true, DecisionDeny: true},
	orgcontract.AccessGrantEffectSoften: {DecisionDeny: true},
}

// effectStrength orders the effects by how much they lift (MatchDetail's
// second sort key).
var effectStrength = map[string]int{
	orgcontract.AccessGrantEffectSoften: 1,
	orgcontract.AccessGrantEffectExempt: 2,
}

// MatchResult is MatchDetail's answer: the covering grant, and whether a
// grant that would otherwise have matched was refused because the node's org
// lock covers the rule and the grant lacks LockOverride (so the deny text can
// say why the developer's grant did not apply).
type MatchResult struct {
	Hit         Hit
	OK          bool
	LockRefused bool
	// ScopeMissID is set when nothing covered the call although the node
	// holds an honoured grant for this very rule whose effect would have
	// changed the verdict: that grant is pinned to another lane, command or
	// project. It names the grant (the lowest id), so the block text can say
	// why a rule the developer holds a grant for still stopped them, rather
	// than leaving them to ask for the same grant again.
	ScopeMissID int64
}

// Match returns the grant that covers q, if any (MatchDetail without the
// refusal detail).
func Match(q Query, grants []Cached, rc Receipt, now time.Time) (Hit, bool) {
	r := MatchDetail(q, grants, rc, now)
	return r.Hit, r.OK
}

// MatchDetail returns the grant that covers q. Only guard exemptions match,
// and only when their effect can change q.Decision (effectActs); on a rule the
// node's org bundle locks, only a LockOverride grant. Every present narrowing
// field must equal the query's (AND). Among several, the NARROWEST wins, then
// the stronger effect (exempt before soften: a developer who holds both for
// the same scope is not asked to confirm what the org exempted), then the
// earliest expiry (a perpetual grant last), then the lowest id - a total
// order, so the answer is deterministic.
func MatchDetail(q Query, grants []Cached, rc Receipt, now time.Time) MatchResult {
	if q.RuleID == "" {
		return MatchResult{}
	}
	var hits []Hit
	lockRefused := false
	scopeMiss := int64(0)
	for _, c := range grants {
		g := c.Grant
		if g.Type != TypeGuardExemption || g.RuleID != q.RuleID || !effectActs[g.Effect][q.Decision] {
			continue
		}
		narrow, ok := 0, true
		for _, f := range matchFields {
			gv := f.grant(g)
			if f.any(gv) {
				continue
			}
			if gv != f.query(q) {
				ok = false
				break
			}
			narrow++
		}
		honoured, _ := Honoured(g, c.UsesUsed, rc, now)
		if !ok {
			if honoured && (!q.RuleLocked || g.LockOverride) && (scopeMiss == 0 || g.ID < scopeMiss) {
				scopeMiss = g.ID
			}
			continue
		}
		if !honoured {
			continue
		}
		if q.RuleLocked && !g.LockOverride {
			lockRefused = true
			continue
		}
		left := int64(-1)
		if g.MaxUses > 0 {
			left = g.MaxUses - c.UsesUsed
		}
		hits = append(hits, Hit{GrantID: g.ID, Effect: g.Effect, ExpiresAtNs: g.ExpiresAtNs, UsesLeft: left, Narrowness: narrow})
	}
	if len(hits) == 0 {
		return MatchResult{LockRefused: lockRefused, ScopeMissID: scopeMiss}
	}
	sort.Slice(hits, func(i, j int) bool {
		a, b := hits[i], hits[j]
		if a.Narrowness != b.Narrowness {
			return a.Narrowness > b.Narrowness
		}
		if as, bs := effectStrength[a.Effect], effectStrength[b.Effect]; as != bs {
			return as > bs
		}
		ae, be := expirySortKey(a.ExpiresAtNs), expirySortKey(b.ExpiresAtNs)
		if ae != be {
			return ae < be
		}
		return a.GrantID < b.GrantID
	})
	return MatchResult{Hit: hits[0], OK: true}
}

// SoftenForRule reports an honoured SOFTEN grant naming ruleID that may reach
// it (locked: the node's org lock covers the rule, so only a LockOverride
// grant counts). It answers the local-confirmation gate: under a soften
// grant the developer's own approval is the per-call confirmation the grant
// asks for, even on a rule the org locks. The narrowing fields are not
// checked here; the claim re-checks every one per call.
func SoftenForRule(ruleID string, locked bool, grants []Cached, rc Receipt, now time.Time) (int64, bool) {
	if ruleID == "" {
		return 0, false
	}
	for _, c := range grants {
		g := c.Grant
		if g.Type != TypeGuardExemption || g.RuleID != ruleID || g.Effect != orgcontract.AccessGrantEffectSoften {
			continue
		}
		if locked && !g.LockOverride {
			continue
		}
		if ok, _ := Honoured(g, c.UsesUsed, rc, now); ok {
			return g.ID, true
		}
	}
	return 0, false
}

func expirySortKey(ns int64) int64 {
	if ns <= 0 {
		return 1<<63 - 1
	}
	return ns
}

// BudgetGrant is an active-or-not budget increase as the server holds it.
type BudgetGrant struct {
	GrantID     int64
	BudgetID    string
	CapTokens   int64
	CapUSD      float64
	StartsAtNs  int64
	ExpiresAtNs int64
}

// Overlay is a budget increase folded into one cap.
type Overlay struct {
	GrantID       int64
	CapTokens     int64
	CapUSD        float64
	BaseCapTokens int64
	BaseCapUSD    float64
	ExpiresAtNs   int64
}

// BudgetOverlay folds the active grants for ONE budget row into its base caps.
// A grant never LOWERS a cap (an admin who raised the base past a grant keeps
// their number); among several active grants the one producing the highest
// cap wins (tokens, then dollars, then the earliest expiry). ok is false when
// no active grant raises anything.
func BudgetOverlay(baseTokens int64, baseUSD float64, grants []BudgetGrant, now time.Time) (Overlay, bool) {
	n := now.UnixNano()
	best, found := Overlay{}, false
	for _, g := range grants {
		if n < g.StartsAtNs || (g.ExpiresAtNs > 0 && n >= g.ExpiresAtNs) {
			continue
		}
		tok, usd := baseTokens, baseUSD
		if g.CapTokens > tok && baseTokens > 0 {
			tok = g.CapTokens
		}
		if g.CapUSD > usd && baseUSD > 0 {
			usd = g.CapUSD
		}
		if tok == baseTokens && usd == baseUSD {
			continue
		}
		cand := Overlay{GrantID: g.GrantID, CapTokens: tok, CapUSD: usd, BaseCapTokens: baseTokens, BaseCapUSD: baseUSD, ExpiresAtNs: g.ExpiresAtNs}
		if !found || betterOverlay(cand, best) {
			best, found = cand, true
		}
	}
	return best, found
}

func betterOverlay(a, b Overlay) bool {
	if a.CapTokens != b.CapTokens {
		return a.CapTokens > b.CapTokens
	}
	if a.CapUSD != b.CapUSD {
		return a.CapUSD > b.CapUSD
	}
	if expirySortKey(a.ExpiresAtNs) != expirySortKey(b.ExpiresAtNs) {
		return expirySortKey(a.ExpiresAtNs) < expirySortKey(b.ExpiresAtNs)
	}
	return a.GrantID < b.GrantID
}

// RevertExpiredOverlay is the node's offline revert (§3.3): a cap raised by a
// grant drops back to its base once the grant's expiry passes, without a
// fetch. grantExpiresNs 0 (no overlay, or a perpetual one) never reverts.
func RevertExpiredOverlay(capTokens int64, capUSD float64, baseTokens int64, baseUSD float64, grantExpiresNs int64, now time.Time) (int64, float64, bool) {
	if grantExpiresNs <= 0 || now.UnixNano() < grantExpiresNs {
		return capTokens, capUSD, false
	}
	return baseTokens, baseUSD, true
}

// ShapeContext is the ONE place the request context block's content keys are
// kept or stripped (§1.2, §4.4; D-083). shipsRaw is the node's
// shipsRawContent() (a managed node, or full_content / admin_managed);
// optInExcerpt is the developer's per-request checkbox. The metadata half is
// always kept; the excerpt is bounded either way.
func ShapeContext(c orgcontract.AccessRequestContext, shipsRaw, optInExcerpt bool) orgcontract.AccessRequestContext {
	out := c
	if len(out.TargetExcerpt) > MaxExcerptBytes {
		out.TargetExcerpt = truncateUTF8(out.TargetExcerpt, MaxExcerptBytes)
	}
	if shipsRaw {
		return out
	}
	if !optInExcerpt {
		out.TargetExcerpt = ""
	}
	out.ProjectRoot = ""
	out.GitBranch = ""
	return out
}

// truncateUTF8 cuts s to at most n bytes without splitting a rune.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut]
}
