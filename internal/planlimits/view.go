package planlimits

import (
	"sort"
	"strings"
	"time"
)

// view.go builds the Plans & limits page model: one card per account, plus
// one card per passive account scope, with the attach rules below deciding
// when a passive scope or a manual entry joins an account's card instead of
// showing on its own.

// AccountInfo is the plain projection of one configured account.
type AccountInfo struct {
	ID        string            `json:"id"`
	Provider  string            `json:"provider"`
	Source    string            `json:"source"`
	Label     string            `json:"label"`
	Params    map[string]string `json:"params,omitempty"`  // non-secret only
	Secrets   []string          `json:"secrets,omitempty"` // which secret keys are stored, never values
	Enabled   bool              `json:"enabled"`
	State     RunState          `json:"state"`
	CreatedAt time.Time         `json:"created_at"`
	// DailyUsage is the source's capability (SourceDef.DailyUsage): the
	// account may have a daily usage reconciliation to show.
	DailyUsage bool `json:"daily_usage,omitempty"`
}

// ScopedSnapshot is a passive reading bound to an account scope.
type ScopedSnapshot struct {
	Snapshot
	Scope      string
	ScopeLabel string // the observed login, shown only on this machine
	Reason     string
}

// ViewInput is everything the page model is built from.
type ViewInput struct {
	Now      time.Time
	Accounts []AccountInfo
	Latest   map[string]Snapshot // account id -> last good polled snapshot
	Passive  []ScopedSnapshot
	OptIns   map[string]bool // provider -> experimental opt-in
}

// CardWindow is one window on a card, with its provenance and pace.
type CardWindow struct {
	Window
	Provenance
	Expired bool  `json:"expired,omitempty"`
	Pace    *Pace `json:"pace,omitempty"`
}

// CardBalance is one balance on a card, with its provenance.
type CardBalance struct {
	Balance
	Provenance
}

// Card is one plan or balance on the page.
type Card struct {
	ID           string   `json:"id"`
	Provider     string   `json:"provider"`
	AccountID    string   `json:"account_id,omitempty"`
	Label        string   `json:"label,omitempty"`
	ScopeReason  string   `json:"scope_reason,omitempty"`
	Sources      []string `json:"sources"`
	Experimental bool     `json:"experimental,omitempty"`
	Status       string   `json:"status"`
	Health       string   `json:"health"`
	PlanCode     string   `json:"plan_code,omitempty"`
	PlanLabel    string   `json:"plan_label,omitempty"`
	// Identity is the observed login a passive scope is bound to (an email
	// or user name). It is kept apart from Label, the name the user typed,
	// so the page shows it as a quiet, masked secondary line and never in
	// the card title.
	Identity   string        `json:"identity,omitempty"`
	ObservedAt *time.Time    `json:"observed_at,omitempty"`
	Windows    []CardWindow  `json:"windows"`
	Balances   []CardBalance `json:"balances"`
	Spend      []Spend       `json:"spend"`
	State      *RunState     `json:"state,omitempty"`
	// Group is the provider's catalogue group (plans | balance | usage).
	Group string `json:"group"`
	// Headline is the number the card leads with: what is left (D-681).
	Headline Headline `json:"headline"`
}

// Health codes of a card.
const (
	HealthFresh   = "fresh"
	HealthStale   = "stale"
	HealthWaiting = "waiting" // configured, no reading yet
)

// passiveStaleAfter is how old a passive reading may be before the card says
// so. Polled cards use twice their cadence.
const passiveStaleAfter = 6 * time.Hour

// unit is one card in the making.
type unit struct {
	provider string
	account  *AccountInfo
	scope    string
	label    string
	identity string
	reason   string
	snaps    []Snapshot
}

func (u *unit) manual() bool { return u.account != nil && u.account.Source == SourceManual }

// attachRule decides whether unit u joins target units of the same provider.
// Rows are walked top-down; the first that matches decides.
type attachRule struct {
	name  string
	match func(u *unit, peers []*unit) (*unit, bool)
}

// nonManualAccounts returns the provider's configured, non-manual units.
func nonManualAccounts(peers []*unit) []*unit {
	var out []*unit
	for _, p := range peers {
		if p.account != nil && !p.manual() {
			out = append(out, p)
		}
	}
	return out
}

func passiveScopes(peers []*unit) int {
	n := 0
	for _, p := range peers {
		if p.account == nil {
			n++
		}
	}
	return n
}

// attachRules: a manual entry fills the gaps of the provider's one other
// card; a passive scope joins the provider's one configured account when it
// is the provider's only scope. Anything ambiguous stands alone: two
// accounts are never merged by guess.
var attachRules = []attachRule{
	{"manual_into_single_card", func(u *unit, peers []*unit) (*unit, bool) {
		if !u.manual() {
			return nil, false
		}
		var others []*unit
		for _, p := range peers {
			if p != u && !p.manual() {
				others = append(others, p)
			}
		}
		if len(others) == 1 {
			return others[0], true
		}
		return nil, false
	}},
	{"passive_into_single_account", func(u *unit, peers []*unit) (*unit, bool) {
		if u.account != nil {
			return nil, false
		}
		accts := nonManualAccounts(peers)
		if len(accts) == 1 && passiveScopes(peers) == 1 {
			return accts[0], true
		}
		return nil, false
	}},
}

// BuildView builds the page model. Cards are ordered by provider table
// order, then label.
func BuildView(in ViewInput) []Card {
	byProv := map[string][]*unit{}
	for i := range in.Accounts {
		a := &in.Accounts[i]
		if !a.Enabled {
			continue
		}
		u := &unit{provider: a.Provider, account: a, label: a.Label}
		if s, ok := in.Latest[a.ID]; ok && a.State.Status != StatusAuthNeeded {
			u.snaps = append(u.snaps, s) // an auth failure clears the numbers
		}
		byProv[a.Provider] = append(byProv[a.Provider], u)
	}
	// Passive: newest reading per (provider, scope, source).
	type pk struct{ prov, scope, src string }
	newest := map[pk]ScopedSnapshot{}
	for _, p := range in.Passive {
		k := pk{p.Provider, p.Scope, p.Source}
		if cur, ok := newest[k]; !ok || p.ObservedAt.After(cur.ObservedAt) {
			newest[k] = p
		}
	}
	scopeUnits := map[string]*unit{}
	keys := make([]pk, 0, len(newest))
	for k := range newest {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].prov != keys[j].prov {
			return keys[i].prov < keys[j].prov
		}
		if keys[i].scope != keys[j].scope {
			return keys[i].scope < keys[j].scope
		}
		return keys[i].src < keys[j].src
	})
	for _, k := range keys {
		p := newest[k]
		id := k.prov + "|" + k.scope
		u, ok := scopeUnits[id]
		if !ok {
			u = &unit{provider: k.prov, scope: k.scope, identity: p.ScopeLabel, reason: p.Reason}
			scopeUnits[id] = u
			byProv[k.prov] = append(byProv[k.prov], u)
		}
		u.snaps = append(u.snaps, p.Snapshot)
	}
	var cards []Card
	for _, prov := range providerOrder(byProv) {
		peers := byProv[prov]
		attached := map[*unit]bool{}
		for _, u := range peers {
			for _, r := range attachRules {
				if t, ok := r.match(u, peers); ok {
					t.snaps = append(t.snaps, u.snaps...)
					if t.label == "" {
						t.label = u.label
					}
					if t.identity == "" {
						t.identity = u.identity
					}
					attached[u] = true
					break
				}
			}
		}
		for _, u := range peers {
			if !attached[u] {
				cards = append(cards, buildCard(u, in))
			}
		}
	}
	return cards
}

// providerOrder returns the providers present, in Providers table order, then
// any unknown id alphabetically.
func providerOrder(m map[string][]*unit) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range Providers {
		if _, ok := m[p.ID]; ok {
			out = append(out, p.ID)
			seen[p.ID] = true
		}
	}
	var rest []string
	for k := range m {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	return append(out, rest...)
}

func buildCard(u *unit, in ViewInput) Card {
	c := Card{Provider: u.provider, Label: u.label, Identity: u.identity, ScopeReason: u.reason, Windows: []CardWindow{}, Balances: []CardBalance{}, Spend: []Spend{}}
	if u.account != nil {
		c.ID = u.account.ID
		c.AccountID = u.account.ID
		st := u.account.State
		c.State = &st
		if d, ok := SourceByID(u.account.Source); ok && d.Experimental() {
			c.Experimental = true
		}
	} else {
		c.ID = "passive:" + u.provider + ":" + strings.TrimPrefix(u.scope, "acct:")
	}
	m := Merge(u.snaps)
	srcs := map[string]bool{}
	for _, s := range u.snaps {
		srcs[s.Source] = true
		if s.Rung != RungOfficial {
			c.Experimental = true
		}
	}
	if u.account != nil {
		srcs[u.account.Source] = true
	}
	c.Sources = sortedKeys(srcs)
	c.PlanCode, c.PlanLabel = m.PlanCode, m.PlanLabel
	c.Status = m.Status
	if len(u.snaps) > 0 {
		t := m.ObservedAt
		c.ObservedAt = &t
	}
	for _, w := range m.Windows {
		cw := CardWindow{Window: w, Provenance: m.WindowProv[w.Key], Expired: Expired(w, in.Now)}
		if !cw.Expired {
			cw.Pace = PaceOf(w, in.Now)
		}
		c.Windows = append(c.Windows, cw)
	}
	for _, b := range m.Balances {
		c.Balances = append(c.Balances, CardBalance{Balance: b, Provenance: m.BalanceProv[b.Kind+"|"+string(b.Unit)]})
	}
	c.Spend = append(c.Spend, m.Spend...)
	c.Group = GroupPlans
	if p, ok := ProviderByID(u.provider); ok {
		c.Group = p.Group
	}
	c.Headline = HeadlineOf(c.Group, m, in.Now)
	c.Health = cardHealth(u, m, in.Now)
	if c.Status == "" {
		c.Status = StatusOK
	}
	return c
}

// cardHealth: an account in a stopped or failing state says so; otherwise a
// reading older than its freshness bound is stale.
func cardHealth(u *unit, m Merged, now time.Time) string {
	if u.account != nil {
		st := u.account.State
		switch {
		case st.Status == StatusAuthNeeded || st.Status == StatusEndpointGone ||
			st.Status == "not_applicable" || st.Status == "unavailable":
			return st.Status
		case len(u.snaps) == 0:
			if st.Status != "" && st.Status != StatusOK {
				return st.Status
			}
			return HealthWaiting
		}
		limit := 2 * Cadence(CadenceInput{MinInterval: MinIntervalOf(u.account.Source)})
		if u.account.Source == SourceManual {
			return HealthFresh
		}
		if now.Sub(m.ObservedAt) > limit {
			return HealthStale
		}
		if st.Status == StatusError || st.Status == StatusThrottled {
			return st.Status
		}
		return HealthFresh
	}
	if now.Sub(m.ObservedAt) > passiveStaleAfter {
		return HealthStale
	}
	return HealthFresh
}
