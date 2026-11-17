package orgclient

import (
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// RequestableBudget is one org budget this node is governed by, as a
// developer picks it on a budget-increase request (orchestrator ruling on the
// request/grant lane's Q4, D-334). It comes from the verified budget rail the
// node already holds, so it names only budgets that apply to this caller; the
// org server re-checks that on receipt (T-523). The approver can still change
// the budget on the grant.
type RequestableBudget struct {
	BudgetID string                     `json:"budget_id"`
	Scope    string                     `json:"scope"`
	Period   string                     `json:"period"`
	Subject  *orgcontract.BudgetSubject `json:"subject,omitempty"`
	// CapTokens / CapUSD are the caps of the row BudgetID names, in the
	// units that row authored (a unit another row supplied is left out: it
	// is not this budget's number).
	CapTokens int64   `json:"cap_tokens,omitempty"`
	CapUSD    float64 `json:"cap_usd,omitempty"`
	// Timezone anchors the period (IANA; "" = UTC); Enforcement is the org
	// mode (report | soft | hard).
	Timezone    string `json:"timezone,omitempty"`
	Enforcement string `json:"enforcement,omitempty"`
	// Grantable is false for a pool shared with others (org, team, an
	// org-wide tool or model): a grant for one member never raises it
	// (C156-07), so the request reaches the approver as an ask to raise the
	// pool for everyone. It is listed because it may be the budget that ran
	// out (D-334).
	Grantable bool `json:"grantable"`
	// GrantID names the org budget-increase grant that raised this budget,
	// 0 when none does. While it is set, CapTokens / CapUSD are the RAISED
	// numbers and BaseCapTokens / BaseCapUSD the budget's own (the same unit
	// rule as the caps), so a surface can say what the grant raises
	// ("2000.00 USD (+500.00 USD)") and list it among the exceptions in
	// force. GrantExpiresAtNs is when the increase ends, 0 for a perpetual
	// one. A grant already past its end on this machine's clock is dropped
	// here, exactly as the enforcer drops it (RevertExpiredGrant).
	GrantID          int64   `json:"grant_id,omitempty"`
	BaseCapTokens    int64   `json:"base_cap_tokens,omitempty"`
	BaseCapUSD       float64 `json:"base_cap_usd,omitempty"`
	GrantExpiresAtNs int64   `json:"grant_expires_at_ns,omitempty"`
}

// RequestableBudgets lists the budgets named on the cached budget rail body,
// one per budget id, the ones a grant can raise for this member first.
// Empty when nothing is cached or the org server predates budget ids on the
// rail; the request then goes without one and the org fills it in or the
// approver picks it.
func (c *Client) RequestableBudgets() []RequestableBudget {
	if c == nil {
		return nil
	}
	_, body, have, _, _, _ := c.budget.snapshot()
	if !have {
		return nil
	}
	return requestableBudgets(body, time.Now())
}

// requestableBudgets is RequestableBudgets over a body at now (pure, for
// tests).
func requestableBudgets(body orgcontract.BudgetPolicyBody, now time.Time) []RequestableBudget {
	seen := map[string]bool{}
	var out []RequestableBudget
	for _, cp := range body.Caps {
		if cp.BudgetID == "" || seen[cp.BudgetID] {
			continue
		}
		seen[cp.BudgetID] = true
		cp = cp.RevertExpiredGrant(now)
		b := RequestableBudget{
			BudgetID: cp.BudgetID, Scope: cp.ResolvedScope, Period: cp.Period, Subject: cp.Subject,
			Timezone: cp.Timezone, Enforcement: cp.Enforcement,
			Grantable: strings.HasPrefix(cp.ResolvedScope, orgcontract.BudgetGrantableScopePrefix),
		}
		if cp.GrantID != 0 {
			b.GrantID, b.GrantExpiresAtNs = cp.GrantID, cp.GrantExpiresAtNs
		}
		// BudgetID names the row behind ResolvedScope; a unit whose number a
		// different row supplied (ScopeTokens / ScopeUSD) is not its cap,
		// nor is that row's base.
		if cp.ScopeTokens == "" || cp.ScopeTokens == cp.ResolvedScope {
			b.CapTokens = cp.CapTokens
			if b.GrantID != 0 {
				b.BaseCapTokens = cp.BaseCapTokens
			}
		}
		if cp.ScopeUSD == "" || cp.ScopeUSD == cp.ResolvedScope {
			b.CapUSD = cp.CapUSD
			if b.GrantID != 0 {
				b.BaseCapUSD = cp.BaseCapUSD
			}
		}
		out = append(out, b)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Grantable != out[j].Grantable {
			return out[i].Grantable
		}
		if out[i].Scope != out[j].Scope {
			return out[i].Scope < out[j].Scope
		}
		return out[i].Period < out[j].Period
	})
	return out
}
