package store

import (
	"context"
	"fmt"
	"sort"
)

// toolaccountme.go is the node-local READ behind the dashboard's You page
// (GET /api/me/tool-accounts): which vendor accounts each AI tool has been
// seen signed in as on this machine. internal/store/toolaccount.go stays the
// table's one writer; this file only reads. Nothing here reaches the org
// wire (the privacy sentinel keeps tool_account_observations out of
// orgpush.go).

// MeToolAccount is one vendor account seen for one tool on this machine.
type MeToolAccount struct {
	// Email and Name are what the tool's own sign-in reported; either may be
	// empty and an empty value means "not captured", never "no account".
	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`
	// Key is the first 8 characters of the account key (already a one-way
	// hash), so two accounts with no email or name stay distinguishable.
	Key string `json:"key"`
	// FirstSeen and LastSeen are RFC3339 observation times.
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	// Sessions is the number of distinct sessions the account was seen in.
	Sessions int `json:"sessions"`
}

// MeToolAccounts is every account seen for one tool.
type MeToolAccounts struct {
	Tool     string          `json:"tool"`
	Accounts []MeToolAccount `json:"accounts"`
	// Multiple is true when more than one distinct account was seen.
	Multiple bool `json:"multiple_accounts"`
}

// LoadMeToolAccounts groups the node-local tool_account_observations by tool
// and account. Stop-stage rows are left out, as in LoadMessageAccounts: a
// session end is not evidence of who signed in. Tools sort by name and a
// tool's accounts by most recently seen.
func (s *Store) LoadMeToolAccounts(ctx context.Context) ([]MeToolAccounts, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT tool, account_key,
	  COALESCE(MAX(email),''), COALESCE(MAX(name),''),
	  MIN(observed_at), MAX(observed_at), COUNT(DISTINCT session_id)
	 FROM tool_account_observations
	 WHERE stage<>'stop'
	 GROUP BY tool, account_key
	 ORDER BY tool, MAX(observed_at) DESC, account_key`)
	if err != nil {
		return nil, fmt.Errorf("store.LoadMeToolAccounts: %w", err)
	}
	defer rows.Close()
	byTool := map[string]*MeToolAccounts{}
	for rows.Next() {
		var tool, key string
		var a MeToolAccount
		if err := rows.Scan(&tool, &key, &a.Email, &a.Name, &a.FirstSeen, &a.LastSeen, &a.Sessions); err != nil {
			return nil, fmt.Errorf("store.LoadMeToolAccounts: scan: %w", err)
		}
		t := byTool[tool]
		if t == nil {
			t = &MeToolAccounts{Tool: tool}
			byTool[tool] = t
		}
		a.Key = key
		if len(a.Key) > 8 {
			a.Key = a.Key[:8]
		}
		t.Accounts = append(t.Accounts, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadMeToolAccounts: %w", err)
	}
	out := make([]MeToolAccounts, 0, len(byTool))
	for _, t := range byTool {
		t.Multiple = len(t.Accounts) > 1
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tool < out[j].Tool })
	return out, nil
}
