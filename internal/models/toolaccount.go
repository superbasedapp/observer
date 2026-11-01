package models

import (
	"strings"
	"time"
)

// ToolAccountScopeAccount is the Scope value (or "account:<detail>" prefix)
// that marks an ACCOUNT-LEVEL observation: the identity is a vendor account
// (a device/installation account id, a tenant, a Snowflake account host) that
// more than one person may share, never a person. Operator ruling 2026-10-21:
// autohand's device accountId and Cortex Code's Snowflake account host are
// captured this way. An account-level observation carries AccountID only;
// Email and Name stay empty (internal/toolaccount.Normalize rejects an
// account-level row that names a person). Surfaces read the marker through
// ToolAccountScopeIsAccountLevel and must not present the value as the person
// who typed the prompt.
const ToolAccountScopeAccount = "account"

// ToolAccountScopeIsAccountLevel reports whether scope carries the
// account-level marker ("account" or "account:<detail>").
func ToolAccountScopeIsAccountLevel(scope string) bool {
	return scope == ToolAccountScopeAccount || strings.HasPrefix(scope, ToolAccountScopeAccount+":")
}

// ToolAccountScopeNoun names an account-level scope in words a dashboard can
// show ("device account", "org account"), from the optional "account:<detail>"
// suffix. The detail vocabulary is closed on purpose: an adapter-supplied detail
// this table does not know falls back to plain "account" rather than being
// echoed into the UI. Returns "" for a scope that is not account-level. The web
// dashboards mirror this table (shared/lib/toolAccounts.ts).
func ToolAccountScopeNoun(scope string) string {
	if !ToolAccountScopeIsAccountLevel(scope) {
		return ""
	}
	switch strings.TrimPrefix(strings.TrimPrefix(scope, ToolAccountScopeAccount), ":") {
	case "device", "install", "installation":
		return "device account"
	case "org", "organization", "tenant", "workspace", "host":
		return "org account"
	}
	return "account"
}

// ToolAccountObservation is node-local login evidence, never enrollment identity
// or proof of the account billed by a provider. Bindings are exact native IDs.
// It deliberately contains no credentials or arbitrary vendor payload.
type ToolAccountObservation struct {
	SessionID   string
	Tool        string
	BindingKind string // message, turn, or tool_call
	BindingID   string
	Role        string
	Email       string
	Name        string
	AccountID   string
	Source      string
	Scope       string
	Stage       string // submission, activity, or stop (context only)
	ObservedAt  time.Time
}

// ToolAccountEvidence is a safe identity projection exposed by the local API.
type ToolAccountEvidence struct {
	Key        string `json:"key"`
	Email      string `json:"email,omitempty"`
	Name       string `json:"name,omitempty"`
	AccountID  string `json:"account_id,omitempty"`
	Source     string `json:"source"`
	Scope      string `json:"scope"`
	Stage      string `json:"stage"`
	ObservedAt string `json:"observed_at"`
}

// MessageAccount preserves disagreement instead of choosing the latest login.
//
// Person and account-level evidence are two separate dimensions
// (internal/toolaccount.Merge owns the rules): Label is the PERSON-level
// login, or the account-level label only when no person evidence exists;
// AccountLabel is the account-level (device / org / install) id when any such
// evidence exists, shown beside the person, never as the person.
type MessageAccount struct {
	Status       string                `json:"status"` // observed, unknown, conflict
	Label        string                `json:"label"`
	AccountLabel string                `json:"account_label,omitempty"`
	Evidence     []ToolAccountEvidence `json:"evidence"`
}
