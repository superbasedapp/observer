package models

import "time"

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
type MessageAccount struct {
	Status   string                `json:"status"` // observed, unknown, conflict
	Label    string                `json:"label"`
	Evidence []ToolAccountEvidence `json:"evidence"`
}
