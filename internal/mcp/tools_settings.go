package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// -----------------------------------------------------------------------------
// get_settings / set_setting (Plane A build-out W2-8, principle 10, ruling
// D19): an AI agent reads and changes superbased settings through the same
// checked write `observer config set` uses, never by editing ~/.observer files
// (guard R-160 keeps denying that).
//
//   - get_settings is always allowed. Credentials are never returned, and a
//     value that looks like one is hidden.
//   - set_setting applies an ordinary key directly. A security-sensitive key
//     (guard, capture and content, sharing, egress, admission mode, budgets,
//     or an SDK destination that sends data online) is NEVER applied: it files
//     a proposal the user approves on the dashboard (Settings, Changes waiting
//     for you) or with `observer config proposals approve <id>`. The rule is
//     internal/settingsgate's table; this tool only relays its verdict.
//
// The work is done by the injected SettingsBackend (cmd/observer wires it),
// so this package holds no config or store logic of its own.
// -----------------------------------------------------------------------------

// SettingsQuery narrows a get_settings read.
type SettingsQuery struct {
	// Key reads one dotted key; it wins over Prefix and Section.
	Key string
	// Prefix keeps keys equal to it or under it.
	Prefix string
	// Section keeps one Settings section.
	Section string
	// Primary keeps only the primary (non-advanced) keys.
	Primary bool
}

// SetSettingRequest is one set_setting call.
type SetSettingRequest struct {
	Key   string
	Value string
	// Note is the agent's own explanation, shown to the user with a proposal.
	Note string
	// Client names the MCP client that asked (from initialize), for the
	// proposal's "asked by".
	Client string
}

// SetSettingResult is what set_setting did.
type SetSettingResult struct {
	// Status is "applied", "proposed" or "refused".
	Status   string   `json:"status"`
	Key      string   `json:"key"`
	Value    string   `json:"value,omitempty"`
	Category string   `json:"category,omitempty"`
	Reason   string   `json:"reason"`
	Proposal int64    `json:"proposal_id,omitempty"`
	Next     string   `json:"next,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// SettingsBackend serves the two tools. Implementations must apply the D19
// gate (internal/settingsgate) to every write.
type SettingsBackend interface {
	GetSettings(ctx context.Context, q SettingsQuery) (any, error)
	SetSetting(ctx context.Context, req SetSettingRequest) (SetSettingResult, error)
}

// errSettingsUnwired is the honest answer when the host gave no backend.
var errSettingsUnwired = errors.New("settings are not available from this MCP server (no settings backend wired); use `observer config get|list|set` or the dashboard's Settings page")

type getSettingsTool struct{ b SettingsBackend }

func (*getSettingsTool) Name() string { return "get_settings" }

func (*getSettingsTool) Description() string {
	return "Read superbased settings (the config schema). Pass key for one dotted key " +
		"(e.g. observability.sdk.destination), or prefix / section to list a family. " +
		"Each entry carries its value, kind, tier, section, restart class and agent_write: " +
		"what set_setting would do (apply, propose for the user's approval, or refuse). " +
		"Credentials are never returned; a value that looks like one is hidden."
}

func (*getSettingsTool) InputSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"key":     map[string]any{"type": "string", "description": "One dotted config key."},
			"prefix":  map[string]any{"type": "string", "description": "List keys equal to or under this dotted prefix (e.g. observability)."},
			"section": map[string]any{"type": "string", "description": "List one Settings section (e.g. observability)."},
			"primary": map[string]any{"type": "boolean", "description": "Only the primary keys (hide advanced and expert ones)."},
		},
		"additionalProperties": false,
	}
}

func (t *getSettingsTool) Invoke(ctx context.Context, args json.RawMessage) (any, error) {
	if t.b == nil {
		return nil, errSettingsUnwired
	}
	var in struct {
		Key     string `json:"key"`
		Prefix  string `json:"prefix"`
		Section string `json:"section"`
		Primary bool   `json:"primary"`
	}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &in); err != nil {
			return nil, fmt.Errorf("get_settings: invalid arguments: %w", err)
		}
	}
	if strings.TrimSpace(in.Key) == "" && strings.TrimSpace(in.Prefix) == "" && strings.TrimSpace(in.Section) == "" {
		return nil, errors.New("get_settings: pass key, prefix or section (the whole schema is over 500 keys)")
	}
	return t.b.GetSettings(ctx, SettingsQuery{
		Key: strings.TrimSpace(in.Key), Prefix: strings.TrimSpace(in.Prefix),
		Section: strings.TrimSpace(in.Section), Primary: in.Primary,
	})
}

type setSettingTool struct {
	b      SettingsBackend
	client func() string
}

func (*setSettingTool) Name() string { return "set_setting" }

func (*setSettingTool) Description() string {
	return "Change one superbased setting (dotted key, value in the `observer config set` spelling: " +
		"true/false, numbers, comma-separated lists). An ordinary setting is applied at once. " +
		"A security-sensitive one (the guard, what is captured or shared, where data or requests go, " +
		"admission, budgets, or an SDK destination of online or both) is NOT applied: it becomes a " +
		"proposal the user approves on the dashboard or with `observer config proposals approve <id>`. " +
		"Tell the user when you file one. Credentials and keys another surface owns are refused."
}

func (*setSettingTool) InputSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"key":   map[string]any{"type": "string", "description": "The dotted config key."},
			"value": map[string]any{"type": "string", "description": "The new value as `observer config set` takes it."},
			"note":  map[string]any{"type": "string", "description": "Why you are asking (shown to the user with a proposal; at most 500 characters)."},
		},
		"required":             []string{"key", "value"},
		"additionalProperties": false,
	}
}

func (t *setSettingTool) Invoke(ctx context.Context, args json.RawMessage) (any, error) {
	if t.b == nil {
		return nil, errSettingsUnwired
	}
	var in struct {
		Key   string           `json:"key"`
		Value *json.RawMessage `json:"value"`
		Note  string           `json:"note"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return nil, fmt.Errorf("set_setting: invalid arguments: %w", err)
	}
	if strings.TrimSpace(in.Key) == "" || in.Value == nil {
		return nil, errors.New("set_setting: key and value are required")
	}
	value, err := settingValueString(*in.Value)
	if err != nil {
		return nil, fmt.Errorf("set_setting: %w", err)
	}
	client := ""
	if t.client != nil {
		client = t.client()
	}
	return t.b.SetSetting(ctx, SetSettingRequest{Key: strings.TrimSpace(in.Key), Value: value, Note: in.Note, Client: client})
}

// settingValueString accepts the value as a JSON string, or a bare JSON
// boolean or number (a model often sends those), in the `config set`
// spelling.
func settingValueString(raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", fmt.Errorf("value is not valid JSON: %w", err)
	}
	switch x := v.(type) {
	case bool, float64:
		return strings.TrimSpace(string(raw)), nil
	case []any:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			es, ok := e.(string)
			if !ok {
				return "", errors.New("a list value must hold strings")
			}
			parts = append(parts, es)
		}
		return strings.Join(parts, ","), nil
	}
	return "", errors.New("value must be a string, boolean, number or list of strings")
}
