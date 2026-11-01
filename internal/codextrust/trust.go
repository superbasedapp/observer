package codextrust

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/BurntSushi/toml"
)

// # Recording trust (live check 2026-10-20, supersedes D-148's "never")
//
// Codex 0.144.4 on Windows ran NO hook from ~/.codex/hooks.json in
// `codex exec` because none was trusted, so Observer's Codex tool gate did
// not exist there. The operator ruled (2026-10-20) that when Observer writes
// its own Codex hooks it also records Codex's trust for exactly those
// entries, under the same consent that authorizes the hook write.
//
// What Codex checks, grounded in the codex-rs source at rust-v0.144.4
// (hooks/src/engine/discovery.rs append_matcher_groups + command_hook_hash,
// hooks/src/lib.rs hook_key, hooks/src/events/common.rs
// matcher_pattern_for_event, config/src/fingerprint.rs version_for_toml):
// a hooks.json command handler runs only when
// config.toml [hooks.state."<key>"].trusted_hash equals the handler's
// current hash, where
//
//	key  = "<hooks.json path as Codex displays it>:<snake event>:<group index>:<handler index>"
//	hash = "sha256:" + hex(sha256(compact key-sorted JSON of
//	       {"event_name", "matcher" (dropped for UserPromptSubmit and Stop),
//	        "hooks": [{"type": "command", "command", "timeout" (600 when unset;
//	                   1, at most 3, for SessionEnd and Interrupt),
//	                   "async", "statusMessage" (when set)}]}))
//
// The hash is the same Hash this package already reproduces against six
// live trusted entries (Codex 0.160.0). Because the hash covers the
// handler's whole normalized body, a recorded trust can only ever match the
// exact Observer command it was computed for: it cannot trust a user's hook
// or a changed Observer entry. PlanTrust therefore plans records only for
// handlers Owned reports as Observer's, only in the shape this package can
// hash exactly, and never for an entry the user turned off in /hooks.

// TrustRecord is one Observer handler's trust identity: the [hooks.state]
// key Codex looks it up under and the trusted_hash that makes it run.
type TrustRecord struct {
	Event string
	Key   string
	Hash  string
}

// TrustInput is everything PlanTrust and OwnedTrustRecords need. File
// contents are nil when the file does not exist.
type TrustInput struct {
	// KeyPath is the hooks.json path spelled exactly as the Codex that loads
	// it builds trust keys: the absolute path it displays (on Windows
	// C:\Users\<u>\.codex\hooks.json, even when Observer reaches the file
	// through /mnt/c).
	KeyPath string
	// HooksJSON is the hooks.json body.
	HooksJSON []byte
	// ConfigTOML is the config.toml body (PlanTrust only).
	ConfigTOML []byte
	// Owned reports whether a hook command is Observer's.
	Owned func(command string) bool
}

// TrustSkip is an Observer handler PlanTrust deliberately left alone.
type TrustSkip struct {
	Event  string
	Reason string
}

// trustRule is how Codex normalizes one event's handler before hashing.
type trustRule struct {
	// keepMatcher: the group matcher is part of the hash
	// (matcher_pattern_for_event); false for the matcherless events.
	keepMatcher bool
	// short: the timeout defaults to 1 s and is clamped to 3 s
	// (normalize_command_hook) instead of defaulting to 600 s.
	short bool
}

// trustableEvents is the Codex hooks.json event vocabulary Observer is
// grounded on: the ten events of 0.144.4 (codex-rs config/src/hook_config.rs
// HookEventsToml) plus SessionEnd and Interrupt from the 0.157.1 source
// (absent from 0.144.4, which ignores those entries, so a record for them is
// inert there). An event outside this table is never trusted: Observer
// cannot know how a Codex it was not grounded against would hash it.
var trustableEvents = map[string]trustRule{
	"PreToolUse":        {keepMatcher: true},
	"PermissionRequest": {keepMatcher: true},
	"PostToolUse":       {keepMatcher: true},
	"PreCompact":        {keepMatcher: true},
	"PostCompact":       {keepMatcher: true},
	"SessionStart":      {keepMatcher: true},
	"SubagentStart":     {keepMatcher: true},
	"SubagentStop":      {keepMatcher: true},
	"SessionEnd":        {keepMatcher: true, short: true},
	"UserPromptSubmit":  {},
	"Stop":              {},
	"Interrupt":         {short: true},
}

// rawHandler is one hooks.json handler with every field kept, so a field
// PlanTrust does not hash exactly can be detected instead of ignored.
type rawHandler map[string]json.RawMessage

// rawHooksFile mirrors hooks.json with raw handlers.
type rawHooksFile struct {
	Hooks map[string][]struct {
		Matcher *string      `json:"matcher"`
		Hooks   []rawHandler `json:"hooks"`
	} `json:"hooks"`
}

// hashedFields are the handler fields Hash covers exactly. A handler with
// any other field (commandWindows, timeoutSec, a field a newer Codex added)
// is not trusted: its hash would be a guess.
var hashedFields = map[string]bool{
	"type": true, "command": true, "timeout": true, "async": true, "statusMessage": true,
}

// handlerTrust is one owned handler's record, or why it has none.
type handlerTrust struct {
	rec  TrustRecord
	skip string
}

// ownedHandlers walks hooks.json and returns every Observer command handler
// with its trust record, or the reason it cannot carry one, in a stable
// (event, key) order.
func ownedHandlers(in TrustInput) ([]handlerTrust, error) {
	var hf rawHooksFile
	if len(in.HooksJSON) > 0 {
		if err := json.Unmarshal(in.HooksJSON, &hf); err != nil {
			return nil, fmt.Errorf("codextrust: parse hooks.json: %w", err)
		}
	}
	var out []handlerTrust
	for event, groups := range hf.Hooks {
		rule, known := trustableEvents[event]
		snake := CamelToSnake(event)
		for gi, g := range groups {
			for hi, h := range g.Hooks {
				var typ, command string
				_ = json.Unmarshal(h["type"], &typ)
				_ = json.Unmarshal(h["command"], &command)
				if typ != "command" || in.Owned == nil || !in.Owned(command) {
					continue
				}
				ht := handlerTrust{rec: TrustRecord{
					Event: event,
					Key:   fmt.Sprintf("%s:%s:%d:%d", in.KeyPath, snake, gi, hi),
				}}
				ht.rec.Hash, ht.skip = exactHash(snake, rule, known, g.Matcher, command, h)
				out = append(out, ht)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].rec.Event != out[j].rec.Event {
			return out[i].rec.Event < out[j].rec.Event
		}
		return out[i].rec.Key < out[j].rec.Key
	})
	return out, nil
}

// exactHash returns the one hash Codex 0.144.4 computes for a handler, or
// the reason it cannot be computed exactly. The rules run in order; the
// first refusal wins.
func exactHash(snake string, rule trustRule, known bool, matcher *string, command string, h rawHandler) (string, string) {
	var timeout int64 = defaultTimeoutSec
	if rule.short {
		timeout = 1
	}
	var async bool
	var status *string
	refusals := []struct {
		refuse func() bool
		reason string
	}{
		{func() bool { return !known }, "event not in the Codex hook vocabulary Observer is grounded on"},
		{func() bool { return command == "" }, "empty command"},
		{func() bool {
			for k := range h {
				if !hashedFields[k] {
					return true
				}
			}
			return false
		}, "handler carries a field Observer does not hash exactly"},
		{func() bool {
			return h["timeout"] != nil && (json.Unmarshal(h["timeout"], &timeout) != nil || timeout < 1)
		}, "timeout is not a positive integer"},
		{func() bool { return h["async"] != nil && json.Unmarshal(h["async"], &async) != nil }, "async is not a boolean"},
		{func() bool { return async }, "async handlers are skipped by Codex"},
		{func() bool { return h["statusMessage"] != nil && json.Unmarshal(h["statusMessage"], &status) != nil }, "statusMessage is not a string"},
	}
	for _, r := range refusals {
		if r.refuse() {
			return "", r.reason
		}
	}
	if rule.short && timeout > 3 {
		timeout = 3
	}
	if !rule.keepMatcher {
		matcher = nil
	}
	return Hash(snake, matcher, command, timeout, async, status), ""
}

// OwnedTrustRecords returns the trust record of every Observer command
// handler in hooks.json that PlanTrust could record, whatever config.toml
// says. The unregister path uses it to remove exactly the records Observer
// wrote (a recorded hash equal to one of these).
func OwnedTrustRecords(in TrustInput) ([]TrustRecord, error) {
	hs, err := ownedHandlers(in)
	if err != nil {
		return nil, err
	}
	var out []TrustRecord
	for _, h := range hs {
		if h.skip == "" {
			out = append(out, h.rec)
		}
	}
	return out, nil
}

// PlanTrust returns the trust records to write so Codex runs every Observer
// handler in hooks.json, and the handlers it deliberately leaves alone. As
// an ordered rule table per handler: a shape it cannot hash exactly is
// skipped; an entry the user turned off in /hooks (enabled = false) is
// skipped and never re-enabled; an entry already trusted with the current
// hash needs nothing; anything else gets a record. Nothing is planned for a
// handler Owned does not claim.
func PlanTrust(in TrustInput) (plan []TrustRecord, skipped []TrustSkip, err error) {
	hs, err := ownedHandlers(in)
	if err != nil {
		return nil, nil, err
	}
	state, err := hookStates(in.ConfigTOML)
	if err != nil {
		return nil, nil, err
	}
	for _, h := range hs {
		entry := state[h.rec.Key]
		switch {
		case h.skip != "":
			skipped = append(skipped, TrustSkip{Event: h.rec.Event, Reason: h.skip})
		case isDisabled(entry):
			skipped = append(skipped, TrustSkip{Event: h.rec.Event, Reason: "turned off in codex /hooks"})
		case normHash(stringField(entry, "trusted_hash")) == normHash(h.rec.Hash):
		default:
			plan = append(plan, h.rec)
		}
	}
	return plan, skipped, nil
}

// isDisabled reports a [hooks.state] entry the user switched off.
func isDisabled(entry map[string]any) bool {
	v, ok := entry["enabled"].(bool)
	return ok && !v
}

// hookStates parses config.toml's [hooks.state] tables, keyed verbatim.
func hookStates(cfg []byte) (map[string]map[string]any, error) {
	out := map[string]map[string]any{}
	if len(cfg) == 0 {
		return out, nil
	}
	root := map[string]any{}
	if err := toml.Unmarshal(cfg, &root); err != nil {
		// The parser's message can quote the file, which may hold a
		// credential: report the failure without it.
		return nil, errors.New("codextrust: config.toml is not valid TOML")
	}
	hooksTbl, _ := root["hooks"].(map[string]any)
	st, _ := hooksTbl["state"].(map[string]any)
	for k, v := range st {
		if m, ok := v.(map[string]any); ok {
			out[k] = m
		}
	}
	return out, nil
}
