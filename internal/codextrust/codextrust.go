package codextrust

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// State is one Observer Codex hook event's trust state.
type State string

// The closed State vocabulary.
const (
	// StateTrusted: a trusted_hash is recorded and (when the hash is
	// verifiable) matches the entry's current body.
	StateTrusted State = "trusted"
	// StateUntrusted: no trusted_hash is recorded; Codex will not run it.
	StateUntrusted State = "untrusted"
	// StateModified: a trusted_hash is recorded for a different body (the
	// command changed after the user trusted it); Codex will not run it.
	StateModified State = "modified"
	// StateDisabled: the user turned the entry off in Codex `/hooks`.
	StateDisabled State = "disabled"
	// StateMissing: Observer registers this event but hooks.json has no
	// Observer entry for it (registered by an older Observer, or removed).
	StateMissing State = "missing"
)

// Runs reports whether Codex dispatches an entry in this state.
func (s State) Runs() bool { return s == StateTrusted }

// Input is everything Classify needs. File contents are nil when the file
// does not exist.
type Input struct {
	// HooksPath is the hooks.json path exactly as Codex keys
	// [hooks.state] with it (the absolute path Codex loaded).
	HooksPath string
	// HooksJSON is the hooks.json body.
	HooksJSON []byte
	// ConfigTOML is the config.toml body.
	ConfigTOML []byte
	// Expected lists the CamelCase events Observer registers for Codex
	// (integration registry, Registered bindings).
	Expected []string
	// Owned reports whether a hook command is Observer's.
	Owned func(command string) bool
	// NormalizePath, when non-nil, maps a hooks.json path to the form trust
	// keys are compared in. It is applied to HooksPath and to the path part
	// of every [hooks.state] key. Codex keys trust with the absolute path IT
	// loaded, so a Windows Codex records C:\Users\<u>\.codex\hooks.json
	// (possibly with the \\?\ prefix) while a WSL daemon reads the same file
	// as /mnt/c/Users/<u>/.codex/hooks.json; without a normalizer such an
	// entry could never read as trusted. nil compares keys byte for byte.
	NormalizePath func(path string) string
}

// Entry is one Observer event's classification.
type Entry struct {
	Event string `json:"event"`
	// Key is the [hooks.state] key Codex uses for the entry ("" when
	// missing).
	Key   string `json:"key,omitempty"`
	State State  `json:"state"`
	// Expected is false for an Observer entry in hooks.json for an event
	// the current Observer no longer registers.
	Expected bool `json:"expected"`
}

// Report is the classification of every Observer Codex event.
type Report struct {
	// Entries is sorted by event name.
	Entries []Entry
	// HashVerified is true when at least one recorded trusted_hash in
	// this hooks.json reproduces exactly, so a mismatch means the entry
	// changed. When false (a Codex release that hashes differently), a
	// recorded trusted_hash is taken at its word and nothing is reported
	// as modified.
	HashVerified bool
	// FeatureHooks is config.toml [features].hooks = true.
	FeatureHooks bool
	// ConfigPresent is false when config.toml does not exist.
	ConfigPresent bool
}

// Counts returns the number of entries in each state.
func (r Report) Counts() map[State]int {
	out := map[State]int{}
	for _, e := range r.Entries {
		out[e.State]++
	}
	return out
}

// Events returns the event names in the given states, in Entries order.
func (r Report) Events(states ...State) []string {
	want := map[State]bool{}
	for _, s := range states {
		want[s] = true
	}
	var out []string
	for _, e := range r.Entries {
		if want[e.State] {
			out = append(out, e.Event)
		}
	}
	return out
}

// hooksFile mirrors hooks.json: {"hooks": {Event: [{matcher, hooks: [...]}]}}.
type hooksFile struct {
	Hooks map[string][]struct {
		Matcher *string `json:"matcher"`
		Hooks   []struct {
			Type          string  `json:"type"`
			Command       string  `json:"command"`
			Timeout       *int64  `json:"timeout"`
			TimeoutSec    *int64  `json:"timeoutSec"`
			Async         *bool   `json:"async"`
			StatusMessage *string `json:"statusMessage"`
		} `json:"hooks"`
	} `json:"hooks"`
}

// handlerRef is one Observer handler found in hooks.json.
type handlerRef struct {
	event string
	key   string
	// lookup is key with its path normalized (Input.NormalizePath): the
	// form the parsed [hooks.state] map is keyed by.
	lookup string
	hashes []string
}

// splitStateKey splits a [hooks.state] key "<path>:<event>:<group>:<handler>"
// into the path and the ":<event>:<group>:<handler>" tail, from the right
// (a Windows path carries its own drive colon). ok is false for a key with
// fewer than three colons.
func splitStateKey(k string) (path, tail string, ok bool) {
	i := len(k)
	for n := 0; n < 3; n++ {
		j := strings.LastIndex(k[:i], ":")
		if j < 0 {
			return "", "", false
		}
		i = j
	}
	return k[:i], k[i:], true
}

// normalizeStateKey rewrites the path part of a [hooks.state] key with norm.
func normalizeStateKey(k string, norm func(string) string) string {
	path, tail, ok := splitStateKey(k)
	if !ok {
		return k
	}
	return norm(path) + tail
}

// Classify returns the trust state of every Observer Codex event.
func Classify(in Input) (Report, error) {
	rep := Report{ConfigPresent: in.ConfigTOML != nil}
	norm := in.NormalizePath
	if norm == nil {
		norm = func(s string) string { return s }
	}
	var hf hooksFile
	if len(in.HooksJSON) > 0 {
		if err := json.Unmarshal(in.HooksJSON, &hf); err != nil {
			return rep, fmt.Errorf("codextrust.Classify: parse hooks.json: %w", err)
		}
	}
	state := map[string]map[string]any{}
	if len(in.ConfigTOML) > 0 {
		root := map[string]any{}
		if err := toml.Unmarshal(in.ConfigTOML, &root); err != nil {
			return rep, fmt.Errorf("codextrust.Classify: parse config.toml: %w", err)
		}
		if features, _ := root["features"].(map[string]any); features != nil {
			rep.FeatureHooks, _ = features["hooks"].(bool)
		}
		hooksTbl, _ := root["hooks"].(map[string]any)
		st, _ := hooksTbl["state"].(map[string]any)
		for k, v := range st {
			if m, ok := v.(map[string]any); ok {
				state[normalizeStateKey(k, norm)] = m
			}
		}
	}

	// Every handler in hooks.json anchors hash verification (a user's own
	// trusted entry proves the algorithm as well as ours does); only
	// Observer's are classified.
	owned := map[string]*handlerRef{}
	for event, groups := range hf.Hooks {
		snake := CamelToSnake(event)
		for gi, g := range groups {
			for hi, h := range g.Hooks {
				if h.Type != "command" {
					continue
				}
				key := fmt.Sprintf("%s:%s:%d:%d", in.HooksPath, snake, gi, hi)
				lookup := fmt.Sprintf("%s:%s:%d:%d", norm(in.HooksPath), snake, gi, hi)
				timeout := h.Timeout
				if timeout == nil {
					timeout = h.TimeoutSec
				}
				hashes := candidateHashes(snake, g.Matcher, h.Command, timeout, h.Async, h.StatusMessage)
				recorded := normHash(stringField(state[lookup], "trusted_hash"))
				if recorded != "" && containsStr(hashes, recorded) {
					rep.HashVerified = true
				}
				if in.Owned == nil || !in.Owned(h.Command) {
					continue
				}
				if _, seen := owned[event]; !seen {
					owned[event] = &handlerRef{event: event, key: key, lookup: lookup, hashes: hashes}
				}
			}
		}
	}

	expected := map[string]bool{}
	for _, e := range in.Expected {
		expected[e] = true
		if _, ok := owned[e]; !ok {
			rep.Entries = append(rep.Entries, Entry{Event: e, State: StateMissing, Expected: true})
		}
	}
	for event, ref := range owned {
		rep.Entries = append(rep.Entries, Entry{
			Event:    event,
			Key:      ref.key,
			State:    classifyOne(state[ref.lookup], ref.hashes, rep.HashVerified),
			Expected: expected[event],
		})
	}
	sort.Slice(rep.Entries, func(i, j int) bool { return rep.Entries[i].Event < rep.Entries[j].Event })
	return rep, nil
}

// classifyOne maps one [hooks.state] entry to a State, as an ordered rule
// table: disabled beats everything, then no recorded hash, then a hash
// that does not match the body (only when the algorithm is verified).
func classifyOne(entry map[string]any, hashes []string, verified bool) State {
	if v, ok := entry["enabled"].(bool); ok && !v {
		return StateDisabled
	}
	recorded := normHash(stringField(entry, "trusted_hash"))
	switch {
	case recorded == "":
		return StateUntrusted
	case verified && !containsStr(hashes, recorded):
		return StateModified
	default:
		return StateTrusted
	}
}

// matcherlessEvents are the events whose matcher Codex drops before
// hashing (live-verified on Codex 0.160.0 for UserPromptSubmit and Stop:
// those events do not take a matcher). Events not listed here are hashed
// both with and without the matcher, so an event added later classifies
// correctly whichever way Codex treats it.
var matcherlessEvents = map[string]bool{
	"user_prompt_submit": true,
	"stop":               true,
}

// shortTimeoutEvents default to a 1 s timeout capped at 3 s instead of
// 600 s (codex-rs hooks/src/engine/discovery.rs normalize_command_hook).
var shortTimeoutEvents = map[string]bool{
	"session_end": true,
	"interrupt":   true,
}

// defaultTimeoutSec is Codex's command-hook timeout when none is set.
const defaultTimeoutSec = 600

// candidateHashes returns every hash Codex could have recorded for one
// handler under the rules above (one or two; never empty).
func candidateHashes(snake string, matcher *string, command string, timeout *int64, async *bool, status *string) []string {
	t := int64(defaultTimeoutSec)
	if shortTimeoutEvents[snake] {
		t = 1
	}
	if timeout != nil && *timeout > 0 {
		t = *timeout
		if shortTimeoutEvents[snake] && t > 3 {
			t = 3
		}
	}
	isAsync := async != nil && *async
	variants := []*string{matcher}
	switch {
	case matcherlessEvents[snake]:
		variants = []*string{nil}
	case matcher != nil:
		variants = append(variants, nil)
	}
	var out []string
	for _, m := range variants {
		out = append(out, Hash(snake, m, command, t, isAsync, status))
	}
	return out
}

// Hash returns the trusted_hash Codex records for a single-handler command
// hook entry: "sha256:" + hex(sha256(compact key-sorted JSON of
// {"event_name", "matcher" (when present), "hooks": [{"type": "command",
// "command", "timeout", "async", "statusMessage" (when present)}]})).
// Reproduced from codex-rs config/src/fingerprint.rs version_for_toml +
// hooks/src/engine/discovery.rs hook_hash and verified against six live
// trusted entries on Codex 0.160.0. Used for detection only.
func Hash(snakeEvent string, matcher *string, command string, timeoutSec int64, async bool, statusMessage *string) string {
	handler := map[string]any{
		"type":    "command",
		"command": command,
		"timeout": timeoutSec,
		"async":   async,
	}
	if statusMessage != nil {
		handler["statusMessage"] = *statusMessage
	}
	obj := map[string]any{
		"event_name": snakeEvent,
		"hooks":      []any{handler},
	}
	if matcher != nil {
		obj["matcher"] = *matcher
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(obj) // map keys encode sorted; values are plain scalars
	sum := sha256.Sum256(bytes.TrimRight(buf.Bytes(), "\n"))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// CamelToSnake converts a hooks.json event name ("PreToolUse") to the
// snake label Codex keys trust state with ("pre_tool_use").
func CamelToSnake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r + ('a' - 'A'))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func normHash(h string) string {
	return strings.TrimPrefix(strings.TrimSpace(h), "sha256:")
}

func stringField(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func containsStr(list []string, want string) bool {
	for _, s := range list {
		if normHash(s) == want {
			return true
		}
	}
	return false
}
