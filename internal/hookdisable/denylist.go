package hookdisable

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// denyDimCode is DimCode's deny-list dialect.
const denyDimCode = "dimcode"

// denyListDialects maps a Switch.DenyList dialect to its membership test:
// whether deny (the deny-list file) holds the hash of one of Observer's own
// entries in hooks (the vendor's hooks file). Only the deny list's keys are
// decoded; its records are never parsed, kept or reported (surface-gap
// decision D5, the D-268 / D-270 surgical class).
var denyListDialects = map[string]func(deny, hooks []byte, own func(string) bool) bool{
	denyDimCode: dimCodeDenied,
}

// discard decodes any JSON value to nothing, so a deny-list record is
// skipped without being parsed into memory.
type discard struct{}

// UnmarshalJSON implements json.Unmarshaler.
func (*discard) UnmarshalJSON([]byte) error { return nil }

// dimCodeDenied is DimCode's rule, read from the dimcode 0.5.21 bundle
// (agent/src/hooks/command/disabled.ts and config.ts): the deny list is
// {"version": 1, "disabled": {"<hash>": record}} (another version or shape
// is ignored by DimCode, so it is no finding here), and an entry's hash is
// the lowercase hex SHA-256 of JSON.stringify of {event, matcher,
// command, commandWindows, timeout, statusMessage}, each absent value
// null and the matcher trimmed, with "" and "*" read as absent.
func dimCodeDenied(deny, hooks []byte, own func(string) bool) bool {
	var list struct {
		Version  int                 `json:"version"`
		Disabled map[string]*discard `json:"disabled"`
	}
	if json.Unmarshal(deny, &list) != nil || list.Version != 1 || len(list.Disabled) == 0 {
		return false
	}
	for _, e := range dimCodeEntries(hooks) {
		if !own(e.Command) && (e.CommandWindows == nil || !own(*e.CommandWindows)) {
			continue
		}
		if _, ok := list.Disabled[e.hash()]; ok {
			return true
		}
	}
	return false
}

// dimCodeEntry is one hook entry in the canonical field order DimCode
// hashes.
type dimCodeEntry struct {
	Event          string   `json:"event"`
	Matcher        *string  `json:"matcher"`
	Command        string   `json:"command"`
	CommandWindows *string  `json:"commandWindows"`
	Timeout        *float64 `json:"timeout"`
	StatusMessage  *string  `json:"statusMessage"`
}

// hash is DimCode's hashCommandHook. JSON.stringify escapes no HTML
// characters, so neither does the encoder (U+2028 and U+2029, which Go
// always escapes, do not occur in a hook command Observer writes).
func (e dimCodeEntry) hash() string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if enc.Encode(e) != nil {
		return ""
	}
	sum := sha256.Sum256(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
	return hex.EncodeToString(sum[:])
}

// dimCodeEntries reads the command hook entries of a DimCode hooks.json:
// {"hooks": {"<Event>": [{"matcher": ..., "hooks": [{"type": "command",
// "command": ..., ...}]}]}}. An entry it cannot read is skipped.
func dimCodeEntries(b []byte) []dimCodeEntry {
	var top struct {
		Hooks map[string][]struct {
			Matcher json.RawMessage `json:"matcher"`
			Hooks   []struct {
				Type           string   `json:"type"`
				Command        string   `json:"command"`
				CommandWindows *string  `json:"commandWindows"`
				Timeout        *float64 `json:"timeout"`
				StatusMessage  *string  `json:"statusMessage"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if json.Unmarshal(b, &top) != nil {
		return nil
	}
	var out []dimCodeEntry
	for event, groups := range top.Hooks {
		for _, g := range groups {
			var matcher *string
			if len(g.Matcher) > 0 && string(g.Matcher) != "null" {
				var m string
				if json.Unmarshal(g.Matcher, &m) != nil {
					continue
				}
				if m = strings.TrimSpace(m); m != "" && m != "*" {
					matcher = &m
				}
			}
			for _, h := range g.Hooks {
				if h.Type != "command" || strings.TrimSpace(h.Command) == "" {
					continue
				}
				out = append(out, dimCodeEntry{
					Event: event, Matcher: matcher, Command: h.Command,
					CommandWindows: h.CommandWindows, Timeout: h.Timeout, StatusMessage: h.StatusMessage,
				})
			}
		}
	}
	return out
}
