package hookliveness

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/url"
	"path/filepath"
	"strings"
)

// Coarse env classes. These, and a "hash:" path hash, are the only strings
// EnvClasses ever returns; a variable's value never does.
const (
	ClassOn             = "on"
	ClassOff            = "off"
	ClassSet            = "set"
	ClassEmpty          = "empty"
	ClassLoopback       = "loopback"
	ClassProviderDirect = "provider_direct"
	ClassOtherHost      = "other_host"
	ClassInvalid        = "invalid"
)

// metadataClasses is the closed coarse vocabulary above: the classes that
// carry no content (lane w5-wire, DEC-5). Anything else EnvClasses returns
// (today only a "hash:" path hash) is content-level.
var metadataClasses = map[string]bool{
	ClassOn: true, ClassOff: true, ClassSet: true, ClassEmpty: true,
	ClassLoopback: true, ClassProviderDirect: true, ClassOtherHost: true,
	ClassInvalid: true,
}

// MetadataClass reports whether class is one of the closed coarse classes,
// which may ship to the org under the hook_activity tier alone. A
// content-level class (a path hash, or any value outside the closed set)
// reports false and ships only under the node's raw-content posture.
func MetadataClass(class string) bool { return metadataClasses[class] }

// EnvProbe is one route-relevant environment variable a hook records: its
// name and the function that reduces its value to a coarse class.
type EnvProbe struct {
	Name  string
	Class func(value string) string
}

// EnvProbes is the table of variables a hook invocation records (CC-2). The
// base URLs tell whether the host's effective route is the proxy; the
// provider-managed flag says the host overrides settings-file routes; the
// config dir hash tells profiles apart (CC-8); the CLAUDE_CODE_USE_*
// selectors name a third-party provider. The names are vendor-documented
// (https://code.claude.com/docs/en/env-vars) and in the generated catalog.
var EnvProbes = []EnvProbe{
	{"ANTHROPIC_BASE_URL", URLClass},
	{"OPENAI_BASE_URL", URLClass},
	{"CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST", ToggleClass},
	{"CLAUDE_CONFIG_DIR", PathHashClass},
	{"CLAUDE_CODE_USE_BEDROCK", ToggleClass},
	{"CLAUDE_CODE_USE_VERTEX", ToggleClass},
	{"CLAUDE_CODE_USE_FOUNDRY", ToggleClass},
	{"CLAUDE_CODE_USE_ANTHROPIC_AWS", ToggleClass},
	{"CLAUDE_CODE_USE_MANTLE", ToggleClass},
}

// ProviderHosts are the model-provider API hosts a base URL class calls
// provider_direct: a route that bypasses the proxy.
var ProviderHosts = map[string]bool{
	"api.anthropic.com":                 true,
	"api.openai.com":                    true,
	"generativelanguage.googleapis.com": true,
}

// EnvClasses returns the class of every EnvProbes variable getenv reports as
// set (a variable that is unset is absent). nil when none is set.
func EnvClasses(getenv func(string) string) map[string]string {
	if getenv == nil {
		return nil
	}
	var out map[string]string
	for _, p := range EnvProbes {
		v := getenv(p.Name)
		if v == "" {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		out[p.Name] = p.Class(v)
	}
	return out
}

// URLClass reduces a base URL to loopback, provider_direct, other_host or
// invalid.
func URLClass(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ClassEmpty
	}
	u, err := url.Parse(v)
	if err != nil || u.Hostname() == "" {
		return ClassInvalid
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" {
		return ClassLoopback
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return ClassLoopback
	}
	if ProviderHosts[host] {
		return ClassProviderDirect
	}
	return ClassOtherHost
}

// ToggleClass reduces a boolean-ish variable to on, off or set.
func ToggleClass(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return ClassOn
	case "0", "false", "no", "off":
		return ClassOff
	case "":
		return ClassEmpty
	}
	return ClassSet
}

// PathHashClass reduces a directory to "hash:" and the first 16 hex digits
// of the SHA-256 of its cleaned form: enough to tell two profiles apart,
// never the path.
func PathHashClass(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ClassEmpty
	}
	sum := sha256.Sum256([]byte(filepath.Clean(v)))
	return "hash:" + hex.EncodeToString(sum[:8])
}

// sessionKeys are the top-level payload keys a session id travels under,
// across the hook dialects, in precedence order (cmd/observer
// hookPayloadSessionID reads the same keys in the same order).
//
// One precedence rule (FU-127): when a payload carries the id under more
// than one spelling, the snake_case session_id wins, then the camelCase
// sessionId, then Cursor's conversation_id, then Antigravity's camelCase
// conversationId, then Cascade's trajectory_id, wherever each key sits in
// the document. It is the order the Claude-shaped tool gate reads them in
// (internal/hook genericToolPayload), so a host that sends both spellings
// (ZCode: sessionId and session_id; Grok Build) is keyed the same way by
// every handler.
var sessionKeys = []string{"session_id", "sessionId", "conversation_id", "conversationId", "trajectory_id"}

// sessionKeyRank is a key's position in sessionKeys (absent: not an id key).
func sessionKeyRank(key string) (int, bool) {
	for i, k := range sessionKeys {
		if k == key {
			return i, true
		}
	}
	return 0, false
}

// PayloadSessionID returns the session id a JSON object payload carries:
// the non-empty string under the sessionKeys key of highest precedence. It
// decodes one top-level token at a time and stops at a session_id, so a
// payload whose id comes first (Claude Code, Codex) costs almost nothing
// however large the tool input behind it; a payload keyed under another
// spelling is read to its end (or to a session_id). "" when the payload is
// not a JSON object or carries no id.
func PayloadSessionID(body []byte) string {
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	dec := json.NewDecoder(bytes.NewReader(body))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return ""
	}
	best, bestRank := "", len(sessionKeys)
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return best
		}
		key, _ := t.(string)
		if rank, ok := sessionKeyRank(key); ok {
			var s string
			if dec.Decode(&s) == nil && s != "" && rank < bestRank {
				best, bestRank = s, rank
				if rank == 0 {
					return best
				}
			}
			continue
		}
		var skip json.RawMessage
		if dec.Decode(&skip) != nil {
			return best
		}
	}
	return best
}
