package mcpaccess

import (
	"encoding/base32"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// MaxTargetNameLen is agentgateway v1.5.0's MCP target-name length cap
// (MCP_TARGET_NAME_MAX_LEN in crates/agentgateway/src/types/agent.rs: the
// Gateway API SectionName limit).
const MaxTargetNameLen = 253

// targetNameRE is agentgateway v1.5.0's MCP_TARGET_NAME_RE, verbatim: dot-
// separated DNS labels of lowercase letters, digits and '-', each starting
// and ending with a letter or digit. '_' and '+' are NOT in it - they are
// agentgateway's multiplexing delimiters (`<target>_<tool>` names,
// `<target>+<uri>` resources), which is why a raw registry id (srv_<hex>)
// is refused as a target name.
var targetNameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)

// ValidTargetName reports whether name is accepted by the pinned
// agentgateway as an MCP target name (validate_mcp_target_name: non-empty,
// at most MaxTargetNameLen bytes, the SectionName pattern). It is the ONE
// copy of that rule on this side of the gateway.
func ValidTargetName(name string) bool {
	return name != "" && len(name) <= MaxTargetNameLen && targetNameRE.MatchString(name)
}

// escapedTargetPrefix marks the escaped form of TargetName. It carries "--",
// which the plain form can never produce (see TargetName).
const escapedTargetPrefix = "x--"

// targetB32 is the escape alphabet: RFC 4648 base32hex, unpadded and
// lowercased by the caller, so every escaped symbol is in [0-9a-v].
var targetB32 = base32.HexEncoding.WithPadding(base32.NoPadding)

// ErrNoTargetName is wrapped when a server id has no agentgateway MCP
// target name (empty, or too long to escape within MaxTargetNameLen).
var ErrNoTargetName = errors.New("mcpaccess: no agentgateway MCP target name for server id")

// TargetName is the agentgateway MCP target name of the registry server id
// serverID: the name the A2 hop gives the member's MCP target and the value
// agentgateway reports as mcp.<kind>.target in its authorization CEL. It is
// the ONE mapping from our server-id space to agentgateway's target-name
// space; every place that shows a server id to agentgateway goes through it.
//
// Id space. The registry mints ids as "srv_" + 16 lowercase hex
// (internal/orgserver/mcpregistry randomID, agentaccesswire mintID; the
// crypto/rand-failure fallback is "srv_" + lowercase hex), but the store's
// own validator (regstore.Server.Validate) requires only a NON-EMPTY id, so
// the function is total over every string and never silently collides:
//
//   - PLAIN form: an id made only of [a-z0-9._], with no "__", whose
//     '_'->'-' image is a valid target name, maps to that image
//     ("srv_303c8f9ab45f0015" -> "srv-303c8f9ab45f0015"; "github" ->
//     "github"). '_'->'-' is a one-to-one symbol map on that alphabet (no
//     plain id contains '-'), so the plain form is injective.
//   - ESCAPED form: every other id (one with '-', an upper-case letter, "__"
//     or any other byte) maps to "x--" + lowercase unpadded base32hex of its
//     bytes ("srv-gh" -> "x--edp7cbj7d0"). base32 is injective, so the
//     escaped form is too.
//   - The two forms are DISJOINT: an escaped name always contains "--",
//     and a plain name never does (its only '-' come from '_', and "__" is
//     excluded from the plain domain).
//
// The result always satisfies ValidTargetName. An empty id, or one whose
// escaped form exceeds MaxTargetNameLen (ids over 156 bytes that are not
// plain), is an error wrapping ErrNoTargetName - refused, never truncated.
func TargetName(serverID string) (string, error) {
	if serverID == "" {
		return "", fmt.Errorf("%w: empty id", ErrNoTargetName)
	}
	if plainTargetID(serverID) {
		if name := strings.ReplaceAll(serverID, "_", "-"); ValidTargetName(name) {
			return name, nil
		}
	}
	name := escapedTargetPrefix + strings.ToLower(targetB32.EncodeToString([]byte(serverID)))
	if len(name) > MaxTargetNameLen {
		return "", fmt.Errorf("%w: id of %d bytes escapes to %d > %d bytes", ErrNoTargetName, len(serverID), len(name), MaxTargetNameLen)
	}
	return name, nil
}

// plainTargetID reports whether id is in the plain domain's alphabet
// ([a-z0-9._], no "__"); TargetName still requires the image to be valid.
func plainTargetID(id string) bool {
	if strings.Contains(id, "__") {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' && c != '_' {
			return false
		}
	}
	return true
}

// celTarget is the mcp.<kind>.target value agentgateway would report for
// the server reference ref, used on BOTH sides of the CEL target (the
// compiled literal and the evaluator's activation) so they agree. An id
// with no target name (ErrNoTargetName) can never be a gateway target - the
// hop refuses to render it - so it maps to a value no target name can
// equal: '_' is outside the target-name alphabet. An empty ref (the
// server is unknown) stays empty, which no target name equals either.
func celTarget(ref string) string {
	if ref == "" {
		return ""
	}
	if name, err := TargetName(ref); err == nil {
		return name
	}
	return "_" + ref
}
