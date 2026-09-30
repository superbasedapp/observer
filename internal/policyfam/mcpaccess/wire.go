package mcpaccess

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	core "github.com/marmutapp/superbased-observer/internal/mcpaccess"
)

// Family is the policy-resource family name (plan §3.1 / D10).
const Family = "tools.mcp_access"

// Modes.
const (
	ModeObserve = "observe"
	ModeEnforce = "enforce"
)

// DefaultMaxBytes bounds a body when the caller passes no cap.
const DefaultMaxBytes int64 = 1 << 20

// Body is the org-wire JSON shape.
type Body struct {
	// Mode is observe (default) or enforce.
	Mode string `json:"mode,omitempty"`
	// Registry is the compiler's registry view.
	Registry core.Registry `json:"registry"`
	// Grants are the mcp_grant rows in the pure model's shape.
	Grants []core.Grant `json:"grants"`
}

// PolicySpec is the compiled form.
type PolicySpec struct {
	Mode string
	Spec core.Spec
	// Problems carries the lint warnings (never errors - those refuse
	// compilation).
	Problems []core.Problem
	// CEL is the compiled agentgateway rule set (the P3 consumer's input).
	CEL core.CELRuleSet
}

// ErrMode names the one family-level validation rule.
var ErrMode = errors.New("policyfam/mcpaccess: mode must be observe or enforce")

// DecodeBody parses raw into Body with unknown fields refused (a misspelt
// key is an error, never a silently ignored condition) AND lints it: a body
// whose grant set carries an error-severity problem - the judge effect, a
// taint condition, requires_mfa or a task-action grant (typed
// feature_unavailable), an unknown or wildcard action, passthrough on a
// non-bearer vserver, ... - is refused with the typed *core.LintError
// (errors.As), never returned as a valid Body. R8.1 at the wire: every
// compiler AND DecodeBody surface the refusal, so a family consumer that
// validates or stores a body through this decoder cannot accept what every
// compiler would later reject. Warnings do not refuse; Lint reports them.
func DecodeBody(raw []byte, maxBytes int64) (Body, error) {
	b, err := decodeBodySyntax(raw, maxBytes)
	if err != nil {
		return Body{}, err
	}
	if ps := core.Lint(core.Spec{Registry: b.Registry, Grants: b.Grants}, 0); core.HasErrors(ps) {
		return Body{}, fmt.Errorf("policyfam/mcpaccess: %w", &core.LintError{Problems: ps})
	}
	return b, nil
}

// decodeBodySyntax is the SYNTAX-only decode (JSON shape with unknown
// fields refused, size cap, trailing data, mode) that DecodeBody, CompileBody
// and Lint share. It accepts a semantically unavailable body on purpose so
// Lint can REPORT the problem set without refusing; it is private so no
// consumer can mistake it for the validating decoder.
func decodeBodySyntax(raw []byte, maxBytes int64) (Body, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if int64(len(raw)) > maxBytes {
		return Body{}, fmt.Errorf("policyfam/mcpaccess: body is %d bytes, max %d", len(raw), maxBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var b Body
	if err := dec.Decode(&b); err != nil {
		return Body{}, fmt.Errorf("policyfam/mcpaccess: invalid body: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Body{}, errors.New("policyfam/mcpaccess: trailing data after the body")
	}
	if b.Mode == "" {
		b.Mode = ModeObserve
	}
	if b.Mode != ModeObserve && b.Mode != ModeEnforce {
		return Body{}, ErrMode
	}
	return b, nil
}

// CompileBody decodes + compiles a body and returns the compiled spec plus
// the canonical bytes to sign/hash. A lint ERROR (feature_unavailable,
// unknown action, passthrough on a non-bearer vserver, ...) is returned as
// *core.LintError so callers can render the typed problems.
func CompileBody(raw []byte, maxBytes int64) (PolicySpec, []byte, error) {
	b, err := decodeBodySyntax(raw, maxBytes)
	if err != nil {
		return PolicySpec{}, nil, err
	}
	spec := core.Spec{Registry: b.Registry, Grants: b.Grants}
	n, err := core.Normalize(spec, 0)
	if err != nil {
		return PolicySpec{}, nil, fmt.Errorf("policyfam/mcpaccess: %w", err)
	}
	cel, err := core.CompileCEL(spec, 0)
	if err != nil {
		return PolicySpec{}, nil, fmt.Errorf("policyfam/mcpaccess: %w", err)
	}
	if err := core.ValidateCEL(cel); err != nil {
		return PolicySpec{}, nil, fmt.Errorf("policyfam/mcpaccess: compiled CEL does not evaluate: %w", err)
	}
	// Canonical order: the body is signed/hashed, so two authored orderings
	// of the same policy must hash the same. Grants take the compiler's
	// canonical order (hierarchy, ord, id; disabled rows removed since they
	// are inert); vservers and their servers sort by id. A member's approved
	// snapshot (Server.Snapshot) is LIVE registry state, not authored policy:
	// the compilers read it at every compile / reload (the R9.8 drift guard)
	// and it is STRIPPED from the canonical bytes, so adopting a snapshot
	// never changes a publication's compiled_hash - adoption is picked up by
	// the next policy reload, never by a republish. The compiled Spec and
	// CEL returned here still carry the pins the decoded view had.
	b.Grants = append([]core.Grant{}, n.Grants...)
	b.Registry.VServers = canonicalVServers(b.Registry.VServers)
	canon, err := json.Marshal(b)
	if err != nil {
		return PolicySpec{}, nil, fmt.Errorf("policyfam/mcpaccess: canonicalise: %w", err)
	}
	return PolicySpec{Mode: b.Mode, Spec: spec, Problems: n.Problems, CEL: cel}, canon, nil
}

// canonicalVServers deep-copies and sorts the registry view for hashing
// (vservers by id, servers by id) and drops every member's live approved
// snapshot pin, which is registry state rather than signed policy. The
// caller's slices are never mutated.
func canonicalVServers(in []core.VServer) []core.VServer {
	out := append([]core.VServer(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	for i := range out {
		srv := append([]core.Server(nil), out[i].Servers...)
		sort.Slice(srv, func(a, c int) bool { return srv[a].ID < srv[c].ID })
		for k := range srv {
			srv[k].Snapshot = nil
		}
		out[i].Servers = srv
	}
	return out
}

// Lint is the dry compile for authoring surfaces: every typed problem
// (warnings included) without refusing.
func Lint(raw []byte, maxBytes int64) ([]core.Problem, error) {
	b, err := decodeBodySyntax(raw, maxBytes)
	if err != nil {
		return nil, err
	}
	return core.Lint(core.Spec{Registry: b.Registry, Grants: b.Grants}, 0), nil
}

// Enforces reports whether the body asks for enforce mode.
func Enforces(s PolicySpec) bool { return s.Mode == ModeEnforce }
