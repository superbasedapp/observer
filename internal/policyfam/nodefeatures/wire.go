package nodefeatures

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// BodyV1 is the org-wire v1 body for the node.features family
// (org-parity plan W5.1): the exact JSON shape an org publisher POSTs and
// an agent later finds inside a fetched SignedPolicyResource.Body.
//
//	{
//	  "terminals": {"enabled": true, "max_concurrent": 2, "sandbox_required": true},
//	  "remote": {"enabled": false},
//	  "routing_apply": {"enabled": true},
//	  "patterns_write": {"enabled": true},
//	  "tools": {"disallow": ["codex", "opencode"]}
//	}
//
// Every top-level key is optional: a body may govern any subset of the
// five stanzas, leaving the rest ungoverned (fail-open) on the node — this
// is what makes the family incrementally adoptable rather than
// all-or-nothing.
type BodyV1 struct {
	Terminals     *TerminalsBodyV1 `json:"terminals,omitempty"`
	Remote        *FeatureBodyV1   `json:"remote,omitempty"`
	RoutingApply  *FeatureBodyV1   `json:"routing_apply,omitempty"`
	PatternsWrite *FeatureBodyV1   `json:"patterns_write,omitempty"`
	Tools         *ToolsBodyV1     `json:"tools,omitempty"`
}

// FeatureBodyV1 is the wire shape of a simple enabled-only governed
// feature (remote, routing_apply, patterns_write).
type FeatureBodyV1 struct {
	// Enabled is a pointer so "the org published this stanza but forgot to
	// say enabled" is a hard compile error rather than silently defaulting
	// to disabled (or enabled) — every governed feature must be explicit.
	Enabled *bool `json:"enabled"`
}

// TerminalsBodyV1 additionally carries the two terminal-only limits.
type TerminalsBodyV1 struct {
	Enabled         *bool `json:"enabled"`
	MaxConcurrent   *int  `json:"max_concurrent,omitempty"`
	SandboxRequired *bool `json:"sandbox_required,omitempty"`
}

// ToolsBodyV1 is the wire shape of the tools disallow-list stanza.
// Presence of the stanza (a non-nil *ToolsBodyV1 on BodyV1) governs the
// feature regardless of whether Disallow is empty — an org can publish an
// empty list to explicitly assert "nothing is disallowed" as a positive
// fact, distinct from never having opined at all. Unlike the enabled-only
// stanzas above, there is no required field here: an empty/absent
// Disallow is a valid, meaningful state on its own.
type ToolsBodyV1 struct {
	Disallow []string `json:"disallow,omitempty"`
}

// DecodeBody strictly decodes raw org-wire JSON bytes into a BodyV1:
// unknown fields are rejected (DisallowUnknownFields), the document must
// not exceed maxBytes, and any byte after the JSON value is rejected — the
// same closed-document discipline as the other policyfam family compilers.
func DecodeBody(raw []byte, maxBytes int64) (BodyV1, error) {
	if maxBytes <= 0 {
		return BodyV1{}, fmt.Errorf("policyfam/nodefeatures.DecodeBody: cap must be positive, got %d", maxBytes)
	}
	if int64(len(raw)) > maxBytes {
		return BodyV1{}, fmt.Errorf("policyfam/nodefeatures.DecodeBody: body is %d bytes, exceeds the %d-byte cap", len(raw), maxBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var body BodyV1
	if err := dec.Decode(&body); err != nil {
		return BodyV1{}, fmt.Errorf("policyfam/nodefeatures.DecodeBody: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return BodyV1{}, fmt.Errorf("policyfam/nodefeatures.DecodeBody: trailing bytes after the document")
	}
	return body, nil
}

// CanonicalJSON re-encodes a decoded BodyV1 deterministically so BodyHash
// is always computed over the same bytes DecodeBody would reproduce, never
// over the publisher's raw submission bytes (whitespace/key-order
// insensitive).
func CanonicalJSON(b BodyV1) ([]byte, error) {
	out, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("policyfam/nodefeatures.CanonicalJSON: %w", err)
	}
	return out, nil
}

// Compile validates a decoded BodyV1 and produces a ready PolicySpec. A
// present stanza whose "enabled" was omitted (nil) is a hard compile
// error — every governed feature must say explicitly whether it is
// enabled or disabled; there is no implicit default.
func Compile(b BodyV1) (PolicySpec, error) {
	var spec PolicySpec
	if b.Terminals != nil {
		if b.Terminals.Enabled == nil {
			return PolicySpec{}, fmt.Errorf("policyfam/nodefeatures.Compile: terminals.enabled is required when the terminals stanza is present")
		}
		maxConcurrent := 0
		if b.Terminals.MaxConcurrent != nil {
			if *b.Terminals.MaxConcurrent < 0 {
				return PolicySpec{}, fmt.Errorf("policyfam/nodefeatures.Compile: terminals.max_concurrent must be >= 0")
			}
			maxConcurrent = *b.Terminals.MaxConcurrent
		}
		sandboxRequired := false
		if b.Terminals.SandboxRequired != nil {
			sandboxRequired = *b.Terminals.SandboxRequired
		}
		spec.Terminals = TerminalsRule{
			FeatureRule:     FeatureRule{Governed: true, Enabled: *b.Terminals.Enabled},
			MaxConcurrent:   maxConcurrent,
			SandboxRequired: sandboxRequired,
		}
	}
	rule, err := compileFeature("remote", b.Remote)
	if err != nil {
		return PolicySpec{}, err
	}
	spec.Remote = rule
	rule, err = compileFeature("routing_apply", b.RoutingApply)
	if err != nil {
		return PolicySpec{}, err
	}
	spec.RoutingApply = rule
	rule, err = compileFeature("patterns_write", b.PatternsWrite)
	if err != nil {
		return PolicySpec{}, err
	}
	spec.PatternsWrite = rule
	if b.Tools != nil {
		disallow := make(map[string]bool, len(b.Tools.Disallow))
		for _, t := range b.Tools.Disallow {
			t = strings.ToLower(strings.TrimSpace(t))
			if t == "" {
				continue
			}
			disallow[t] = true
		}
		spec.Tools = ToolsRule{Governed: true, Disallow: disallow}
	}
	spec.Hash = hashBody(b)
	return spec, nil
}

func compileFeature(name string, fb *FeatureBodyV1) (FeatureRule, error) {
	if fb == nil {
		return FeatureRule{}, nil
	}
	if fb.Enabled == nil {
		return FeatureRule{}, fmt.Errorf("policyfam/nodefeatures.Compile: %s.enabled is required when the %s stanza is present", name, name)
	}
	return FeatureRule{Governed: true, Enabled: *fb.Enabled}, nil
}

// hashBody computes a stable content hash over the canonical JSON encoding
// of the body — the same discipline as policyfam/providers.HashLaneTable,
// simplified here since encoding/json's deterministic (sorted-key) struct
// marshaling already gives a stable byte sequence to hash directly, with no
// map-iteration-order hazard to guard against.
func hashBody(b BodyV1) string {
	canon, err := CanonicalJSON(b)
	if err != nil {
		// CanonicalJSON only fails on values json.Marshal itself cannot
		// encode (channels, funcs) — BodyV1 contains none, so this is
		// unreachable in practice; fall back to hashing nothing rather
		// than panicking in a pure library function.
		canon = nil
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:])
}

// CompileBody decodes and canonicalizes raw org-wire JSON, then compiles it
// into a ready PolicySpec. It returns the canonical JSON bytes the caller
// should sign/hash as the resource's Body.
func CompileBody(raw []byte, maxBytes int64) (spec PolicySpec, canonicalBody []byte, err error) {
	body, err := DecodeBody(raw, maxBytes)
	if err != nil {
		return PolicySpec{}, nil, err
	}
	canon, err := CanonicalJSON(body)
	if err != nil {
		return PolicySpec{}, nil, err
	}
	spec, err = Compile(body)
	if err != nil {
		return PolicySpec{}, nil, fmt.Errorf("policyfam/nodefeatures.CompileBody: %w", err)
	}
	return spec, canon, nil
}
