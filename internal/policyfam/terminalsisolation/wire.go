package terminalsisolation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// Family is the policy family name (policyfam.FamilyTerminalsIsolation).
const Family = "terminals.isolation"

// Forbidden is the one value the two provider floors accept.
const Forbidden = "forbidden"

// BodyV1 is the wire body. Every field is optional; an absent field is no
// floor. Pointers keep "absent" apart from a zero value.
type BodyV1 struct {
	MinIsolation         string    `json:"min_isolation,omitempty"`
	AllowedBackends      *[]string `json:"allowed_backends,omitempty"`
	AllowRemote          *bool     `json:"allow_remote,omitempty"`
	FloorAcceptsBeta     *bool     `json:"floor_accepts_beta,omitempty"`
	RequireFullCapture   *bool     `json:"require_full_capture,omitempty"`
	AllowedRegions       *[]string `json:"allowed_regions,omitempty"`
	ProviderKeyInjection string    `json:"provider_key_injection,omitempty"`
	ProviderMemoryImages string    `json:"provider_memory_images,omitempty"`
	MinEgress            string    `json:"min_egress,omitempty"`
	// RequireRefusalAudit (lane N4) is the newest key: a node built before
	// it refuses the body as an unknown field, and one that knows it but
	// does not advertise its token NACKs (capability_mismatch), so no node
	// ever reads the floor as absent.
	RequireRefusalAudit *bool `json:"require_refusal_audit,omitempty"`
	// GatewayModes (OpenShell lane O4) lists the sandbox gateway modes a
	// row run through a gateway may use (managed_local, external): a
	// newer key like require_refusal_audit, so a node built before it
	// refuses the body as an unknown field and one that does not advertise
	// its token NACKs, never reading the floor as absent.
	GatewayModes *[]string `json:"gateway_modes,omitempty"`
}

// PolicySpec is the compiled floors. A zero field is no floor.
type PolicySpec struct {
	MinIsolation vocab.IsoClass
	// AllowedBackends nil means any backend.
	AllowedBackends []string
	// ForbidRemote: allow_remote = false.
	ForbidRemote       bool
	FloorAcceptsBeta   bool
	RequireFullCapture bool
	// AllowedRegions nil means any region.
	AllowedRegions             []string
	ForbidProviderKeyInjection bool
	ForbidProviderMemoryImages bool
	MinEgress                  vocab.Tier
	// RequireRefusalAudit: only a launch on a tier whose refusals the row
	// hands to the node's refusal audit may run (sandboxbackend
	// Net.RefusalAuditTiers).
	RequireRefusalAudit bool
	// GatewayModes nil means any gateway mode; otherwise a row run through
	// a gateway may run only under one of these (sandboxselect rule S7g).
	// A row with no gateway is not judged by it.
	GatewayModes []string
	// Keys lists the floor keys the body set, in FloorKeys order.
	Keys []string
	Hash string
}

// FloorKey is one row of the floor table: the wire key, its admin label,
// the capability token a node needs to enforce it, whether it implies
// sandbox_required on the node (section 8.1: min_isolation, allowed_backends
// and min_egress do; the rest only qualify which backend may be used), and
// whether this build enforces it.
type FloorKey struct {
	Key            string
	Label          string
	Token          string
	ImpliesSandbox bool
	// Enforced: this build applies the floor (sandboxselect.Floors carries
	// it). A key this build cannot enforce is not a live capability, so a
	// body naming it NACKs instead of being ignored.
	Enforced bool
	present  func(s PolicySpec) bool
}

// tokenPrefix is the capability token prefix, one token per floor key.
const tokenPrefix = "terminals.isolation."

// FloorKeys is the floor table, in the order the admin form lists them.
var FloorKeys = []FloorKey{
	{
		Key: "min_isolation", Label: "Minimum isolation", ImpliesSandbox: true, Enforced: true,
		present: func(s PolicySpec) bool { return s.MinIsolation != "" },
	},
	{
		Key: "allowed_backends", Label: "Allowed sandbox backends", ImpliesSandbox: true, Enforced: true,
		present: func(s PolicySpec) bool { return s.AllowedBackends != nil },
	},
	{
		Key: "min_egress", Label: "Minimum network tier", ImpliesSandbox: true, Enforced: true,
		present: func(s PolicySpec) bool { return s.MinEgress != "" },
	},
	{
		Key: "allow_remote", Label: "Hosted sandboxes", Enforced: true,
		present: func(s PolicySpec) bool { return s.ForbidRemote },
	},
	{
		Key: "floor_accepts_beta", Label: "Beta backends may meet the floors", Enforced: true,
		present: func(s PolicySpec) bool { return s.FloorAcceptsBeta },
	},
	{
		Key: "require_full_capture", Label: "Require full capture", Enforced: true,
		present: func(s PolicySpec) bool { return s.RequireFullCapture },
	},
	// Lane N4: a qualifying floor (it narrows which backend may run, like
	// require_full_capture, and implies no sandbox on its own).
	{
		Key: "require_refusal_audit", Label: "Require refusal audit", Enforced: true,
		present: func(s PolicySpec) bool { return s.RequireRefusalAudit },
	},
	// OpenShell lane O4: a qualifying floor too. Rule S7g judges only the
	// gateway mode a row's driver reports, but like every floor its
	// presence puts the body in force: managed nodes are projected
	// "Require a sandboxed terminal", and beta rows drop without
	// floor_accepts_beta (S4b).
	{
		Key: "gateway_modes", Label: "Allowed sandbox gateway modes", Enforced: true,
		present: func(s PolicySpec) bool { return s.GatewayModes != nil },
	},
	{
		Key: "allowed_regions", Label: "Allowed hosted regions", Enforced: true,
		present: func(s PolicySpec) bool { return s.AllowedRegions != nil },
	},
	{
		Key: "provider_key_injection", Label: "Provider key injection", Enforced: true,
		present: func(s PolicySpec) bool { return s.ForbidProviderKeyInjection },
	},
	// No hosted row exists before P7, so no build can apply this floor yet:
	// a body naming it NACKs on every node until then (sandboxselect.Floors
	// gains the field with the hosted rows).
	{
		Key: "provider_memory_images", Label: "Provider memory images", Enforced: false,
		present: func(s PolicySpec) bool { return s.ForbidProviderMemoryImages },
	},
}

func init() {
	for i := range FloorKeys {
		FloorKeys[i].Token = tokenPrefix + FloorKeys[i].Key
	}
}

// LookupFloorKey returns the floor table row for a wire key.
func LookupFloorKey(key string) (FloorKey, bool) {
	for _, k := range FloorKeys {
		if k.Key == key {
			return k, true
		}
	}
	return FloorKey{}, false
}

// DecodeBody strictly decodes raw: unknown fields refused, the document
// capped at maxBytes, no bytes after it.
func DecodeBody(raw []byte, maxBytes int64) (BodyV1, error) {
	if maxBytes <= 0 {
		return BodyV1{}, fmt.Errorf("terminalsisolation.DecodeBody: cap must be positive, got %d", maxBytes)
	}
	if int64(len(raw)) > maxBytes {
		return BodyV1{}, fmt.Errorf("terminalsisolation.DecodeBody: body is %d bytes, exceeds the %d-byte cap", len(raw), maxBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var body BodyV1
	if err := dec.Decode(&body); err != nil {
		return BodyV1{}, fmt.Errorf("terminalsisolation.DecodeBody: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return BodyV1{}, errors.New("terminalsisolation.DecodeBody: trailing bytes after the document")
	}
	return body, nil
}

// Compile validates a decoded body into floors. Every value that would widen
// a node, or that names something outside the closed vocabularies, is a hard
// error.
func Compile(b BodyV1) (PolicySpec, error) {
	var s PolicySpec
	if m := strings.TrimSpace(b.MinIsolation); m != "" {
		c := vocab.IsoClass(m)
		if !c.Valid() || c == vocab.ClassNone {
			return PolicySpec{}, fmt.Errorf("min_isolation %q is not one of process, container, userspace_kernel, hw_vm", m)
		}
		s.MinIsolation = c
	}
	if b.AllowedBackends != nil {
		l, err := closedList("allowed_backends", *b.AllowedBackends, func(v string) bool { _, ok := sandboxbackend.Get(v); return ok })
		if err != nil {
			return PolicySpec{}, err
		}
		s.AllowedBackends = l
	}
	if b.AllowRemote != nil {
		if *b.AllowRemote {
			return PolicySpec{}, errors.New("allow_remote can only be false (a floor never turns hosted sandboxes on); omit it to leave the choice to each node")
		}
		s.ForbidRemote = true
	}
	if b.FloorAcceptsBeta != nil {
		s.FloorAcceptsBeta = *b.FloorAcceptsBeta
	}
	if b.RequireFullCapture != nil {
		s.RequireFullCapture = *b.RequireFullCapture
	}
	if b.RequireRefusalAudit != nil {
		// false is no floor, as for require_full_capture: a floor only
		// tightens, so there is nothing to widen.
		s.RequireRefusalAudit = *b.RequireRefusalAudit
	}
	if b.GatewayModes != nil {
		l, err := closedList("gateway_modes", *b.GatewayModes, func(v string) bool { return vocab.GatewayMode(v).Valid() })
		if err != nil {
			return PolicySpec{}, err
		}
		s.GatewayModes = l
	}
	if b.AllowedRegions != nil {
		l, err := closedList("allowed_regions", *b.AllowedRegions, func(v string) bool { return !strings.ContainsAny(v, " \t\r\n") })
		if err != nil {
			return PolicySpec{}, err
		}
		s.AllowedRegions = l
	}
	var err error
	if s.ForbidProviderKeyInjection, err = forbiddenOnly("provider_key_injection", b.ProviderKeyInjection); err != nil {
		return PolicySpec{}, err
	}
	if s.ForbidProviderMemoryImages, err = forbiddenOnly("provider_memory_images", b.ProviderMemoryImages); err != nil {
		return PolicySpec{}, err
	}
	if e := strings.TrimSpace(b.MinEgress); e != "" {
		t := vocab.Tier(e)
		switch {
		case t == vocab.TierNone:
			// The none tier forwards not even the model proxy, so a none
			// floor would force reduced capture (I2, I7).
			return PolicySpec{}, errors.New("min_egress cannot be none: the none tier forwards not even the model proxy, so it would force reduced capture; the strictest floor is proxy_only")
		case !t.Valid():
			return PolicySpec{}, fmt.Errorf("min_egress %q is not one of host, internet, proxy_only", e)
		}
		s.MinEgress = t
	}
	for _, k := range FloorKeys {
		if k.present(s) {
			s.Keys = append(s.Keys, k.Key)
		}
	}
	s.Hash = hashSpec(s)
	return s, nil
}

func closedList(name string, in []string, valid func(string) bool) ([]string, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("%s is empty, which would allow nothing; omit it to allow any", name)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		switch {
		case v == "":
			return nil, fmt.Errorf("%s contains an empty entry", name)
		case seen[v]:
			return nil, fmt.Errorf("%s names %q twice", name, v)
		case !valid(v):
			return nil, fmt.Errorf("%s names %q, which is not a known value", name, v)
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out, nil
}

func forbiddenOnly(name, v string) (bool, error) {
	switch strings.TrimSpace(v) {
	case "":
		return false, nil
	case Forbidden:
		return true, nil
	}
	return false, fmt.Errorf("%s may only be %q (a floor never allows what the node does not); omit it to leave the choice to each node", name, Forbidden)
}

// CanonicalJSON re-encodes a body deterministically, so the signed body hash
// never depends on the publisher's whitespace or key order. Lists are sorted
// first.
//
// An explicit "require_refusal_audit": false is dropped (tracker F-012,
// audit finding N4-A6): false is no floor, the same as an absent key, and
// dropping it keeps the published body one a node built before the key
// accepts (it refuses the key as unknown whatever its value). The compiled
// spec and its hash are the same either way.
func CanonicalJSON(b BodyV1) ([]byte, error) {
	cp := b
	if b.RequireRefusalAudit != nil && !*b.RequireRefusalAudit {
		cp.RequireRefusalAudit = nil
	}
	if b.AllowedBackends != nil {
		l := append([]string(nil), *b.AllowedBackends...)
		sort.Strings(l)
		cp.AllowedBackends = &l
	}
	if b.AllowedRegions != nil {
		l := append([]string(nil), *b.AllowedRegions...)
		sort.Strings(l)
		cp.AllowedRegions = &l
	}
	if b.GatewayModes != nil {
		l := append([]string(nil), *b.GatewayModes...)
		sort.Strings(l)
		cp.GatewayModes = &l
	}
	out, err := json.Marshal(cp)
	if err != nil {
		return nil, fmt.Errorf("terminalsisolation.CanonicalJSON: %w", err)
	}
	return out, nil
}

// CompileBody decodes, canonicalizes and compiles raw org-wire bytes.
func CompileBody(raw []byte, maxBytes int64) (PolicySpec, []byte, error) {
	body, err := DecodeBody(raw, maxBytes)
	if err != nil {
		return PolicySpec{}, nil, err
	}
	canon, err := CanonicalJSON(body)
	if err != nil {
		return PolicySpec{}, nil, err
	}
	spec, err := Compile(body)
	if err != nil {
		return PolicySpec{}, nil, fmt.Errorf("terminalsisolation.CompileBody: %w", err)
	}
	return spec, canon, nil
}

// InForce reports whether the spec sets any floor.
func (s PolicySpec) InForce() bool { return len(s.Keys) > 0 }

// ImpliesSandboxRequired reports whether a floor the spec sets implies
// sandbox_required on the node (section 8.1).
func (s PolicySpec) ImpliesSandboxRequired() bool {
	_, ok := s.ImpliedBy()
	return ok
}

// ImpliedBy names the first floor key that implies sandbox_required.
func (s PolicySpec) ImpliedBy() (FloorKey, bool) {
	for _, k := range FloorKeys {
		if k.ImpliesSandbox && k.present(s) {
			return k, true
		}
	}
	return FloorKey{}, false
}

// RequiredCapabilities is one token per floor key the spec sets.
func RequiredCapabilities(s PolicySpec) []string {
	var out []string
	for _, k := range FloorKeys {
		if k.present(s) {
			out = append(out, k.Token)
		}
	}
	return out
}

// LiveCapabilities is the tokens of every floor this build enforces.
func LiveCapabilities() []string {
	var out []string
	for _, k := range FloorKeys {
		if k.Enforced {
			out = append(out, k.Token)
		}
	}
	return out
}

func hashSpec(s PolicySpec) string {
	h := sha256.New()
	write := func(parts ...string) {
		for _, p := range parts {
			_, _ = h.Write([]byte(p))
			_, _ = h.Write([]byte{0})
		}
	}
	write("min_isolation", string(s.MinIsolation), "allowed_backends", strings.Join(s.AllowedBackends, ","),
		"forbid_remote", fmt.Sprint(s.ForbidRemote), "beta", fmt.Sprint(s.FloorAcceptsBeta),
		"full_capture", fmt.Sprint(s.RequireFullCapture), "regions", strings.Join(s.AllowedRegions, ","),
		"key_injection", fmt.Sprint(s.ForbidProviderKeyInjection), "memory_images", fmt.Sprint(s.ForbidProviderMemoryImages),
		"min_egress", string(s.MinEgress))
	// Written only when set, so the hash of every body published before
	// the key existed is unchanged.
	if s.RequireRefusalAudit {
		write("refusal_audit", "true")
	}
	if s.GatewayModes != nil {
		write("gateway_modes", strings.Join(s.GatewayModes, ","))
	}
	return hex.EncodeToString(h.Sum(nil))
}
