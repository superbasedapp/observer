package entitlements

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// BodySchema names the body layout inside an sbo-entitlements-v1 envelope.
// A reader ignores unknown JSON fields (the platformcontract v1 rule); a
// changed meaning is a new schema string.
const BodySchema = "sbo-entitlements-body-v1"

// Bounds on a body.
const (
	maxCapabilities = 256
	maxCaps         = 64
	maxTerms        = 32
	maxLabel        = 80
	maxPlanName     = 48
	maxValue        = 128
)

// PlanRef names the plan a document was issued from. It is informational
// (display, the generated cloud plans row, billing reconciliation): code
// never branches on it, which the plan-name lint enforces.
type PlanRef struct {
	// Name is the plan's catalog name (PlanWords holds the vocabulary).
	Name string `json:"name"`
	// Version is the plan's catalog version.
	Version int `json:"version"`
	// Label is the user-facing plan name.
	Label string `json:"label"`
}

// Body is the signed entitlements body.
type Body struct {
	// Schema is BodySchema.
	Schema string `json:"schema"`
	// Org is the org (or account) id the document is issued to; it must
	// equal the envelope's signed scope. Empty in a catalog template.
	Org string `json:"org,omitempty"`
	// Kind is the kind of org the document entitles.
	Kind Kind `json:"kind"`
	// Plan names the catalog plan the document was issued from.
	Plan PlanRef `json:"plan"`
	// Capabilities are the plan-gated server component ids the document
	// entitles (sorted, unique). Included components need not be listed.
	Capabilities []string `json:"capabilities,omitempty"`
	// Caps are the numeric caps (Unlimited = no limit).
	Caps map[CapName]int64 `json:"caps,omitempty"`
	// Terms are the string-valued terms.
	Terms map[TermName]string `json:"terms,omitempty"`
	// IssuedAt is when the document was issued (unix seconds).
	IssuedAt int64 `json:"issued_at,omitempty"`
	// NotBefore is when the document starts to apply (unix seconds; 0 =
	// from issue).
	NotBefore int64 `json:"not_before,omitempty"`
	// NotAfter is when the document stops applying (unix seconds; 0 = no
	// end). A licence and a paid period carry one; the issuer adds the
	// grace (plan 06 17.5) before signing.
	NotAfter int64 `json:"not_after,omitempty"`
	// Licensee names the licence holder on a self-hosted licence.
	Licensee string `json:"licensee,omitempty"`
}

// Body errors.
var (
	// ErrBody means a body is malformed or breaks a rule.
	ErrBody = errors.New("entitlements: invalid body")
)

// bodyRule is one row of a validation table, walked top-down; every row
// that fails is reported.
type bodyRule struct {
	name  string
	check func(b Body) error
}

// structuralRules hold for every body: a received document, an issued one
// and a catalog template. They never refuse a name this binary does not
// know (only a known core id), so a newer issuer's additive cap, term or
// component reaches an older host as an ignored value, not a refusal.
func structuralRules() []bodyRule {
	return []bodyRule{
		{name: "schema", check: checkSchema},
		{name: "kind", check: checkKind},
		{name: "plan", check: checkPlanRef},
		{name: "capabilities", check: checkCapabilities},
		{name: "caps", check: checkCaps},
		{name: "terms", check: checkTerms},
		{name: "window", check: checkWindow},
		{name: "licensee", check: checkLicensee},
	}
}

func checkSchema(b Body) error {
	if b.Schema != BodySchema {
		return fmt.Errorf("schema %q, want %q", b.Schema, BodySchema)
	}
	return nil
}

func checkKind(b Body) error {
	if !b.Kind.Valid() {
		return fmt.Errorf("unknown kind %q", b.Kind)
	}
	return nil
}

func checkPlanRef(b Body) error {
	if !validPlanName(b.Plan.Name) {
		return fmt.Errorf("plan name %q is not [a-z][a-z0-9_]* of at most %d characters", b.Plan.Name, maxPlanName)
	}
	if b.Plan.Version < 1 {
		return fmt.Errorf("plan version %d is not positive", b.Plan.Version)
	}
	if b.Plan.Label == "" || len(b.Plan.Label) > maxLabel || !printable(b.Plan.Label, true) {
		return fmt.Errorf("plan label empty, too long or not printable")
	}
	return nil
}

func checkCapabilities(b Body) error {
	if len(b.Capabilities) > maxCapabilities {
		return fmt.Errorf("%d capabilities, at most %d", len(b.Capabilities), maxCapabilities)
	}
	seen := map[string]bool{}
	for _, id := range b.Capabilities {
		if id == "" || len(id) > maxValue || !printable(id, false) {
			return fmt.Errorf("capability %q is empty, too long or not printable", id)
		}
		if seen[id] {
			return fmt.Errorf("capability %q listed twice", id)
		}
		seen[id] = true
		if c, ok := components.Get(id); ok && c.Class == components.ClassCore {
			return fmt.Errorf("capability %q is core: core is always entitled", id)
		}
	}
	return nil
}

func checkCaps(b Body) error {
	if len(b.Caps) > maxCaps {
		return fmt.Errorf("%d caps, at most %d", len(b.Caps), maxCaps)
	}
	for _, n := range sortedCapNames(b.Caps) {
		if n == "" || len(n) > maxValue || !printable(string(n), false) {
			return fmt.Errorf("cap name %q is empty, too long or not printable", n)
		}
		if v := b.Caps[n]; v < 0 && v != Unlimited {
			return fmt.Errorf("cap %s is %d: negative and not Unlimited", n, v)
		}
	}
	return nil
}

func checkTerms(b Body) error {
	if len(b.Terms) > maxTerms {
		return fmt.Errorf("%d terms, at most %d", len(b.Terms), maxTerms)
	}
	for _, n := range sortedTermNames(b.Terms) {
		if n == "" || len(n) > maxValue || !printable(string(n), false) {
			return fmt.Errorf("term name %q is empty, too long or not printable", n)
		}
		if v := b.Terms[n]; v == "" || len(v) > maxValue || !printable(v, false) {
			return fmt.Errorf("term %s value is empty, too long or not printable", n)
		}
	}
	return nil
}

func checkWindow(b Body) error {
	if b.IssuedAt < 0 || b.NotBefore < 0 || b.NotAfter < 0 {
		return fmt.Errorf("a time is negative")
	}
	if b.NotAfter != 0 && b.NotAfter <= b.NotBefore {
		return fmt.Errorf("not_after %d is not after not_before %d", b.NotAfter, b.NotBefore)
	}
	return nil
}

func checkLicensee(b Body) error {
	if len(b.Licensee) > maxLabel || !printable(b.Licensee, true) {
		return fmt.Errorf("licensee too long or not printable")
	}
	return nil
}

// vocabularyRules hold for what this binary issues: a catalog template and
// an issued document. Every name must be in this binary's vocabulary and
// apply to the body's kind, and every capability must be a mapped,
// plan-gated server row.
func vocabularyRules() []bodyRule {
	return []bodyRule{
		{name: "capability mapping", check: func(b Body) error {
			for _, id := range b.Capabilities {
				g, ok := GateOf(id)
				if !ok {
					return fmt.Errorf("capability %q is not a mapped server component", id)
				}
				if g != GatePlan {
					return fmt.Errorf("capability %q is %s: only plan-gated components are listed", id, g)
				}
			}
			if !sort.StringsAreSorted(b.Capabilities) {
				return fmt.Errorf("capabilities are not sorted")
			}
			return nil
		}},
		{name: "cap vocabulary", check: func(b Body) error {
			for _, n := range sortedCapNames(b.Caps) {
				r, ok := capRuleFor(n)
				if !ok {
					return fmt.Errorf("cap %q is not in the vocabulary", n)
				}
				if !slices.Contains(r.kinds, b.Kind) {
					return fmt.Errorf("cap %s does not apply to kind %s", n, b.Kind)
				}
				if v := b.Caps[n]; v != Unlimited && r.value != nil && !r.value(v) {
					return fmt.Errorf("cap %s value %d is not allowed", n, v)
				}
			}
			return nil
		}},
		{name: "term vocabulary", check: func(b Body) error {
			for _, n := range sortedTermNames(b.Terms) {
				r, ok := termRuleFor(n)
				if !ok {
					return fmt.Errorf("term %q is not in the vocabulary", n)
				}
				if !slices.Contains(r.kinds, b.Kind) {
					return fmt.Errorf("term %s does not apply to kind %s", n, b.Kind)
				}
			}
			return nil
		}},
	}
}

// templateRules: a catalog template names no org and carries no time.
func templateRules() []bodyRule {
	return []bodyRule{
		{name: "template org", check: func(b Body) error {
			if b.Org != "" {
				return fmt.Errorf("a template names no org")
			}
			if b.IssuedAt != 0 || b.NotBefore != 0 || b.NotAfter != 0 {
				return fmt.Errorf("a template carries no issue or validity time")
			}
			return nil
		}},
	}
}

// issuedRules: an issued document names a valid scope and its issue time.
func issuedRules() []bodyRule {
	return []bodyRule{
		{name: "issued org", check: func(b Body) error {
			if err := platformcontract.ValidateDocumentScope(platformcontract.KindEntitlements, b.Org); err != nil {
				return fmt.Errorf("org %q is not a valid document scope", b.Org)
			}
			return nil
		}},
		{name: "issued at", check: func(b Body) error {
			if b.IssuedAt <= 0 {
				return fmt.Errorf("issued_at is not set")
			}
			return nil
		}},
	}
}

func runRules(what string, b Body, sets ...[]bodyRule) error {
	var probs []string
	for _, set := range sets {
		for _, r := range set {
			if err := r.check(b); err != nil {
				probs = append(probs, r.name+": "+err.Error())
			}
		}
	}
	if len(probs) == 0 {
		return nil
	}
	return fmt.Errorf("entitlements.%s: %s: %w", what, strings.Join(probs, "; "), ErrBody)
}

// Validate applies the structural rules: what a host checks on a document
// it received (vocabulary-free, see structuralRules).
func (b Body) Validate() error { return runRules("Validate", b, structuralRules()) }

// CheckTemplate applies the rules of a catalog template.
func (b Body) CheckTemplate() error {
	return runRules("CheckTemplate", b, structuralRules(), vocabularyRules(), templateRules())
}

// CheckIssuable applies the rules of a document about to be signed: the
// structural rules, this binary's vocabulary and the issued-document rules.
// The signer side calls it; a host never needs to.
func (b Body) CheckIssuable() error {
	return runRules("CheckIssuable", b, structuralRules(), vocabularyRules(), issuedRules())
}

// Normalized returns a copy with capabilities sorted and deduplicated and
// empty maps dropped, so equal bodies encode to equal bytes.
func (b Body) Normalized() Body {
	out := b
	out.Capabilities = nil
	if len(b.Capabilities) > 0 {
		out.Capabilities = slices.Compact(slices.Sorted(slices.Values(b.Capabilities)))
	}
	out.Caps = nil
	if len(b.Caps) > 0 {
		out.Caps = make(map[CapName]int64, len(b.Caps))
		for k, v := range b.Caps {
			out.Caps[k] = v
		}
	}
	out.Terms = nil
	if len(b.Terms) > 0 {
		out.Terms = make(map[TermName]string, len(b.Terms))
		for k, v := range b.Terms {
			out.Terms[k] = v
		}
	}
	return out
}

// Encode returns the canonical JSON of the normalized body (encoding/json
// writes map keys sorted, so the bytes are deterministic). It refuses a
// body that fails Validate.
func (b Body) Encode() ([]byte, error) {
	n := b.Normalized()
	if err := n.Validate(); err != nil {
		return nil, fmt.Errorf("entitlements.Encode: %w", err)
	}
	out, err := json.Marshal(n)
	if err != nil {
		return nil, fmt.Errorf("entitlements.Encode: %w", err)
	}
	return out, nil
}

// Decode parses and validates a body. Unknown fields are ignored (the
// platformcontract v1 reader rule).
func Decode(raw []byte) (Body, error) {
	if len(raw) == 0 || len(raw) > platformcontract.MaxDocumentBody {
		return Body{}, fmt.Errorf("entitlements.Decode: body empty or too large: %w", ErrBody)
	}
	var b Body
	if err := json.Unmarshal(raw, &b); err != nil {
		return Body{}, fmt.Errorf("entitlements.Decode: %w: %w", err, ErrBody)
	}
	if err := b.Validate(); err != nil {
		return Body{}, fmt.Errorf("entitlements.Decode: %w", err)
	}
	return b, nil
}

func validPlanName(s string) bool {
	if s == "" || len(s) > maxPlanName || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// printable reports printable ASCII; spaces only when allowSpace.
func printable(s string, allowSpace bool) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' && allowSpace {
			continue
		}
		if c <= ' ' || c > '~' {
			return false
		}
	}
	return true
}

func sortedCapNames(m map[CapName]int64) []CapName {
	out := make([]CapName, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func sortedTermNames(m map[TermName]string) []TermName {
	out := make([]TermName, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
