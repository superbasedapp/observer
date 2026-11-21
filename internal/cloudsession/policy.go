package cloudsession

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// policy.go is the sandbox policy file (lane CA-C2, decision CA-D9): the
// signed guard policy and, for an org member, the org's signed budget
// document, committed into the repository by `observer cloud-session init
// --guard` and read by the committed gate hooks with no network call.
//
// Trust: `init` fetches the material from the destination (the org server
// through the enrolled node's pinned org client, or the owner's own node,
// which signs with its own cloud-session policy key) and verifies it against
// the pinned distribution key before writing anything. The committed gate
// command carries two values a reviewer sees in the diff: the sha256 pin of
// that key and the sha256 of the policy file. In the sandbox the gate refuses
// the file unless BOTH match and every signature verifies, so an agent that
// edits the file, swaps in an older genuinely signed copy from the git history,
// or forges a key gets a refusal (fail closed under enforcement), never a
// weaker policy. Changing the pins means editing the committed hook block,
// which the self-modification guard (guard.go) reports at the next flush.

// PolicyPath is the repository path of the sandbox policy file.
const PolicyPath = ".superbased/cloud-session/policy.json"

// PolicyFormat names the file layout; a file without it is not Observer's.
const PolicyFormat = "sbo-cloud-session-policy/1"

// PolicyOrigin says who signed the policy.
type PolicyOrigin string

// The policy origins.
const (
	// OriginOrg: the org server's policy key, pinned by the member's
	// enrolled node (TOFU at enrolment); the budget document rides with it.
	OriginOrg PolicyOrigin = "org"
	// OriginNode: the owner's node, with its own cloud-session policy key;
	// the guard policy is the node's user policy file. No budget.
	OriginNode PolicyOrigin = "node"
)

// SandboxBudget is the org's signed budget document for the member, with the
// org and subject its signature binds (orgcontract.VerifyBudgetPolicy).
type SandboxBudget struct {
	OrgID    string                      `json:"org_id"`
	Subject  string                      `json:"subject"`
	Document orgcontract.BudgetPolicyDoc `json:"document"`
}

// SandboxPolicy is the policy file's content.
type SandboxPolicy struct {
	// Format is PolicyFormat.
	Format string `json:"format"`
	// Origin is who signed Guard (and Budget).
	Origin PolicyOrigin `json:"origin"`
	// KeyPin is the sha256 hex of the signing key, for the reader; the
	// trusted pin is the one in the committed gate command.
	KeyPin string `json:"key_pin"`
	// FetchedAt is when init fetched the material (RFC3339, informational).
	FetchedAt string `json:"fetched_at"`
	// Guard is the signed guard policy envelope (the org's own bundle, or
	// one the node signed in the same envelope shape).
	Guard orgcontract.PolicyBundle `json:"guard"`
	// Budget is the org's signed budget document; nil when the org has none
	// for the member or the origin is the node.
	Budget *SandboxBudget `json:"budget,omitempty"`
}

// PolicyPin is what the committed gate command pins.
type PolicyPin struct {
	// KeyPin is the sha256 hex of the distribution key.
	KeyPin string
	// Digest is "sha256:<hex>" of the policy file bytes.
	Digest string
}

var (
	hex64       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	digestShape = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Validate checks the pin's shape.
func (p PolicyPin) Validate() error {
	if !hex64.MatchString(p.KeyPin) {
		return fmt.Errorf("cloudsession: key pin must be 64 lowercase hex characters")
	}
	if !digestShape.MatchString(p.Digest) {
		return fmt.Errorf("cloudsession: policy digest must be sha256:<64 hex>")
	}
	return nil
}

// PolicyDigest returns "sha256:<hex>" of raw.
func PolicyDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// EncodePolicy renders the policy file: two-space JSON with a trailing
// newline, so a diff reads like the rest of the repository.
func EncodePolicy(p SandboxPolicy) ([]byte, error) {
	p.Format = PolicyFormat
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("cloudsession: encode policy: %w", err)
	}
	return append(raw, '\n'), nil
}

// isPolicyFile reports whether content is an Observer policy file (the
// ownership test init and remove use).
func isPolicyFile(content string) bool {
	var head struct {
		Format string `json:"format"`
	}
	return json.Unmarshal([]byte(content), &head) == nil && head.Format == PolicyFormat
}

// PolicyFailure names why the gate refused the policy file. A closed set:
// the gate's reason, the coverage line and the tests read it.
type PolicyFailure string

// The policy failures, in check order.
const (
	PolicyMissing         PolicyFailure = "missing"
	PolicyDigestMismatch  PolicyFailure = "digest_mismatch"
	PolicyMalformed       PolicyFailure = "malformed"
	PolicySignature       PolicyFailure = "signature"
	PolicyKeyPin          PolicyFailure = "key_pin"
	PolicyBudgetSignature PolicyFailure = "budget_signature"
)

// PolicyError is a refused policy file.
type PolicyError struct {
	Failure PolicyFailure
	Detail  string
}

func (e *PolicyError) Error() string {
	return "cloudsession: policy file refused (" + string(e.Failure) + "): " + e.Detail
}

// Reason is the developer-facing sentence a gate shows when it blocks on a
// refused policy file.
func (e *PolicyError) Reason() string {
	return "Observer refused this cloud session's guard policy (" + string(e.Failure) + ": " + e.Detail +
		"); calls are blocked because guard enforcement is on. Restore " + PolicyPath +
		" as committed, or re-run `observer cloud-session init --guard` and commit the result."
}

// AsPolicyError returns err's PolicyError, if it is one.
func AsPolicyError(err error) (*PolicyError, bool) {
	var pe *PolicyError
	ok := errors.As(err, &pe)
	return pe, ok
}

// VerifiedPolicy is a policy file that passed every check.
type VerifiedPolicy struct {
	Policy SandboxPolicy
	// GuardEnvelope is the guard envelope as JSON, the bytes the guard's org
	// layer loader reads (it verifies them again, with the same pin).
	GuardEnvelope []byte
	// Budget is the verified budget body; nil when none rides along.
	Budget *orgcontract.BudgetPolicyBody
}

// policyCheckState carries one verification through the check table.
type policyCheckState struct {
	raw    []byte
	exists bool
	pin    PolicyPin
	out    VerifiedPolicy
	pub    []byte
}

// policyCheck is one row of the verification table.
type policyCheck struct {
	failure PolicyFailure
	check   func(s *policyCheckState) error
}

// policyChecks is THE verification table, walked top-down; the first
// failing row names the refusal.
var policyChecks = []policyCheck{
	{PolicyMissing, func(s *policyCheckState) error {
		if !s.exists {
			return errors.New(PolicyPath + " is not in the repository")
		}
		return nil
	}},
	{PolicyDigestMismatch, func(s *policyCheckState) error {
		if got := PolicyDigest(s.raw); got != s.pin.Digest {
			return fmt.Errorf("the file's sha256 is not the one the committed hooks pin")
		}
		return nil
	}},
	{PolicyMalformed, func(s *policyCheckState) error {
		dec := json.NewDecoder(bytes.NewReader(s.raw))
		if err := dec.Decode(&s.out.Policy); err != nil {
			return fmt.Errorf("not a policy file: %w", err)
		}
		p := s.out.Policy
		switch {
		case p.Format != PolicyFormat:
			return fmt.Errorf("format %q, want %q", p.Format, PolicyFormat)
		case p.Origin != OriginOrg && p.Origin != OriginNode:
			return fmt.Errorf("unknown origin %q", p.Origin)
		case p.Origin == OriginNode && p.Budget != nil:
			return errors.New("a node-signed policy carries no budget")
		}
		return nil
	}},
	{PolicySignature, func(s *policyCheckState) error {
		pub, err := orgcontract.VerifyPolicyBundle(s.out.Policy.Guard)
		if err != nil {
			return err
		}
		s.pub = pub
		return nil
	}},
	{PolicyKeyPin, func(s *policyCheckState) error {
		if got := orgcontract.PublicKeyPinHash(s.pub); got != s.pin.KeyPin {
			return fmt.Errorf("signed by key %s…, the committed hooks pin %s…", got[:12], s.pin.KeyPin[:12])
		}
		return nil
	}},
	{PolicyBudgetSignature, func(s *policyCheckState) error {
		b := s.out.Policy.Budget
		if b == nil {
			return nil
		}
		if strings.TrimSpace(b.OrgID) == "" || strings.TrimSpace(b.Subject) == "" {
			return errors.New("the budget document names no org or subject")
		}
		if err := orgcontract.VerifyBudgetPolicy(s.pub, b.OrgID, b.Subject, b.Document); err != nil {
			return err
		}
		body := b.Document.BudgetPolicyBody
		s.out.Budget = &body
		return nil
	}},
}

// VerifyPolicy checks a policy file against the committed pin. It is pure
// and offline: a byte comparison, two Ed25519 verifications and a hash.
func VerifyPolicy(raw []byte, exists bool, pin PolicyPin) (VerifiedPolicy, error) {
	if err := pin.Validate(); err != nil {
		return VerifiedPolicy{}, &PolicyError{Failure: PolicyMalformed, Detail: err.Error()}
	}
	s := &policyCheckState{raw: raw, exists: exists, pin: pin}
	for _, c := range policyChecks {
		if err := c.check(s); err != nil {
			return VerifiedPolicy{}, &PolicyError{Failure: c.failure, Detail: err.Error()}
		}
	}
	env, err := json.Marshal(s.out.Policy.Guard)
	if err != nil {
		return VerifiedPolicy{}, &PolicyError{Failure: PolicyMalformed, Detail: err.Error()}
	}
	s.out.GuardEnvelope = env
	return s.out, nil
}

// insertPolicyFile writes the policy file init fetched. A file at the path
// that is not Observer's is refused.
func insertPolicyFile(_ Agent, opts PlanOptions, before string, existed bool) (string, string, []string, error) {
	if opts.Guard == nil || len(opts.Guard.Policy) == 0 {
		return "", "", nil, errors.New("no policy was fetched")
	}
	if existed && !isPolicyFile(before) {
		return "", "", nil, errors.New("a file Observer did not write is already at this path; move it or remove it first")
	}
	return string(opts.Guard.Policy), "", nil, nil
}

// removePolicyFile deletes Observer's policy file and keeps anything else.
func removePolicyFile(_ Agent, before string) (string, bool, string, error) {
	if !isPolicyFile(before) {
		return before, false, "kept: not Observer's policy file", nil
	}
	return "", true, "", nil
}
