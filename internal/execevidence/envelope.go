package execevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// Version is the envelope's shape version; it is part of every digest, so a
// shape change can never collide with an older digest.
const Version = 1

// digestDomain separates this digest from every other hash in the product.
const digestDomain = "sbo-exec-evidence-v1"

// ProducerKind says what kind of execution an envelope describes.
type ProducerKind string

// The closed ProducerKind vocabulary.
const (
	// KindTerminalRun is a dashboard or CLI terminal launch (the sandbox
	// module's first consumer).
	KindTerminalRun ProducerKind = "terminal_run"
	// KindIsolatedRun is a one-shot isolated program run (the isolation
	// engine, roadmap F0-11; the security module's scanner drivers).
	KindIsolatedRun ProducerKind = "isolated_run"
)

// Producer identifies what produced the execution.
type Producer struct {
	Kind ProducerKind
	// Component is the node catalog id that owns the run.
	Component string
	// ComponentVersion is the Observer build that recorded it.
	ComponentVersion string
}

// Artifact is the verified identity of the program that enforced or ran
// the execution (the isolation backend's binary, a scanner engine): its
// name, the version read and how, and its digest when one was taken.
type Artifact struct {
	Name    string
	Version string
	// VersionAuthenticated: the version was read from an authenticated
	// identity, not a bare --version.
	VersionAuthenticated bool
	// Digest is the lowercase hex sha256 of the binary, when taken.
	Digest string
}

// Isolation is the sandbox module's half: the isolation and capture facts
// of one run. Every field is a closed enum; the zero value of a field means
// "not recorded", never a default.
type Isolation struct {
	// Class is the effective isolation class actually built.
	Class vocab.IsoClass
	// Stack is the backend ids of the layers, outermost first.
	Stack []string
	// EgressTier is the tier the network-owning layer enforced.
	EgressTier vocab.Tier
	// CaptureLevel is the COMPUTED level (sandboxselect), and CaptureRule
	// the rule id that decided it ("C1" to "C8").
	CaptureLevel vocab.CaptureLevel
	CaptureRule  string
	// GatewayGuarded: full only through the provider-host block.
	GatewayGuarded     bool
	CaptureOrigin      vocab.CaptureOrigin
	CaptureDegraded    bool
	NativeSandboxState vocab.NativeSandboxState
	Verification       vocab.Verification
	KeyCustody         vocab.KeyCustody
}

// Envelope is one execution's evidence.
type Envelope struct {
	RunID     string
	Producer  Producer
	Artifact  Artifact
	Isolation Isolation
	// OrgRowRef names the org-side row this envelope backs, when the run
	// shipped on the org wire ("" otherwise).
	OrgRowRef string
}

// Validate checks every closed field. An empty field is allowed (not
// recorded); an unknown value is not.
func (e Envelope) Validate() error {
	if strings.TrimSpace(e.RunID) == "" {
		return fmt.Errorf("execevidence: run id is empty")
	}
	switch e.Producer.Kind {
	case KindTerminalRun, KindIsolatedRun:
	default:
		return fmt.Errorf("execevidence: producer kind %q", e.Producer.Kind)
	}
	if e.Producer.Component == "" {
		return fmt.Errorf("execevidence: producer component is empty")
	}
	iso := e.Isolation
	checks := []struct {
		name string
		ok   bool
	}{
		{"class", iso.Class == "" || iso.Class.Valid()},
		{"egress tier", iso.EgressTier == "" || iso.EgressTier.Valid()},
		{"capture level", iso.CaptureLevel == "" || iso.CaptureLevel.Valid()},
		{"capture origin", iso.CaptureOrigin == "" || validOrigin(iso.CaptureOrigin)},
		{"native sandbox state", iso.NativeSandboxState == "" || validNative(iso.NativeSandboxState)},
		{"verification", iso.Verification == "" || validVerification(iso.Verification)},
		{"key custody", iso.KeyCustody == "" || validCustody(iso.KeyCustody)},
		{"artifact digest", e.Artifact.Digest == "" || isHex64(e.Artifact.Digest)},
	}
	for _, c := range checks {
		if !c.ok {
			return fmt.Errorf("execevidence: %s is not in its vocabulary", c.name)
		}
	}
	for _, id := range iso.Stack {
		if id == "" || strings.ContainsAny(id, "\n\x00|") {
			return fmt.Errorf("execevidence: stack id %q", id)
		}
	}
	return nil
}

// Digest returns the evidence digest: hex sha256 over the domain, the shape
// version and every field in a fixed order, each length-prefixed so no two
// envelopes share an encoding. It does not include OrgRowRef (the same
// evidence backs the row it is attached to).
func (e Envelope) Digest() string {
	iso := e.Isolation
	fields := []string{
		digestDomain, strconv.Itoa(Version),
		e.RunID,
		string(e.Producer.Kind), e.Producer.Component, e.Producer.ComponentVersion,
		e.Artifact.Name, e.Artifact.Version, strconv.FormatBool(e.Artifact.VersionAuthenticated), e.Artifact.Digest,
		string(iso.Class), strings.Join(iso.Stack, ","), string(iso.EgressTier),
		string(iso.CaptureLevel), iso.CaptureRule, strconv.FormatBool(iso.GatewayGuarded),
		string(iso.CaptureOrigin), strconv.FormatBool(iso.CaptureDegraded),
		string(iso.NativeSandboxState), string(iso.Verification), string(iso.KeyCustody),
	}
	h := sha256.New()
	for _, f := range fields {
		_, _ = h.Write([]byte(strconv.Itoa(len(f))))
		_, _ = h.Write([]byte{':'})
		_, _ = h.Write([]byte(f))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Seal validates the envelope and returns its digest.
func (e Envelope) Seal() (string, error) {
	if err := e.Validate(); err != nil {
		return "", err
	}
	return e.Digest(), nil
}

// Verify reports whether digest is this envelope's digest.
func (e Envelope) Verify(digest string) bool {
	return e.Validate() == nil && digest == e.Digest()
}

func validOrigin(o vocab.CaptureOrigin) bool {
	return o == vocab.OriginLocal || o == vocab.OriginSandboxed || o == vocab.OriginRemoteSandbox
}

func validNative(n vocab.NativeSandboxState) bool {
	switch n {
	case vocab.NativeOn, vocab.NativeWeak, vocab.NativeDisabledByObserver, vocab.NativeDisabledByUser,
		vocab.NativeOrgForced, vocab.NativeUnavailableFellBack, vocab.NativeNotApplicable:
		return true
	}
	return false
}

func validVerification(v vocab.Verification) bool {
	switch v {
	case vocab.VerifiedLive, vocab.VerifiedDoc, vocab.VerifiedFixture, vocab.VerifiedInferred:
		return true
	}
	return false
}

func validCustody(k vocab.KeyCustody) bool {
	switch k {
	case vocab.CustodyHomeRelay, vocab.CustodyProviderInjected, vocab.CustodyInBoxAPIKey,
		vocab.CustodyInBoxOAuthSeed, vocab.CustodyHostBound:
		return true
	}
	return false
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
