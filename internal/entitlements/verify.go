package entitlements

import (
	"errors"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// Binding is what the verifying host expects a document to be for.
type Binding struct {
	// Org is the org id the document must be signed for and name.
	Org string
	// Kind is the org's kind; a document of another kind is refused.
	Kind Kind
}

// Document is a verified entitlements document: the envelope's version and
// key id plus the decoded, validated body.
type Document struct {
	// Version is the signed, monotonic document version.
	Version int64
	// KeyID names the key that signed it.
	KeyID string
	// Body is the decoded body.
	Body Body
}

// Verification errors (each wraps the platformcontract error when that
// layer refused).
var (
	// ErrBinding means the body names another org or another kind than the
	// host expects.
	ErrBinding = errors.New("entitlements: document is bound to another org or kind")
)

// Verify is what a host calls on a pushed (or fetched) document: the
// envelope signature under one of keys and its version strictly above
// lastVersion (platformcontract.VerifyEntitlements), then the body decoded,
// structurally valid and bound to b. Keys are injected: production passes
// CompiledKeys(), tests a test key.
func Verify(raw platformcontract.EntitlementDocument, b Binding, keys platformcontract.KeySet, lastVersion int64) (Document, error) {
	if err := platformcontract.VerifyEntitlements(raw, b.Org, keys, lastVersion); err != nil {
		return Document{}, fmt.Errorf("entitlements.Verify: %w", err)
	}
	body, err := Decode(raw.Body)
	if err != nil {
		return Document{}, fmt.Errorf("entitlements.Verify: %w", err)
	}
	if body.Org != b.Org {
		return Document{}, fmt.Errorf("entitlements.Verify: body names org %q, want %q: %w", body.Org, b.Org, ErrBinding)
	}
	if body.Kind != b.Kind {
		return Document{}, fmt.Errorf("entitlements.Verify: body kind %s, want %s: %w", body.Kind, b.Kind, ErrBinding)
	}
	return Document{Version: raw.Version, KeyID: raw.KeyID, Body: body}, nil
}

// Reverify re-checks the document a host already holds (at boot, or after a
// key rollover): the same checks as Verify, with the version rule relaxed to
// "the stored version itself", so a host can re-read what it accepted. A
// push still goes through Verify with the version in force.
func Reverify(raw platformcontract.EntitlementDocument, b Binding, keys platformcontract.KeySet) (Document, error) {
	if raw.Version <= 0 {
		return Document{}, fmt.Errorf("entitlements.Reverify: %w", platformcontract.ErrDocumentVersion)
	}
	d, err := Verify(raw, b, keys, raw.Version-1)
	if err != nil {
		return Document{}, fmt.Errorf("entitlements.Reverify: %w", err)
	}
	return d, nil
}
