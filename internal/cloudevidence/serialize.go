package cloudevidence

import (
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

// Serialize is THE ONE function that produces both the literal preview bytes
// and the upload bytes for an envelope — there is no second "friendly"
// serialization (telemetry plan §5.2). It computes the two-digest protocol:
//
//  1. the evidence-content digest over the canonical preimage (both digest
//     fields absent), stamped into the returned bytes;
//  2. the upload digest over those final bytes.
//
// It works on a copy of e (so the caller's envelope is never mutated) and
// validates before serializing. The returned bytes are exactly what a node
// would preview and upload; the returned Digests are what a consent receipt
// binds and what a rebuild-and-compare check (consent/rebuild coherence)
// compares against.
func Serialize(e *cloudcontract.Envelope) ([]byte, cloudcontract.Digests, error) {
	if e == nil {
		return nil, cloudcontract.Digests{}, fmt.Errorf("cloudevidence.Serialize: nil envelope")
	}
	env := *e // copy; never mutate the caller's envelope

	if err := env.Validate(); err != nil {
		return nil, cloudcontract.Digests{}, fmt.Errorf("cloudevidence.Serialize: %w", err)
	}

	evidenceDigest, err := cloudcontract.EvidenceContentDigest(env)
	if err != nil {
		return nil, cloudcontract.Digests{}, fmt.Errorf("cloudevidence.Serialize: %w", err)
	}
	env.EvidenceContentDigest = evidenceDigest

	final, err := cloudcontract.UploadBytes(env)
	if err != nil {
		return nil, cloudcontract.Digests{}, fmt.Errorf("cloudevidence.Serialize: %w", err)
	}
	uploadDigest := cloudcontract.UploadDigest(final)

	return final, cloudcontract.Digests{EvidenceContent: evidenceDigest, Upload: uploadDigest}, nil
}
