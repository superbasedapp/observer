package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/update"
)

// update_vendorsig.go is §3.7 step 3 — the SECOND signature.
//
// Two independent signatures protect an apply: the ORG's Ed25519 manifest
// signature (TOFU-pinned, verified in internal/update's rule table when the
// manifest is fetched) and the VENDOR's signature over the archive bytes,
// verified here. The second exists so that a compromised org server alone
// cannot serve a binary we did not build: the attacker would control the
// sha256 inside the signed manifest AND the bytes at the mirror, and only the
// vendor signature stands between that and a substituted daemon.
//
// Verification is OFFLINE. The public key is compiled into the agent
// (internal/update/vendorkey.go) and there is no Rekor lookup, because a
// transparency-log query would be a SECOND OUTBOUND HOST on a node whose
// entire update story is "the org server you are already enrolled with,
// and nothing else" (ruling R8).
//
// THE PRE-W6 REALITY, STATED RATHER THAN PAPERED OVER. The release pipeline
// does not produce these signatures yet — W6 adds the producer, and until it
// does, update.VendorPublicKeys() returns an EMPTY set (W1 deliberately
// excluded the all-zero placeholder, because Go's ed25519.Verify ACCEPTS an
// all-zero signature under an all-zero key). An empty key set therefore means
// "this build cannot verify", and the honest answer to that is to REFUSE the
// apply — not to skip the check. That keeps the two-signature claim either
// true or loudly unavailable, never quietly halved.

// maxVendorSigBytes caps the signature blob carried in the manifest. An
// Ed25519 signature is 64 bytes, so the cap is orders of magnitude of slack;
// it exists so a manifest cannot make this node allocate on its say-so.
const maxVendorSigBytes = 64 * 1024

// verifyVendorSignature checks the artifact's upstream_sig over the archive
// bytes against every accepted vendor key.
//
// It returns errNoVendorKeyLocal when this build has no key at all, which the
// apply maps to blocked{unsigned_artifact} rather than to a failure: a node
// that CANNOT verify is not a node that FAILED to verify, and an admin
// staring at the fleet board needs to be able to tell those apart.
func verifyVendorSignature(archivePath string, a update.Artifact) error {
	sig := strings.TrimSpace(a.UpstreamSig)
	if sig == "" {
		return fmt.Errorf("artifact %s carries no vendor signature", a.Filename)
	}
	// ENFORCE the declared scheme. update.KnownSigType now admits exactly
	// the one scheme this function performs (raw Ed25519), so a manifest
	// naming another does not even validate — but an apply can run from a
	// manifest cached in update_state, and a rule that guards only one of two
	// entry points is not a rule. Refusing a label the agent cannot honour
	// keeps the manifest's claim and the check actually made the same
	// statement.
	if t := strings.TrimSpace(a.UpstreamSigType); t != "" && t != update.SigTypeEd25519 {
		return fmt.Errorf("%w: artifact %s declares upstream_sig_type %q",
			errUnsupportedSigTypeLocal, a.Filename, t)
	}
	if len(sig) > maxVendorSigBytes {
		return fmt.Errorf("artifact %s carries an implausibly large vendor signature (%d bytes)", a.Filename, len(sig))
	}
	keys := update.VendorPublicKeys()
	if len(keys) == 0 {
		return errNoVendorKeyLocal
	}
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return fmt.Errorf("artifact %s: vendor signature is not base64: %w", a.Filename, err)
	}
	body, err := os.ReadFile(archivePath) //nolint:gosec // a path this process composed under state_dir
	if err != nil {
		return fmt.Errorf("reading %s for signature verification: %w", archivePath, err)
	}
	// Every accepted key is tried, not just the newest: §2.2's rotation
	// overlap window means an agent accepts the previous key for one
	// release, so a key rotation cannot strand a fleet mid-flight.
	for _, k := range keys {
		if ed25519.Verify(k, body, raw) {
			return nil
		}
	}
	return fmt.Errorf("artifact %s: the vendor signature does not verify against any key this build accepts", a.Filename)
}
