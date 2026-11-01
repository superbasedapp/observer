// Command secengine is the RELEASE-SIDE verifier of an Opengrep release
// asset for the security.scan.opengrep driver (security pillar plan
// sections 8.1 and 8.5, Phase G lane G1; spike JSP-8).
//
// Opengrep publishes no checksum, only a keyless cosign .sig and .cert per
// binary, and the certificate lives ten minutes, so a node can never
// verify the signature itself: only Sigstore's Rekor log proves it was
// made inside that window. The asset is therefore verified ONCE, online,
// where the engine manifest is built (Observer's release pipeline, or the
// org mirror's import), and nodes check only the sha256 it records.
//
//	secengine verify -asset FILE -sig FILE -cert FILE -cosign PATH
//	                 [-version 1.30.1] [-os linux] [-arch amd64]
//	                 [-where release_pipeline] [-cosign-sha256 HEX]
//
// In order, it: hashes the asset; runs the standard-library offline
// pre-check (internal/secengine.Precheck: the ECDSA signature over the
// asset's digest, the Fulcio chain at signing time, the branch-form
// identity and the issuer), which refuses a tampered asset before anything
// goes online; checks the cosign binary against its pinned sha256 (the
// release pipeline's cosign v2.6.5, COSIGN_SHA256 in npm-release.yml); runs
// `cosign verify-blob` with the identity and issuer pinned, which consults
// Rekor; and prints the UNSIGNED content.Entry (method
// cosign_keyless_online) that `vendorsign` then signs into a
// security.engine manifest. It signs nothing itself.
//
// It lives under scripts/ because it runs only where a manifest is built:
// no shipped binary imports it. The cosign start is one injected function,
// so the tests run against a fake with JSP-8's recorded output.
package main
