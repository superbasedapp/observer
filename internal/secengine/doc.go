// Package secengine decides whether an Opengrep binary on this machine may
// run for the security.scan.opengrep driver (security pillar plan sections
// 8.1 and 8.5, threat T3, adversarial case X9; spike JSP-8). It is the
// engine half of Phase G lane G1; the rule pack is internal/secrulepack.
//
// What it owns:
//
//   - the compiled pins: Opengrep v1.30.1 on linux amd64 by the sha256 JSP-8
//     recorded, with the signing identity in its branch form
//     (rolling-release.yml@refs/heads/release-v<version>) and the GitHub
//     Actions issuer. Every other platform is "pin owed" and refused as
//     driver_unverified until a pin or a verified engine manifest fills it;
//   - the engine manifest: a verified security.engine content manifest
//     (internal/update/content) whose entries carry the sha256 Observer's
//     release pipeline or the org mirror recorded after ONE full online
//     keyless verification. It supersedes the compiled pins for the
//     platforms it lists and can revoke a digest;
//   - Decide, the ordered table that turns the binary's digest, the
//     tenancy, the manifest and the companion tree's state into run,
//     refuse or run labelled: an unverified engine is refused on a managed
//     node and labelled on an individual one (section 8.1);
//   - the companion tree record (X9): after the first verified run the
//     digests of the files Opengrep's self-extracting bundle unpacked into
//     its own cache, re-checked before every later run; a changed, missing
//     or added file makes the engine driver_unverified;
//   - Precheck, the offline pre-check of a keyless cosign signature with the
//     standard library: the ECDSA signature over the artifact's digest, the
//     Fulcio chain at signing time, the identity and the issuer. It cannot
//     prove the signature was made inside the certificate's 10 minutes
//     (only Rekor can, JSP-8), so it never replaces the online
//     verification of scripts/secengine; it refuses a tampered artifact
//     before anything goes online.
//
// The package is PURE (CLAUDE.md "Module Boundaries" rule 1): every input
// is bytes or facts its caller read; it opens no file, starts no process
// and makes no network call (imports_test.go). It belongs to
// security.scan.opengrep.
package secengine
