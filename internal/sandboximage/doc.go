// Package sandboximage is the trust check for Observer's default sandbox
// image (sandbox plan v2 section 12.3, ledger SBX-IMG-1, lane SBX-P3B).
//
// The image is one artifact set of the signed content channel (kind
// sandbox.image, internal/update/content): a signed manifest covers a small
// descriptor file (sandbox-image.json: the repository, the image digest, the
// version, the minimum allowed version, the recipe's hash and the source
// commit) and the image's SBOM (SPDX JSON). The node installs and re-verifies
// both through internal/contentchan against the vendor key compiled into the
// agent; this package decides, from what that load returned, whether the
// image may be used and under which digest reference, and checks what the
// container engine reports for that reference before a run starts.
//
// Every refusal is the one verdict artifact_unverified with a reason, so a
// replayed older manifest, a below-minimum artifact, a revoked artifact and a
// tampered image are each refused before use (acceptance case A12).
//
// Lane SBX-P4 adds the microVM guest image set (vmdescriptor.go,
// vmmanifest.go, vmresolve.go, vmsbom.go): ONE sandbox.rootfs manifest over
// a small descriptor (version, minimum, verity root hash, recipe hash,
// source commit, the pinned kernel package, the guest userns flag), its
// SBOM, the kernel, the initramfs, the read-only rootfs and its verity
// tree, and ONE sandbox.guest_binary manifest (one guest observer per
// architecture, its version the host agent's). ResolveVMSet refuses a
// replayed, below-minimum, revoked (by digest or by the set's verity root
// hash), tampered, past-age or wrong-version set before boot; an expired
// one within the age floor boots as last-known-good, reported. The recipe
// is deploy/sandbox-vm-image; the signing verbs are vendorsign
// sandboxrootfs and sandboxguest.
//
// The package is pure: no file, socket or process I/O (imports_test-pinned).
// The recipe, build script and SBOM generator input live in
// deploy/sandbox-image; the signing step is scripts/vendorsign's
// `sandboximage` verb, run with the real key only at the operator's release
// step. Nothing is published yet.
package sandboximage
