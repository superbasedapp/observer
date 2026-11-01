// Package content is the signed content channel (joint roadmap F0-6; security
// pillar plan section 8.5; sandbox plan section 12.3): ONE protocol for
// everything Observer publishes that is not the agent binary itself. The
// security pillar's feeds (the malicious-packages list, the popular-names
// lists, OSV exports, the agent CVE table, rule packs) and engine manifests
// (Opengrep, osv-scanner), and the sandbox plan's artifact sets (rootfs,
// images, the guest binary, bundled native files) are each a typed content
// KIND of this channel, not a mechanism of their own.
//
// The properties are the channel's, not a consumer's:
//
//   - signed metadata: one manifest per kind, signed with the compiled-in
//     vendor key (vendorkey.go) under its own domain tag, listing each
//     artifact's name, size, SHA-256, upstream check and source;
//   - the org mirror adds its own countersignature (Countersign), so
//     a managed node that requires it gets both and a compromised org server
//     alone cannot substitute an artifact;
//   - monotonic versions: a manifest below the accepted version is refused
//     (rollback), and the same version with other bytes is refused (a fork);
//   - separate epochs per kind: the data epoch may not go backwards either,
//     and a database update never swaps an engine because they are kinds;
//   - required expiry, bounded per kind, and an age floor: past expiry the
//     accepted data is stale, past the floor it is unknown (PR14), so a
//     frozen feed is visible, never silent;
//   - revocation: a manifest names the artifacts it withdraws;
//   - last-known-good: a failed update keeps the last verified state and
//     records why (Apply).
//
// It is pure: bytes, keys and a clock in, a decision out. Fetching
// (internal/secfeed/online, the org client) and the files on disk
// (internal/contentchan) are other packages. It lives beside
// internal/update and not in it because internal/update belongs to the
// org.update component (an optional module), while this channel is shared
// core: so the vendor key set is passed in by the caller, never read here.
package content
