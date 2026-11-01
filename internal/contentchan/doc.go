// Package contentchan is the file side of the signed content channel
// (joint roadmap F0-6; ledger SHR-7): it installs a verified content
// manifest and its artifacts into a per-kind directory, keeps the
// last-known-good state there, and re-verifies on every load.
//
// The decisions (signatures, rollback, epochs, expiry, revocation, the
// last-known-good transition) are the pure content core internal/update/content; this
// package only reads and writes files around them, so the security pillar's
// feeds and the sandbox plan's artifact sets share one installer. It does no
// network I/O: fetching is the caller's (the public feed client, the org
// mirror client internal/orgclient/seccontent.go, or a directory an
// operator copied in). InstallFiles takes artifacts already on disk, so a
// kind of hundreds of megabytes (the OSV exports) is never held in memory.
//
// Layout, under the caller's root (one directory per kind, 0700):
//
//	<root>/<kind>/manifest.json   the accepted envelope, exactly as received
//	<root>/<kind>/state.json      content.State (last-known-good, last failure)
//	<root>/<kind>/<entry name>    each artifact, written only after its digest matched
package contentchan
