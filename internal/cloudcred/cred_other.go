//go:build !unix

package cloudcred

import (
	"io/fs"
	"os"
)

// openNoFollow is 0 on platforms without O_NOFOLLOW (Windows). The Lstat
// symlink refusal in read/write still applies on every platform, checked on the
// path before the open and re-validated on the open handle afterwards. That
// Lstat-only check is exactly the race fileFallbackSecure refuses to trust on
// this platform: nothing here closes the window between the Lstat and the
// open, so a reparse point swapped in mid-race is not refused the way
// O_NOFOLLOW refuses a symlink on unix.
const openNoFollow = 0

// checkOwner is a documented no-op where POSIX ownership does not apply. On
// Windows the required verification is an ACL check confirming the file's
// DACL grants access only to the current user SID (via the security
// descriptor, e.g. golang.org/x/sys/windows), plus a reparse-point refusal.
// Neither is implemented in this arc — the stdlib+keyring purity pin excludes
// x/sys/windows — so this function must NEVER be relied on to gate a
// plaintext-secret write or read on this platform. It stays a no-op (rather
// than being deleted) only because fileStore's shared code path calls it
// unconditionally; fileFallbackSecure()==false on this build means Open()
// never selects fileStore here in the first place — see cred.go's
// selectFallbackStore and failClosedStore. Flip this to a real DACL check
// only alongside flipping fileFallbackSecure to true.
func checkOwner(string, fs.FileInfo) error { return nil }

// checkOwnerFile is the open-handle counterpart of checkOwner; the same
// "never actually trusted on this platform" note applies.
func checkOwnerFile(string, *os.File, fs.FileInfo) error { return nil }

// fileFallbackSecure reports whether this platform build's file fallback
// (fileStore) has verified owner+symlink/reparse protections sufficient to
// trust with the WorkOS refresh material, API bearer token, and Ed25519
// device signing key when the OS keychain is unavailable. It does not:
// openNoFollow is 0 (no O_NOFOLLOW-equivalent reparse-point refusal) and
// checkOwner/checkOwnerFile are no-ops (no current-user SID/DACL
// verification), so nothing here closes the Lstat-to-open race or confirms
// the file's ACL is current-user-only. Open() therefore fails closed
// (selectFallbackStore returns failClosedStore, cred.go) instead of silently
// writing cloud credentials to this unverified file store — see FF2,
// docs/audits/cloud-intelligence-shipped-code-sol-review-2026-08-31.md.
// Flip this to true only alongside a real current-user SID/DACL check and a
// reparse-point refusal (e.g. via golang.org/x/sys/windows), which would
// also require amending the stdlib+keyring purity pin this arc holds.
func fileFallbackSecure() bool { return false }
