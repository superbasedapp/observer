//go:build !unix

package orgclient

import "io/fs"

// agentAccessKeyFileSupported is false where no O_NOFOLLOW-equivalent refusal
// and no current-user owner/ACL check exist (Windows): the agent-access key
// then stays keychain-only and OpenAgentAccessKeyStore fails closed with
// ErrAgentAccessKeychainUnavailable when the keychain cannot round-trip a
// record (the internal/cloudcred fileFallbackSecure()==false precedent).
const agentAccessKeyFileSupported = false

// agentAccessKeyOpenNoFollow is 0 where O_NOFOLLOW does not exist.
const agentAccessKeyOpenNoFollow = 0

// checkAgentAccessKeyOwner is a no-op here; it is never relied on because the
// file fallback is never selected on this build.
func checkAgentAccessKeyOwner(string, fs.FileInfo) error { return nil }
