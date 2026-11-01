//go:build !unix && !windows

package hook

import "runtime"

// claudeOSPolicy: Claude Code has no MDM or registry source Observer reads
// on this OS; only the file channel applies.
func claudeOSPolicy() (mdm, hkcu ClaudePolicySource, goos string) {
	return ClaudePolicySource{}, ClaudePolicySource{}, runtime.GOOS
}
