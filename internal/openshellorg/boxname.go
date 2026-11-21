package openshellorg

import (
	"crypto/sha256"
	"encoding/base32"
	"regexp"
	"strings"
)

// box32 is lowercase RFC 4648 base32 without padding: letters and the digits
// 2 to 7 only, which OpenShell's sandbox names accept.
var box32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

var (
	boxNameRE      = regexp.MustCompile(`^obs[a-z2-7]{16}$`)
	providerNameRE = regexp.MustCompile(`^obsc[a-z2-7]{16}$`)
)

// BoxNameLen is the box name's length: OpenShell's maximum of 19.
const BoxNameLen = 19

// BoxName is a run's box name (G1-A16): "obs" followed by the first 16
// characters of the lowercase base32 SHA-256 of the org id and the run id,
// 19 characters in all, letters and digits only. The run id is the box's
// ledger key (the original run id, kept across a resume).
func BoxName(orgID, runID string) string {
	sum := sha256.Sum256([]byte(orgID + "\n" + runID))
	return "obs" + box32.EncodeToString(sum[:])[:16]
}

// IsBoxName reports whether name has the box-name grammar.
func IsBoxName(name string) bool { return boxNameRE.MatchString(name) }

// ProviderInstanceName is the repository provider instance the worker creates
// in a member's workspace for one clone (section 7.8): "obsc" plus 16 base32
// characters of the SHA-256 of the box name.
func ProviderInstanceName(boxName string) string {
	sum := sha256.Sum256([]byte("sbo-openshell-provider-v1\n" + boxName))
	return "obsc" + box32.EncodeToString(sum[:])[:16]
}

// IsProviderInstanceName reports whether name has the provider-instance
// grammar (the detective check deletes any such instance outside a clone
// window).
func IsProviderInstanceName(name string) bool { return providerNameRE.MatchString(name) }

// RequestID is the create's at-most-once request id, derived from the run id
// (section 3.2 step 5: the gateway replays a receipt for 24 h).
func RequestID(orgID, runID string) string {
	sum := sha256.Sum256([]byte("sbo-openshell-request-v1\n" + orgID + "\n" + runID))
	return "obsr-" + strings.ToLower(box32.EncodeToString(sum[:])[:26])
}
