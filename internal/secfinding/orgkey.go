package secfinding

import (
	"regexp"
	"strconv"
	"strings"
)

// orgkey.go is the node's half of the org dedupe key's lifecycle (security
// plan 4.5.1, lane LEFT-SHARED), pure: a secret finding's org_key is
// OrgSecretKey under the org's dedupe key, computed while the secret value
// is in hand (the value is never kept, so the digest cannot be computed
// later), and stored node-locally TAGGED with the key's version
// ("v<version>:<hex>"). The push composition then ships the digest only
// while the node still holds that very version (WireOrgKey), so a rotated
// or withdrawn key never ships a digest made under the old one.

// orgKeyHex is OrgSecretKey's digest shape.
var orgKeyHex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// StoredOrgKey tags an org_key digest with the dedupe key's version for the
// node-local finding row; "" for an empty digest or a non-positive version.
func StoredOrgKey(version int64, digest string) string {
	if version <= 0 || !orgKeyHex.MatchString(digest) {
		return ""
	}
	return "v" + strconv.FormatInt(version, 10) + ":" + digest
}

// WireOrgKey is the org_key a push may carry for a stored value: the digest
// when it was made under heldVersion (the dedupe key version the node holds
// now), else "" (no key held, another version, or a malformed value).
func WireOrgKey(stored string, heldVersion int64) string {
	if heldVersion <= 0 || !strings.HasPrefix(stored, "v") {
		return ""
	}
	ver, digest, ok := strings.Cut(stored[1:], ":")
	if !ok || ver != strconv.FormatInt(heldVersion, 10) || !orgKeyHex.MatchString(digest) {
		return ""
	}
	return digest
}
