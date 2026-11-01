package orgcontract

import (
	"fmt"
	"strings"
	"unicode"
)

// MaxOrgNameBytes caps the organization's display name, in bytes. The name is
// shown verbatim on every enrolled node (`observer org status`, the consent
// disclosures), so it stays short.
const MaxOrgNameBytes = 100

// OrgNameProblem is the ONE rule for a usable organization display name
// (T-862), shared by the org server's rename (orgdb.ValidateOrgName) and the
// node that adopts a renamed org from PushResponse.OrgName, so the two sides
// can never disagree about what a name may be. It reports why name, already
// trimmed of surrounding space, is not usable, or "" when it is.
func OrgNameProblem(name string) string {
	switch {
	case name == "":
		return "it is empty"
	case len(name) > MaxOrgNameBytes:
		return fmt.Sprintf("it is longer than %d bytes", MaxOrgNameBytes)
	case strings.TrimSpace(name) != name:
		return "it has surrounding space"
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "it contains a control character"
		}
	}
	return ""
}
