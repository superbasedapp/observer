package accessgrant

import (
	"fmt"
	"regexp"
	"strings"
)

// The revoke reason an extension leaves on the grant it replaced. The org
// stores an extension as a revoke of the old grant; a developer reads that as
// the grant being REPLACED, not taken away (round-3 demo wording). The node's
// surfaces (the `observer requests` CLI here, web/src/lib/grantRevokeReason.ts
// on the dashboard) map the stored reason through the same table.

// replacedByReason matches the stored reason exactly: "superseded by G-<n>"
// as the org server writes it today, or "replaced by G-<n>" from a server
// that words it so.
var replacedByReason = regexp.MustCompile(`^(?:superseded|replaced) by (G-\d+)$`)

// ReplacedReason is the reason text an extension records on the grant it
// replaces ("replaced by G-<n>").
func ReplacedReason(newGrantID int64) string {
	return fmt.Sprintf("replaced by G-%d", newGrantID)
}

// ReplacedBy reports the grant that replaced this one ("G-6") when reason is
// an extension's reason, and ok=false for any other reason.
func ReplacedBy(reason string) (grant string, ok bool) {
	m := replacedByReason.FindStringSubmatch(strings.TrimSpace(reason))
	if m == nil {
		return "", false
	}
	return m[1], true
}

// RevokeReasonWords is a stored revoke reason as the developer reads it: an
// extension's reason reads "replaced by G-<n>"; any other reason is returned
// as the admin wrote it.
func RevokeReasonWords(reason string) string {
	if by, ok := ReplacedBy(reason); ok {
		return "replaced by " + by
	}
	return reason
}
