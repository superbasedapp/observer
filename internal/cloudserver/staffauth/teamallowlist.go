package staffauth

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// teamallowlist.go is the pure half of the team create allow-list (managed-
// SaaS plan 07 wave 17; cloud 0130; docs/security.md TEAMGATE-1): the two
// entry kinds and the one validator both writers (the staff console route
// and the operator's `observer-cloud staff team-allowlist add`) call, so an
// entry reaches the database in one canonical spelling. The database CHECK
// holds the same shapes.

// AllowlistKind is what an allow-list entry names. The vocabulary is closed
// and mirrors the team_create_allowlist.kind CHECK.
type AllowlistKind string

// The two entry kinds.
const (
	// AllowlistAccount names one account by its id.
	AllowlistAccount AllowlistKind = "account"
	// AllowlistEmailDomain names a domain: an account whose VERIFIED email
	// is at exactly that domain may create a team org. No subdomain match.
	AllowlistEmailDomain AllowlistKind = "email_domain"
)

// KnownAllowlistKinds lists every kind.
var KnownAllowlistKinds = []AllowlistKind{AllowlistAccount, AllowlistEmailDomain}

// ErrAllowlistEntry is the sentinel every refused entry wraps.
var ErrAllowlistEntry = errors.New("staffauth: invalid team allow-list entry")

var (
	allowlistUUID   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	allowlistDomain = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

// AllowlistEntry is a validated entry: what the store writes.
type AllowlistEntry struct {
	Kind  AllowlistKind
	Value string
}

// ValidateAllowlistEntry checks kind and value and returns the entry in its
// canonical form: an account id lower-cased (braces and the urn prefix are
// not accepted), a domain lower-cased with any trailing dot and a leading
// "@" removed. A domain must have at least two labels; an address
// (anything with a local part) is refused, so no email is ever stored.
func ValidateAllowlistEntry(kind, value string) (AllowlistEntry, error) {
	v := strings.ToLower(strings.TrimSpace(value))
	switch AllowlistKind(kind) {
	case AllowlistAccount:
		if !allowlistUUID.MatchString(v) {
			return AllowlistEntry{}, fmt.Errorf("%w: an account entry is an account id (a uuid)", ErrAllowlistEntry)
		}
		return AllowlistEntry{Kind: AllowlistAccount, Value: v}, nil
	case AllowlistEmailDomain:
		v = strings.TrimSuffix(strings.TrimPrefix(v, "@"), ".")
		if strings.Contains(v, "@") {
			return AllowlistEntry{}, fmt.Errorf("%w: a domain entry is a domain (example.com), not an address", ErrAllowlistEntry)
		}
		if len(v) < 3 || len(v) > 253 || !allowlistDomain.MatchString(v) {
			return AllowlistEntry{}, fmt.Errorf("%w: %q is not a domain name like example.com", ErrAllowlistEntry, v)
		}
		return AllowlistEntry{Kind: AllowlistEmailDomain, Value: v}, nil
	default:
		return AllowlistEntry{}, fmt.Errorf("%w: kind must be %q or %q", ErrAllowlistEntry, AllowlistAccount, AllowlistEmailDomain)
	}
}
