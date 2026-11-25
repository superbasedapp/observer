package tenantctx

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Kind names what a context token is for: whose rows it opens, which
// PostgreSQL setting carries it and the domain its MAC is computed under.
// The zero value is not a kind; every function given one refuses it.
type Kind uint8

const (
	// KindOrg is the org server's organization context (managed-SaaS plan 06
	// 5.3.3): the subject is an org id, the setting sbo.tenant, checked by
	// sbo_current_org() (org pgmigrations 0189).
	KindOrg Kind = 1
	// KindAccount is the cloud service's account context: the subject is an
	// account id (a lower-case canonical UUID), the setting sbci.account_id,
	// checked by sbci_current_account() (cloud migration 0067).
	KindAccount Kind = 2
)

// MaxSubjectBytes is the longest subject a token may carry.
const MaxSubjectBytes = 256

// kindSpec is one row of the kind table.
type kindSpec struct {
	kind Kind
	// name is the kind's name in errors and test output.
	name string
	// setting is the custom PostgreSQL setting the token travels in.
	setting string
	// domain prefixes the MAC input (see doc.go, "Kinds never cross"). The
	// org kind's is empty: its MAC input is the one org pgmigrations 0189
	// already computes, "<org>.<expiry>". Every other kind's domain ends in
	// a newline and contains no other control character, so no MAC input of
	// one kind is ever a MAC input of another.
	domain string
	// rules is the subject rule table, walked top down.
	rules []subjectRule
}

// kindSpecs returns the kind table. It is a function, not a variable, so the
// table is never mutable package state.
func kindSpecs() []kindSpec {
	return []kindSpec{
		{kind: KindOrg, name: "org", setting: "sbo.tenant", domain: "", rules: commonSubjectRules()},
		{
			kind: KindAccount, name: "account", setting: "sbci.account_id", domain: "sbci-account-v1\n",
			rules: append(commonSubjectRules(), subjectRule{name: "not a lower-case canonical UUID", bad: notCanonicalUUID}),
		},
	}
}

// Kinds returns every kind, in table order.
func Kinds() []Kind {
	specs := kindSpecs()
	out := make([]Kind, len(specs))
	for i, s := range specs {
		out[i] = s.kind
	}
	return out
}

// spec returns the kind's row of the kind table.
func (k Kind) spec() (kindSpec, error) {
	for _, s := range kindSpecs() {
		if s.kind == k {
			return s, nil
		}
	}
	return kindSpec{}, fmt.Errorf("%w: unknown kind %d", ErrInvalidContext, uint8(k))
}

// Valid reports whether k is a row of the kind table.
func (k Kind) Valid() bool {
	_, err := k.spec()
	return err == nil
}

// String returns the kind's name, or "kind(<n>)" for an unknown kind.
func (k Kind) String() string {
	if s, err := k.spec(); err == nil {
		return s.name
	}
	return fmt.Sprintf("kind(%d)", uint8(k))
}

// Setting returns the custom PostgreSQL setting carrying k's token, or "" for
// an unknown kind.
func (k Kind) Setting() string {
	s, _ := k.spec()
	return s.setting
}

// Domain returns the prefix of k's MAC input ("" for the org kind and for an
// unknown kind). It is public so the attack-test kit can build a token of one
// kind under another kind's domain; nothing else needs it.
func (k Kind) Domain() string {
	s, _ := k.spec()
	return s.domain
}

// SetLocalSQL returns the statement that sets k's token for the current
// transaction only: set_config's third argument is is_local, the SET LOCAL
// form. The token is the bind parameter $1, never statement text, so it does
// not reach pg_stat_activity or a statement log that omits parameters. ""
// for an unknown kind.
func (k Kind) SetLocalSQL() string {
	if !k.Valid() {
		return ""
	}
	return "SELECT set_config('" + k.Setting() + "', $1, true)"
}

// ClearLocalSQL returns the statement that empties k's setting for the
// current transaction, overriding any session-level value a pooled
// connection still carries. "" for an unknown kind.
func (k Kind) ClearLocalSQL() string {
	if !k.Valid() {
		return ""
	}
	return "SELECT set_config('" + k.Setting() + "', '', true)"
}

// macMessage is the MAC input of a token: the kind's domain, then
// "<subject>.<expiry>".
func (s kindSpec) macMessage(subject, expiry string) string {
	return s.domain + subject + "." + expiry
}

// subjectRule is one row of a subject rule table: the first row whose bad
// returns true names the refusal.
type subjectRule struct {
	name string
	bad  func(subject string) bool
}

// commonSubjectRules is the rule table every kind starts with. A token
// splits from the right, so dots are allowed; whitespace and control
// characters are not, which is the org database's token pattern
// ([^[:space:][:cntrl:]]+) and what keeps the kinds' MAC inputs apart.
func commonSubjectRules() []subjectRule {
	return []subjectRule{
		{name: "empty", bad: func(s string) bool { return s == "" }},
		{name: "too long", bad: func(s string) bool { return len(s) > MaxSubjectBytes }},
		{name: "not UTF-8", bad: func(s string) bool { return !utf8.ValidString(s) }},
		{name: "whitespace or control character", bad: func(s string) bool {
			return strings.IndexFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0
		}},
	}
}

// IsCanonicalUUID reports whether s is the 36-character, lower-case,
// hyphenated 8-4-4-4-12 hex form PostgreSQL prints a uuid in (uuid::text):
// the only form sbci_current_account() accepts. It is the one owner of this
// check; the cloud OIDC issuer uses it too.
func IsCanonicalUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}
	return true
}

// notCanonicalUUID is the subject-rule form of IsCanonicalUUID (a rule
// reports the bad case).
func notCanonicalUUID(s string) bool { return !IsCanonicalUUID(s) }

// CheckSubject returns nil when subject may be carried in a token of kind k,
// else an error matching ErrInvalidContext that names the refusing rule.
func (k Kind) CheckSubject(subject string) error {
	s, err := k.spec()
	if err != nil {
		return err
	}
	for _, r := range s.rules {
		if r.bad(subject) {
			return fmt.Errorf("%w: %s subject refused (%s)", ErrInvalidContext, s.name, r.name)
		}
	}
	return nil
}
