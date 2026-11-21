package sandboxnet

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// hosts.go is the gateway's optional host allow-list (sandbox plan v2
// sections 7 and 7.1, gap G23, ledger SBX-NET-1). When a Gateway carries a
// HostRules, a CONNECT or absolute-form target is checked against it BEFORE
// any resolution:
//
//   - the target must equal an entry, or end in ".<suffix>" for a
//     "*.<suffix>" entry (a subdomain only: "*.npmjs.org" never matches
//     "npmjs.org" itself, and never "evilnpmjs.org");
//   - names are compared as ASCII, lowercased; a name with a trailing dot,
//     a byte outside ASCII, an empty or over-long label, or a character
//     outside letters, digits and "-" is refused as host-name-invalid, never
//     guessed (no IDNA mapping is done, so a look-alike Unicode name cannot
//     be folded onto a listed one);
//   - a literal-IP target is refused (literal-ip) while a list is set: a run
//     that may reach only named hosts has no need for an address.
//
// A name that passes is then resolved once and its addresses still go
// through the IP policy (private ranges refused unless allow-listed), and
// the chosen address is dialled by IP, as for a list-less gateway. Entries
// are validated by ParseHostRules: lowercase ASCII names of at least two
// labels, no IP literal, no trailing dot, no punycode label ("xn--", whose
// Unicode form would have to be guessed), and a "*." wildcard only as the
// whole first label over a suffix of at least two labels.
//
// The rules are pure (no resolution, no I/O); imports_test.go pins the
// package.

// The host allow-list rule names (operator-visible in the 403 body and in
// the run log). Every gateway rule name is spelled with hyphens (the
// spelling of the IP policy and provider rules), never underscores.
const (
	// RuleHostNotListed refuses a name the run's host allow-list does not
	// list.
	RuleHostNotListed = "host-not-listed"
	// RuleHostNameInvalid refuses a target name that cannot be compared as
	// a plain ASCII host name (a trailing dot, non-ASCII, a bad label).
	RuleHostNameInvalid = "host-name-invalid"
)

// maxHostLen and maxLabelLen are the DNS limits on a name and a label.
const (
	maxHostLen  = 253
	maxLabelLen = 63
)

// HostRules is a parsed host allow-list. Build it with ParseHostRules; a
// nil *HostRules lists nothing and Check on it passes every target (the
// list-less gateway).
type HostRules struct {
	exact    map[string]bool
	suffixes []string
	entries  []string
	// key is the key a refusal by this list names ("" is the owner's
	// list, KeyEgressAllowHosts).
	key string
}

// WithKey returns a copy of h whose refusals name key instead of the
// owner's host-list key: a list that is not the owner's (the first-start
// install step's, KeyInstallHosts) says so in its refusals. Nil stays nil.
func (h *HostRules) WithKey(key string) *HostRules {
	if h == nil {
		return nil
	}
	c := *h
	c.key = key
	return &c
}

// Key is the key a refusal by this list names.
func (h *HostRules) Key() string {
	if h == nil || h.key == "" {
		return KeyEgressAllowHosts
	}
	return h.key
}

// ParseHostRules validates a host allow-list and returns it. An empty list
// is an error: a list that names nothing would refuse every target, which
// the caller should say as "no egress", not as an empty allow-list.
func ParseHostRules(entries []string) (*HostRules, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("sandboxnet: the host allow-list is empty")
	}
	h := &HostRules{exact: map[string]bool{}}
	seen := map[string]bool{}
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		if e != raw || e == "" {
			return nil, fmt.Errorf("sandboxnet: host allow-list entry %q has surrounding space or is empty", raw)
		}
		if e != strings.ToLower(e) {
			return nil, fmt.Errorf("sandboxnet: host allow-list entry %q is not lowercase", raw)
		}
		if _, err := netip.ParseAddr(strings.Trim(e, "[]")); err == nil {
			return nil, fmt.Errorf("sandboxnet: host allow-list entry %q is an IP address; list host names only", raw)
		}
		name, wildcard := strings.CutPrefix(e, "*.")
		if strings.Contains(name, "*") {
			return nil, fmt.Errorf("sandboxnet: host allow-list entry %q has a wildcard outside a leading \"*.\"", raw)
		}
		if rule := checkHostName(name); rule != "" {
			return nil, fmt.Errorf("sandboxnet: host allow-list entry %q is not a plain ASCII host name", raw)
		}
		for _, label := range strings.Split(name, ".") {
			if strings.HasPrefix(label, "xn--") {
				return nil, fmt.Errorf("sandboxnet: host allow-list entry %q has a punycode label; Observer does not map international names", raw)
			}
		}
		if strings.Count(name, ".") < 1 {
			return nil, fmt.Errorf("sandboxnet: host allow-list entry %q needs at least two labels", raw)
		}
		if seen[e] {
			continue
		}
		seen[e] = true
		h.entries = append(h.entries, e)
		if wildcard {
			h.suffixes = append(h.suffixes, "."+name)
		} else {
			h.exact[name] = true
		}
	}
	sort.Strings(h.entries)
	return h, nil
}

// Entries returns the list as parsed, sorted (for the consent line and the
// 403 body).
func (h *HostRules) Entries() []string {
	if h == nil {
		return nil
	}
	return append([]string(nil), h.entries...)
}

// Check applies the list to a target host (the host part of a CONNECT or
// absolute-form target, port removed). It returns the refusing rule, or ""
// when the target is listed. A nil list passes every target.
func (h *HostRules) Check(host string) string {
	if h == nil {
		return ""
	}
	if parseLiteral(strings.Trim(host, "[]")) != nil {
		return RuleLiteralIP
	}
	if rule := checkHostName(host); rule != "" {
		return rule
	}
	name := strings.ToLower(host)
	if h.exact[name] {
		return ""
	}
	for _, s := range h.suffixes {
		if len(name) > len(s) && strings.HasSuffix(name, s) {
			return ""
		}
	}
	return RuleHostNotListed
}

// checkHostName returns RuleHostNameInvalid unless name is a plain ASCII
// host name: 1 to 253 bytes, no trailing dot, labels of 1 to 63 letters,
// digits or "-", no label starting or ending with "-". Case is not checked
// (the caller lowercases).
func checkHostName(name string) string {
	if name == "" || len(name) > maxHostLen || strings.HasSuffix(name, ".") {
		return RuleHostNameInvalid
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > maxLabelLen || label[0] == '-' || label[len(label)-1] == '-' {
			return RuleHostNameInvalid
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
			default:
				return RuleHostNameInvalid
			}
		}
	}
	return ""
}

// DenyAllHosts is a host list that names nothing: every host target is
// refused (RuleHostNotListed) and every literal IP (RuleLiteralIP). It is
// the agent-run allow-list an organization pin left empty (lane LEFT-SBX),
// which must refuse everything rather than read as no list at all.
func DenyAllHosts() *HostRules { return &HostRules{exact: map[string]bool{}} }
