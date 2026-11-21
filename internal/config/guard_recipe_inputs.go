package config

import (
	"net"
	"regexp"
	"strings"
)

// A [guard.network] host pattern is judged on the host the network rules
// actually compare (internal/policy rules_network.go hostMatchesPattern),
// which tolerates surrounding space, a scheme and a path, a :port, a
// bracketed IPv6 address and a trailing dot. Validation therefore takes the
// same host out of the value first (guardHostOf) and refuses only what no
// rule could ever honour (sweep finding CFG-5). Anything stricter would turn
// a value the matcher handles into a config.Load failure, which stops the
// daemon on upgrade.

// guardHostOf returns the host a pattern names, the way the matcher reads
// it: surrounding space trimmed, a scheme and its path dropped, a :port and
// IPv6 brackets dropped, a trailing dot dropped. cidr reports a value that
// carries a "/" with no scheme, which must be a CIDR block as a whole.
func guardHostOf(raw string) (host string, cidr bool) {
	t := strings.TrimSpace(raw)
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
		if j := strings.IndexAny(t, "/?#"); j >= 0 {
			t = t[:j]
		}
	} else if strings.Contains(t, "/") {
		return t, true
	}
	if strings.Contains(t, "@") {
		// user[:password]@host: kept whole, so the user-name rule sees it
		// (stripping a "port" would cut at the password's colon).
		return t, false
	}
	switch {
	case strings.HasPrefix(t, "["):
		// [v6] or [v6]:port.
		if j := strings.Index(t, "]"); j > 0 {
			t = t[1:j]
		}
	case strings.Count(t, ":") == 1:
		// host:port (more than one colon is an IPv6 literal).
		t, _, _ = strings.Cut(t, ":")
	}
	return strings.TrimSuffix(t, "."), false
}

// guardHostPatternRules are the refusals, walked in order on the host
// guardHostOf took out of the value; the first match wins. why completes
// "host pattern %q ...".
var guardHostPatternRules = []struct {
	refuse func(host string) bool
	why    string
}{
	{func(h string) bool { return h == "" }, "names no host"},
	{func(h string) bool { return strings.ContainsAny(h, " \t\r\n") }, "contains whitespace"},
	{func(h string) bool { return strings.Contains(h, "@") }, "carries a user name: name the host alone"},
	{func(h string) bool { return guardHostWildcardRest(h) == "" }, `is a bare "*", which names no host`},
	{func(h string) bool { return strings.Contains(guardHostWildcardRest(h), "*") }, `uses "*" other than as a leading "*." or "*" ("*.example.com" matches the subdomains, "*example.com" the host and its subdomains)`},
}

// guardHostWildcardRest is a host with its one allowed leading wildcard
// ("*." or "*") removed.
func guardHostWildcardRest(h string) string {
	if rest, ok := strings.CutPrefix(h, "*."); ok {
		return rest
	}
	return strings.TrimPrefix(h, "*")
}

// guardHostPatternProblem returns why no network rule could honour raw ("" =
// it is fine).
func guardHostPatternProblem(raw string) string {
	host, cidr := guardHostOf(raw)
	if cidr {
		if strings.ContainsAny(host, " \t\r\n") {
			return "contains whitespace"
		}
		if _, _, err := net.ParseCIDR(host); err != nil {
			return "has a \"/\" but is not a CIDR block: " + err.Error()
		}
		return ""
	}
	for _, r := range guardHostPatternRules {
		if r.refuse(host) {
			return r.why
		}
	}
	return ""
}

// guardProdPatternCredential matches a credential inside a
// [guard.database] prod pattern: a user:password@ part of a connection
// string, or a password= key (any case, pwd and passwd included). A prod
// pattern names a host, a database or a profile; it never needs the
// password, and config.toml keeps it in plain text.
var guardProdPatternCredential = []*regexp.Regexp{
	regexp.MustCompile(`[^\s/:@;]+:[^\s/@;]+@`),
	regexp.MustCompile(`(?i)(^|[\s;&?,])(password|passwd|pwd)\s*=`),
}

// guardProdPatternHasCredential reports whether p carries a credential.
func guardProdPatternHasCredential(p string) bool {
	for _, rx := range guardProdPatternCredential {
		if rx.MatchString(p) {
			return true
		}
	}
	return false
}
