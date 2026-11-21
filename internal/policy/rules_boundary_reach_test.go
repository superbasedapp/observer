package policy

import "testing"

// TestReachRecordIsObserverConfiguration: the Go symbol checks' stored
// record (plan section 14.5 item 3b, secreachsvc.SymbolPath) ranks a
// finding up or down, so an agent forging it would rank its own vulnerable
// dependency down; it lives under ~/.observer, so R-160 judges every write
// to it, and it is not a consent record (R-165 does not take it over).
func TestReachRecordIsObserverConfiguration(t *testing.T) {
	const home = "/home/dev"
	for _, p := range []string{
		"/home/dev/.observer/security/reach/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json",
		"~/.observer/security/reach/x.json",
	} {
		if _, ok := observerConfigPath(p, home); !ok {
			t.Errorf("%s is not judged as observer configuration (R-160)", p)
		}
		if _, ok := pathPatternMatch(p, home, consentRecordPatterns); ok {
			t.Errorf("%s matched a consent record pattern", p)
		}
	}
}
