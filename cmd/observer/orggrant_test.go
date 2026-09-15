package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/govern"
)

// TestAuthorityPlainEnglishCoversEnterpriseAuthoritySet pins
// authorityPlainEnglish against drift (2026-09-13 W7/W8 verification finding
// A): every token an enterprise-posture enrolment can mint
// (govern.EnterpriseAuthoritySet) must have real copy here, or `observer
// enroll` and `observer org grant show` print the "UNKNOWN ... never acted
// on" fallback for a token this build DOES act on — which is exactly what
// happened for enforce.budget, the token that makes the org's budget cap
// authoritative on a managed node and the fail-closed budget stop (guard
// rule B-625) engage.
func TestAuthorityPlainEnglishCoversEnterpriseAuthoritySet(t *testing.T) {
	t.Parallel()
	for _, tok := range govern.EnterpriseAuthoritySet() {
		got := authorityPlainEnglish(tok)
		if strings.HasPrefix(got, "UNKNOWN to this version of Observer") {
			t.Errorf("authorityPlainEnglish(%q) fell through to the UNKNOWN fallback; add a case for it", tok)
		}
	}
}
