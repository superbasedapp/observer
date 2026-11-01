package orgenrol

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/govern"
)

// TestModuleEnforceTokensConsentCopy is security plan 7.2 row 13 (node
// consent copy, and `observer org grant` through it) for both module enforce
// tokens: each has its own sentence naming what the org can switch on, and
// says it is managed tenancy only.
func TestModuleEnforceTokensConsentCopy(t *testing.T) {
	for tok, want := range map[string]string{
		govern.AuthorityEnforceSecurity: "code security",
		govern.AuthorityEnforceSandbox:  "sandboxed terminals",
	} {
		copy := AuthorityPlainEnglish(tok)
		if !strings.Contains(copy, want) || !strings.Contains(copy, "managed tenancy only") || strings.HasPrefix(copy, "UNKNOWN") {
			t.Errorf("%s: %q", tok, copy)
		}
	}
}
