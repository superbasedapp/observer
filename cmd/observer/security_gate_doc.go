//go:build !sbo_omit_security

package main

import (
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/secrules"
)

// security_gate_doc.go renders the commit gate's section of
// docs/guard-rules.md (the S-791 to S-794 rows, secrules.GateRules), with
// how S-792's hold on a pushed-away secret is released (merge finding F2
// of lane SEC-GATE5). With sbo_omit_security the section is absent.

func init() { guardCommitGateCatalogMarkdown = commitGateRuleCatalogMarkdown }

// commitGateRuleCatalogMarkdown is the commit gate's section.
func commitGateRuleCatalogMarkdown() string {
	var b strings.Builder
	b.WriteString("\n## Code security: commit gate\n\n")
	b.WriteString("These rows fire only while the security module is active (see\n")
	b.WriteString("`docs/code-security.md`). S-792 holds a push while a commit the push's\n")
	b.WriteString("remote does not have yet adds a secret, also after the secret is removed\n")
	b.WriteString("from the files. Amending, rebasing or resetting does not release that\n")
	b.WriteString("hold until the reflog no longer reaches the old commit (30 days by\n")
	b.WriteString("default). The hold is released by a push the developer approves (which\n")
	b.WriteString("sends the commit, so rotate the secret afterwards), or, after dropping\n")
	b.WriteString("the secret from the commit, by " + secrules.PushReleaseStep + ".\n\n")
	b.WriteString("| ID | Category | Severity | Observe | Enforce | Trigger |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for _, r := range secrules.GateRules() {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", r.ID, r.Category, r.Severity, r.Observe, r.Enforce, strings.ReplaceAll(r.Doc, "|", "\\|"))
	}
	return b.String()
}
