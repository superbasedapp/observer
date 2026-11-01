package orgcontract

import (
	"strings"
	"testing"
)

// TestSecurityCustomCatalogValidation (lane SEC-E4): the served catalog
// only ever expands a named manifest, with both digests pinned, and the
// custom mode is a closed vocabulary.
func TestSecurityCustomCatalogValidation(t *testing.T) {
	m := "sha256:" + strings.Repeat("a", 64)
	x := "sha256:" + strings.Repeat("b", 64)
	ok := SecurityManagedPolicyV1{
		Version: 1, CustomManifests: []string{m}, CustomMode: "require",
		CustomCatalog: []SecurityCustomCatalogEntry{{ManifestSHA256: m, ExecutableSHA256: x, BlockingRules: []SecurityCustomBlockingRule{{RuleID: "G101", Precision: 0.9}}}},
	}
	if err := ValidateSecurityManagedPolicy(ok); err != nil {
		t.Fatalf("valid catalog refused: %v", err)
	}
	cases := map[string]func(p *SecurityManagedPolicyV1){
		"unknown mode":         func(p *SecurityManagedPolicyV1) { p.CustomMode = "allow_all" },
		"not named":            func(p *SecurityManagedPolicyV1) { p.CustomManifests = []string{x} },
		"bad digest":           func(p *SecurityManagedPolicyV1) { p.CustomCatalog[0].ExecutableSHA256 = "/usr/bin/gosec" },
		"no precision":         func(p *SecurityManagedPolicyV1) { p.CustomCatalog[0].BlockingRules[0].Precision = 0 },
		"rule id with a space": func(p *SecurityManagedPolicyV1) { p.CustomCatalog[0].BlockingRules[0].RuleID = "rm -rf" },
		"duplicate":            func(p *SecurityManagedPolicyV1) { p.CustomCatalog = append(p.CustomCatalog, p.CustomCatalog[0]) },
		"empty":                func(p *SecurityManagedPolicyV1) { p.CustomCatalog = []SecurityCustomCatalogEntry{} },
	}
	for name, mut := range cases {
		p := ok
		p.CustomManifests = append([]string(nil), ok.CustomManifests...)
		p.CustomCatalog = []SecurityCustomCatalogEntry{{ManifestSHA256: m, ExecutableSHA256: x, BlockingRules: []SecurityCustomBlockingRule{{RuleID: "G101", Precision: 0.9}}}}
		mut(&p)
		if err := ValidateSecurityManagedPolicy(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	raw := []byte(`{"version":1,"custom_manifests":["` + m + `"],"custom_catalog":[{"manifest_sha256":"` + m + `","executable_sha256":"` + x + `","argv":["sh"]}]}`)
	if _, _, err := DecodeSecurityManagedPolicy(raw); err == nil {
		t.Error("an argument field must be refused (the body is closed)")
	}
}
