package secfinding

import (
	"errors"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestLocalKeyRules (section 4.5.1, acceptance A): stable under
// whitespace changes and line moves, different across projects and
// rules, location-free.
func TestLocalKeyRules(t *testing.T) {
	t.Parallel()
	k := func(project, rule, text string) string { return LocalKey(project, rule, TextIdentity(text)) }
	base := k("p1", "R", "x := query + input")
	cases := []struct {
		name string
		got  string
		same bool
	}{
		{"reindented", k("p1", "R", "  x :=   query +\n\tinput  "), true},
		{"another project", k("p2", "R", "x := query + input"), false},
		{"another rule", k("p1", "R2", "x := query + input"), false},
		{"another text", k("p1", "R", "y := query + input"), false},
		{"symbol identity differs from text", LocalKey("p1", "R", SymbolIdentity("x", "call")), false},
	}
	for _, tc := range cases {
		if (tc.got == base) != tc.same {
			t.Errorf("%s: same = %v, want %v", tc.name, tc.got == base, tc.same)
		}
	}
	if len(base) != 64 {
		t.Fatalf("local key %q is not a sha256 hex", base)
	}
}

// TestSecretIdentityNeverHoldsTheValue and the org keys: a node never
// builds the org key from the node-keyed HMAC, and without the org key
// there is no org fingerprint.
func TestSecretIdentityAndOrgKeys(t *testing.T) {
	t.Parallel()
	const secret = "AKIA" + "ABCDEFGHIJKLMNOP" // split: GitHub push protection on the public mirror
	nodeA, nodeB, org := []byte("node-a"), []byte("node-b"), []byte("org-dedupe-key")
	id := func(key []byte, v string) MatchIdentity {
		t.Helper()
		m, err := SecretIdentity(key, "aws", v)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	a, b := id(nodeA, secret), id(nodeB, secret)
	if strings.Contains(a.Value, secret) || a.Value == b.Value {
		t.Fatal("a secret identity holds no value and differs per node key")
	}
	if a != id(nodeA, "  "+secret+"\n") {
		t.Fatal("surrounding white space must not change the identity")
	}
	// Audit P-002 finding 7: no node key, no identity.
	for _, key := range [][]byte{nil, {}} {
		if m, err := SecretIdentity(key, "aws", secret); !errors.Is(err, ErrNoNodeKey) || m != (MatchIdentity{}) {
			t.Fatalf("empty key: %+v, %v", m, err)
		}
	}
	if OrgKey(org, "S-721", a) != "" {
		t.Fatal("an org key is never built from the node-keyed HMAC")
	}
	if OrgSecretKey(org, "aws", secret) == "" || OrgSecretKey(org, "aws", secret) != OrgSecretKey(org, "aws", secret+" ") {
		t.Fatal("the same secret dedupes across nodes under the org key")
	}
	if OrgSecretKey(nil, "aws", secret) != "" || OrgKey(nil, "R", TextIdentity("x")) != "" {
		t.Fatal("no org key, no org fingerprint")
	}
	if OrgKey(org, "R", TextIdentity("x")) == OrgKey([]byte("other"), "R", TextIdentity("x")) {
		t.Fatal("the org key depends on the org's key")
	}
	d1 := DependencyIdentity("npm", "lodash", "4.17.20", "GHSA-1")
	if d1 == DependencyIdentity("npm", "lodash", "4.17.21", "GHSA-1") {
		t.Fatal("the dependency identity includes the version")
	}
}

func TestNormalizeCapsAndVocabularies(t *testing.T) {
	t.Parallel()
	f := Normalize(Finding{
		Location:         Location{RelPath: strings.Repeat("a", MaxPath+50), StartLine: 9, EndLine: 3, PathAliases: make([]string, MaxPathAliases+3)},
		Rule:             Rule{ID: "R\x1b[31m-1"},
		EvidenceRedacted: strings.Repeat("é", MaxEvidence+10),
		Message:          strings.Repeat("m", MaxMessage+1),
		Category:         "bogus", Severity: "apocalyptic", Confidence: "very", Baseline: "x", Status: "y",
		Attribution: InferredAttribution{Class: "person"},
	})
	switch {
	case len(f.Location.RelPath) != MaxPath, len(f.Location.PathAliases) != MaxPathAliases, f.Location.EndLine != 9:
		t.Errorf("location not capped: %d, %d, %d", len(f.Location.RelPath), len(f.Location.PathAliases), f.Location.EndLine)
	case strings.ContainsRune(f.Rule.ID, 0x1b):
		t.Errorf("control characters kept: %q", f.Rule.ID)
	case len([]rune(f.EvidenceRedacted)) != MaxEvidence || f.EvidenceHash == "":
		t.Errorf("evidence not capped or hashed: %d", len([]rune(f.EvidenceRedacted)))
	case len(f.Message) != MaxMessage:
		t.Errorf("message not capped: %d", len(f.Message))
	case f.Category != "" || f.Severity != policy.FindingSeverityInfo || f.Confidence != policy.FindingConfidenceLow:
		t.Errorf("vocabularies not closed: %q %q %q", f.Category, f.Severity, f.Confidence)
	case f.Baseline != policy.FindingBaselineUnknown || f.Status != policy.FindingStatusOpen || f.Attribution.Class != policy.FindingAttributionUnknown:
		t.Errorf("vocabularies not closed: %q %q %q", f.Baseline, f.Status, f.Attribution.Class)
	}
	if !NeverPreExisting(policy.FindingSecret) || !NeverPreExisting(policy.FindingMaliciousPackage) || NeverPreExisting(policy.FindingCodeVuln) {
		t.Error("NeverPreExisting")
	}
}
