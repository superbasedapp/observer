package scrub

import (
	"fmt"
	"strings"
	"testing"
)

// TestDetectSecrets_PerDetectorRow gives every typed detector row a
// hit + near-miss pair (§18: one case per table row minimum).
func TestDetectSecrets_PerDetectorRow(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		in       string
		wantType string // "" = expect NO findings
		certain  bool
	}{
		{
			name:     "github_pat hit",
			in:       "pushed with ghp_AbCdEfGhIjKlMnOpQrStUvWx1234",
			wantType: "github_pat", certain: true,
		},
		{
			name: "github_pat near-miss: too short",
			in:   "ghp_short",
		},
		{
			name:     "bearer_token hit",
			in:       `Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig`,
			wantType: "bearer_token", certain: true,
		},
		{
			name: "bearer_token near-miss: prose",
			in:   "the Bearer of bad news",
		},
		{
			name:     "api_key_prefixed hit",
			in:       "use sk-proj_AbCd1234EfGh5678IjKl",
			wantType: "api_key_prefixed", certain: true,
		},
		{
			name: "api_key_prefixed near-miss: short tail",
			in:   "ask-me-anything sk-short",
		},
		{
			name:     "api_key_named hit",
			in:       "api_key_AbCdEfGh1234567890XyZabc",
			wantType: "api_key_named", certain: true,
		},
		{
			name:     "aws_access_key hit",
			in:       "creds AKIAIOSFODNN7EXAMPLE here",
			wantType: "aws_access_key", certain: true,
		},
		{
			name: "aws_access_key near-miss: lowercase",
			in:   "akiaiosfodnn7example",
		},
		{
			name:     "private_key_block hit",
			in:       "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
			wantType: "private_key_block", certain: true,
		},
		{
			name:     "private_key_block hit: truncated paste",
			in:       "-----BEGIN PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7c8",
			wantType: "private_key_block", certain: true,
		},
		{
			name:     "json_secret_value hit",
			in:       `{"password": "hunter22"}`,
			wantType: "json_secret_value", certain: true,
		},
		{
			name: "json_secret_value near-miss: usage tokens field",
			in:   `{"input_tokens": 4096, "output_tokens": 200, "max_tokens": 8192}`,
		},
		{
			// The value is deliberately NOT api-key-prefixed: a prefixed
			// key (sk-/pk-/ak-) is claimed by the more precise
			// api_key_prefixed detector since its body admits hyphens
			// (the sk-ant-api03 fix, 2026-08-29) - pinned two rows down.
			name:     "env_secret_value hit",
			in:       `{"OPENAI_API_KEY": "svcacct9AbCd1234EfGh5678IjKl"}`,
			wantType: "env_secret_value", certain: true,
		},
		{
			name:     "api_key_prefixed claims hyphenated anthropic-shaped key",
			in:       `{"ANTHROPIC_API_KEY": "sk-ant-api03-AbCd1234EfGh5678IjKl9MnOp"}`,
			wantType: "api_key_prefixed", certain: true,
		},
		{
			name:     "secret_assignment hit",
			in:       "password=correcthorsebatterystaple",
			wantType: "secret_assignment", certain: true,
		},
		{
			name: "secret_assignment near-miss: short prose value",
			in:   "token: yes",
		},
		{
			name:     "api_key_assignment hit",
			in:       "api-key: 0123456789abcdef",
			wantType: "api_key_assignment", certain: true,
		},
		{
			name: "export_secret hit",
			// A *_KEY var name: covered by the export row but NOT by
			// secret_assignment (whose class set has no bare "key") —
			// pins the export row's own coverage.
			in:       "export DEPLOY_KEY=abc123def456",
			wantType: "export_secret", certain: true,
		},
		{
			name: "export_secret near-miss: unrelated var",
			in:   "export EDITOR=vim",
		},
		{
			name:     "connection_string_password hit",
			in:       "postgres://admin:s3cr3tpw@db.internal:5432/app",
			wantType: "connection_string_password", certain: true,
		},
		{
			name: "connection_string_password near-miss: no credentials",
			in:   "https://docs.example.com/path",
		},
		{
			name: "entropy hit: high-entropy token near secret context",
			// "access_key" opens an entropy window but triggers no
			// assignment row (no '=' / ':' between word and token).
			in:       "# access_key for deploy\naB3dE5fG7hI9jK1LmN3oP5qR7sT9uV1wX3yZ5aB7cD9eF1g",
			wantType: "entropy", certain: false,
		},
		{
			name: "entropy near-miss: same token without context word",
			in:   `value = "aB3dE5fG7hI9jK1LmN3oP5qR7sT9uV1wX3yZ5aB7cD9eF1g"`,
		},
		{
			name: "entropy near-miss: hex digest near context (no uppercase)",
			in:   "auth log sha 3b8f2c9d4e5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6",
		},
		{
			name: "clean body",
			in:   `{"model":"claude-opus-4-8","messages":[{"role":"user","content":"hello"}]}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := DetectSecrets(tc.in)
			if tc.wantType == "" {
				if len(got) != 0 {
					t.Fatalf("DetectSecrets(%q) = %+v, want none", tc.in, got)
				}
				return
			}
			found := false
			for _, f := range got {
				if f.Type == tc.wantType {
					found = true
					if f.Certain != tc.certain {
						t.Errorf("finding %s Certain = %v, want %v", f.Type, f.Certain, tc.certain)
					}
					if f.Value == "" {
						t.Errorf("finding %s has empty Value", f.Type)
					}
				}
			}
			if !found {
				t.Fatalf("DetectSecrets(%q) = %+v, want a %q finding", tc.in, got, tc.wantType)
			}
		})
	}
}

// TestDetectSecrets_Phase0SecretRows gives each of the five Phase 0
// secret-shape rows (contract §4.1) a hit + near-miss pair, mirroring
// TestDetectSecrets_PerDetectorRow's convention.
func TestDetectSecrets_Phase0SecretRows(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		in       string
		wantType string // "" = expect NO findings
	}{
		{
			// Neutral prefix (no "token"/"secret"/"key" trigger word) so
			// the earlier, more generic secret_assignment/env_secret_value
			// rows don't claim the span first — mirrors the existing
			// "pushed with ghp_..." github_pat convention.
			name:     "github_pat_fine hit",
			in:       "pushed with " + "github_pat_" + repeatToLen("11ABCDEFGH", 24),
			wantType: "github_pat_fine",
		},
		{
			name: "github_pat_fine near-miss: too short",
			in:   "pushed with github_pat_short",
		},
		{
			name:     "gcp_api_key hit",
			in:       "key=" + "AIza" + repeatToLen("SyD4kZ8xF0", 35),
			wantType: "gcp_api_key",
		},
		{
			name: "gcp_api_key near-miss: short tail",
			in:   "key=AIzaShort",
		},
		{
			// Neutral prefix — "export ...TOKEN=" would let the earlier,
			// more generic export_secret/secret_assignment rows claim
			// the span first.
			name:     "slack_token hit: bot token",
			in:       "posting via " + "xoxb-" + repeatToLen("1234567890", 12),
			wantType: "slack_token",
		},
		{
			name:     "slack_token hit: xapp",
			in:       "socket mode: " + "xapp-" + repeatToLen("1A2b3C4d5E", 12),
			wantType: "slack_token",
		},
		{
			name: "slack_token near-miss: short tail",
			in:   "xoxb-short",
		},
		{
			name:     "jwt hit",
			in:       "Authorization: " + "eyJ" + repeatToLen("aGVhZGVy", 12) + "." + "eyJ" + repeatToLen("cGF5bG9hZA", 12) + "." + repeatToLen("c2ln", 12),
			wantType: "jwt",
		},
		{
			name: "jwt near-miss: only two segments",
			in:   "eyJhbGciOiJIUzI1NiJ9.justonemoresegment",
		},
		{
			// The bare shell/env-file assignment form is the genuine
			// gap this row closes (contract §4.1): no pre-existing row
			// covers a key name starting "aws_..." outside of an
			// "export"/generic-keyword prefix. The JSON-quoted form
			// ("aws_secret_key": "...") is intentionally NOT exercised
			// here — env_secret_value's broader `[a-z_]*secret[a-z_]*`
			// key match already claims it (its match starts at the
			// enclosing quote, one byte earlier), which is correct,
			// pre-existing, certain coverage, not a regression.
			name:     "aws_secret_key hit: shell assignment",
			in:       "aws_secret_access_key=" + repeatToLen("aB3dE5fG7h", 32),
			wantType: "aws_secret_key",
		},
		{
			name: "aws_secret_key near-miss: unrelated key",
			in:   "aws_region=us-east-1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := DetectSecrets(tc.in)
			if tc.wantType == "" {
				for _, f := range got {
					if f.Type == tc.wantType {
						t.Fatalf("DetectSecrets(%q) unexpectedly matched %+v", tc.in, f)
					}
				}
				return
			}
			found := false
			for _, f := range got {
				if f.Type == tc.wantType {
					found = true
					if !f.Certain {
						t.Errorf("finding %s Certain = false, want true", f.Type)
					}
					if f.Class != classSecret {
						t.Errorf("finding %s Class = %q, want %q", f.Type, f.Class, classSecret)
					}
					if f.Value == "" {
						t.Errorf("finding %s has empty Value", f.Type)
					}
				}
			}
			if !found {
				t.Fatalf("DetectSecrets(%q) = %+v, want a %q finding", tc.in, got, tc.wantType)
			}
		})
	}
}

// TestPhase0SecretRows_FeedPreExistingConsumers pins the NIT (round-2
// re-review): the five Phase 0 secret rows (§4.1) are exercised above
// only through DetectSecrets directly. This test closes the gap by
// asserting they ALSO flow, unmodified, into the two pre-existing
// downstream consumers every OTHER secret row already feeds:
// CertainSecretTypes (the R-172 shell-arg rule's injectable detector)
// and MaskSecrets (the proxy egress masking primitive) — intentional
// coverage, not an accidental side effect of adding rows to the shared
// table.
func TestPhase0SecretRows_FeedPreExistingConsumers(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"github_pat_fine", "pushed with github_pat_" + repeatToLen("11ABCDEFGH", 24), "github_pat_fine"},
		{"gcp_api_key", "key=AIza" + repeatToLen("SyD4kZ8xF0", 35), "gcp_api_key"},
		{"slack_token", "posting via xoxb-" + repeatToLen("1234567890", 12), "slack_token"},
		{"jwt", "Authorization: eyJ" + repeatToLen("aGVhZGVy", 12) + ".eyJ" + repeatToLen("cGF5bG9hZA", 12) + "." + repeatToLen("c2ln", 12), "jwt"},
		{"aws_secret_key", "aws_secret_access_key=" + repeatToLen("aB3dE5fG7h", 32), "aws_secret_key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			types := CertainSecretTypes(tc.in)
			found := false
			for _, ty := range types {
				if ty == tc.want {
					found = true
				}
			}
			if !found {
				t.Errorf("CertainSecretTypes(%q) = %v, want it to include %q", tc.in, types, tc.want)
			}
			masked, findings := MaskSecrets(tc.in, func(TypedFinding) bool { return true })
			if masked == tc.in {
				t.Errorf("MaskSecrets(%q) left the body unmasked", tc.in)
			}
			maskedType := false
			for _, f := range findings {
				if f.Type == tc.want {
					maskedType = true
				}
			}
			if !maskedType {
				t.Errorf("MaskSecrets(%q) findings = %+v, want a %q finding", tc.in, findings, tc.want)
			}
		})
	}
}

// TestDetectSecrets_FernetShielded pins the encrypted_content shield:
// a Fernet blob that happens to contain a secret-shaped substring must
// not be flagged, and masking must leave it byte-identical.
func TestDetectSecrets_FernetShielded(t *testing.T) {
	t.Parallel()
	body := `{"encrypted_content":"gAAAAABghp_AbCdEfGhIjKlMnOpQrStUvWx1234zzz","note":"x"}`
	if got := DetectSecrets(body); len(got) != 0 {
		t.Fatalf("DetectSecrets flagged inside shielded encrypted_content: %+v", got)
	}
	masked, _ := MaskSecrets(body, func(TypedFinding) bool { return true })
	if masked != body {
		t.Fatalf("MaskSecrets mutated a shielded body:\n got %q\nwant %q", masked, body)
	}
}

// TestMaskSecrets_Selective pins selective masking: only findings the
// predicate accepts are rewritten; the rest of the body (and rejected
// findings) survive byte-identical, and the output stays valid in
// place ("[REDACTED:type]" markers).
func TestMaskSecrets_Selective(t *testing.T) {
	t.Parallel()
	body := `{"key":"ghp_AbCdEfGhIjKlMnOpQrStUvWx1234","msg":"access_key aB3dE5fG7hI9jK1LmN3oP5qR7sT9uV1wX3yZ5aB7cD9eF1g"}`
	masked, findings := MaskSecrets(body, func(f TypedFinding) bool { return f.Certain })
	if !strings.Contains(masked, "[REDACTED:github_pat]") {
		t.Fatalf("certain finding not masked: %q", masked)
	}
	if strings.Contains(masked, "ghp_AbCdEfGhIjKlMnOpQrStUvWx1234") {
		t.Fatalf("secret survived masking: %q", masked)
	}
	if !strings.Contains(masked, "aB3dE5fG7hI9jK1LmN3oP5qR7sT9uV1wX3yZ5aB7cD9eF1g") {
		t.Fatalf("entropy (non-certain) finding was masked despite predicate: %q", masked)
	}
	var types []string
	for _, f := range findings {
		types = append(types, f.Type)
	}
	if len(findings) < 2 {
		t.Fatalf("findings = %v, want both github_pat and an entropy hit", types)
	}
}

// TestMaskSecrets_NilPredicate pins pure-detection mode: nil predicate
// returns the input unchanged.
func TestMaskSecrets_NilPredicate(t *testing.T) {
	t.Parallel()
	body := "token ghp_AbCdEfGhIjKlMnOpQrStUvWx1234"
	out, findings := MaskSecrets(body, nil)
	if out != body {
		t.Fatalf("nil-predicate MaskSecrets mutated input: %q", out)
	}
	if len(findings) == 0 {
		t.Fatal("nil-predicate MaskSecrets returned no findings")
	}
}

// TestMaskSecrets_OverlapDedup pins overlap resolution: when the
// entropy candidate covers the same bytes as a certain detector, only
// the certain finding survives (table order wins).
func TestMaskSecrets_OverlapDedup(t *testing.T) {
	t.Parallel()
	// A GitHub PAT sitting next to the word "secret" is both a
	// github_pat hit and an entropy-window candidate.
	body := "secret: ghp_AbCd1234EfGh5678IjKl9012MnOp"
	_, findings := MaskSecrets(body, nil)
	var pat, ent int
	for _, f := range findings {
		switch f.Type {
		case "github_pat":
			pat++
		case "entropy":
			ent++
		}
	}
	if pat != 1 {
		t.Fatalf("github_pat findings = %d, want 1 (findings %+v)", pat, findings)
	}
	if ent != 0 {
		t.Fatalf("entropy findings = %d, want 0 — overlap with github_pat must dedup", ent)
	}
}

// TestCertainSecretTypes pins the R-172 injection surface: certain
// types only, deduplicated, first-seen order.
func TestCertainSecretTypes(t *testing.T) {
	t.Parallel()
	in := "curl -H 'Authorization: Bearer eyJabc12345.def.ghi' -d token=ghp_AbCdEfGhIjKlMnOpQrStUvWx1234 -d t2=ghp_ZyXwVuTsRqPoNmLkJiHg5678"
	got := CertainSecretTypes(in)
	want := map[string]bool{"bearer_token": true, "github_pat": true}
	if len(got) < 2 {
		t.Fatalf("CertainSecretTypes = %v, want at least bearer_token + github_pat", got)
	}
	seen := map[string]bool{}
	for _, ty := range got {
		if seen[ty] {
			t.Fatalf("CertainSecretTypes returned duplicate %q: %v", ty, got)
		}
		seen[ty] = true
	}
	for w := range want {
		if !seen[w] {
			t.Fatalf("CertainSecretTypes = %v, missing %q", got, w)
		}
	}
}

// ---------------------------------------------------------------------
// Round-2 review B2 — the secret-only public API must never leak a
// PII-classified finding to a consumer that treats "detected" as
// "route egress enforcement" (proxy scan / R-172 shell-arg rule /
// admission gate / process-argv masker).
// ---------------------------------------------------------------------

// TestCertainSecretTypes_NeverFlagsEmail pins the exact regression the
// review called out: a commit-trailer email must never trip the R-172
// secret rule via CertainSecretTypes.
func TestCertainSecretTypes_NeverFlagsEmail(t *testing.T) {
	t.Parallel()
	if got := CertainSecretTypes("Reviewed-by: dev@corp.io"); got != nil {
		t.Fatalf("CertainSecretTypes(%q) = %v, want nil — an email is PII, not a secret", "Reviewed-by: dev@corp.io", got)
	}
}

// TestDetectSecrets_ExcludesEveryPIIClassRow walks every PII-classified
// row (email, phone, credit_card, ...) through the secret-only API and
// asserts none of them ever surface there — DetectSecrets/
// CertainSecretTypes/MaskSecrets are secret-only post round-2 review B2;
// PII findings are reachable ONLY via DetectPromptFindings.
func TestDetectSecrets_ExcludesEveryPIIClassRow(t *testing.T) {
	t.Parallel()
	body := "contact dev@corp.io or call +15551234567 (phone), card 4532015112830366, " +
		"ssn 245-11-1234, iban GB29NWBK60161331926819, aadhaar 234123412346 (aadhaar), pan ABCPE1234F (pan)"
	for _, f := range DetectSecrets(body) {
		if f.Class == classPII {
			t.Errorf("DetectSecrets leaked a PII-classified finding: %+v", f)
		}
	}
	for _, ty := range CertainSecretTypes(body) {
		for _, pii := range []string{"credit_card", "us_ssn", "iban", "in_aadhaar", "in_pan", "email", "phone_e164", "phone_nanp", "uk_nino"} {
			if ty == pii {
				t.Errorf("CertainSecretTypes leaked PII type %q", ty)
			}
		}
	}
	// Sanity: the class-aware entry point DOES see both classes, so the
	// exclusion above is a real filter, not an artifact of the body
	// containing no PII at all.
	sawPII := false
	findings, _ := DetectPromptFindings(body, PromptDetectOptions{SuppressInCode: true})
	for _, f := range findings {
		if f.Class == classPII {
			sawPII = true
		}
	}
	if !sawPII {
		t.Fatal("test body produced no PII findings via DetectPromptFindings — test is vacuous")
	}
}

// TestMaskSecrets_NeverEmitsPIIRedactionMarker pins the same posture
// for MaskSecrets: a PII finding must never be masked as
// "[REDACTED:<pii-type>]", and must never appear in the returned
// finding list either.
func TestMaskSecrets_NeverEmitsPIIRedactionMarker(t *testing.T) {
	t.Parallel()
	body := "email me at dev@corp.io about the outage"
	masked, findings := MaskSecrets(body, func(TypedFinding) bool { return true })
	if strings.Contains(masked, "[REDACTED:email]") {
		t.Fatalf("MaskSecrets masked a PII (email) finding as a secret: %q", masked)
	}
	if masked != body {
		t.Fatalf("MaskSecrets mutated a body with no secrets in it: %q", masked)
	}
	for _, f := range findings {
		if f.Class == classPII {
			t.Errorf("MaskSecrets returned a PII finding: %+v", f)
		}
	}
}

// TestDetectSecrets_UnifiedDiffPasteYieldsNoSecretFindings pins the
// acceptance-gate shape from contract §10 item 1: a unified-diff hunk
// (the classic false-positive source for numeric/PII-shaped patterns —
// "+1234567890"-style addition lines) must produce no finding via the
// secret-only API.
func TestDetectSecrets_UnifiedDiffPasteYieldsNoSecretFindings(t *testing.T) {
	t.Parallel()
	diff := "--- a/config.go\n+++ b/config.go\n@@ -1,3 +1,4 @@\n" +
		" package config\n+const phoneCode = +1234567890\n-const old = 1\n+const new = 2\n"
	if got := DetectSecrets(diff); len(got) != 0 {
		t.Fatalf("DetectSecrets(diff) = %+v, want no findings", got)
	}
	if got := CertainSecretTypes(diff); got != nil {
		t.Fatalf("CertainSecretTypes(diff) = %v, want nil", got)
	}
}

// ---------------------------------------------------------------------
// Round-2 review B3 — the §4.5 MaxRawInputBytes bound must apply ONLY
// to the PII detection surface; the pre-existing secret scan must
// always see the whole body, however large.
// ---------------------------------------------------------------------

// TestDetectSecrets_ScansFullBodyPastPIIBound pins the exact scenario
// the review called out: a 2 MiB body with a real secret at the very
// end must still yield the finding, even though that's well past the
// 1 MiB MaxRawInputBytes ceiling the PII surface is bounded by.
func TestDetectSecrets_ScansFullBodyPastPIIBound(t *testing.T) {
	t.Parallel()
	padding := strings.Repeat("the quick brown fox jumps over the lazy dog. ", 50000) // ~2.3MB
	if len(padding) <= MaxRawInputBytes {
		t.Fatalf("test setup: padding %d bytes is not past MaxRawInputBytes %d", len(padding), MaxRawInputBytes)
	}
	body := padding + "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
	got := DetectSecrets(body)
	found := false
	for _, f := range got {
		if f.Type == "api_key_prefixed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("DetectSecrets on a %d-byte body did not find the trailing sk-ant- key (findings=%+v) — the secret scan must never be bounded", len(body), got)
	}
}

// ---------------------------------------------------------------------
// BLOCK-2 (round-2 re-review) — the shared max_findings cap used to be
// consumed in detector-table order: a body carrying many off-mode
// findings could exhaust it before an active detector's own candidates
// were ever tried, silently dropping a live interrupt-worthy finding
// with no signal anything was skipped.
// ---------------------------------------------------------------------

// TestDetectPromptFindings_OffModeDetectorNeverConsumesAnothersCap pins
// the exact scenario the contract's re-review named: 70 email-shaped
// strings (email detector NOT in ActiveDetectors — the caller's
// equivalent of [guard.prompt.detectors].email = "off") followed by a
// real, non-suppressed credit card AND SSN. Before this fix, a shared
// 64-finding cap consumed by 70 email hits (scanned regardless of
// "mode") left NOTHING for the numeric pre-pass that finds
// credit_card/us_ssn. With email excluded from ActiveDetectors AND the
// cap made per-detector, both the card and the SSN must be found.
func TestDetectPromptFindings_OffModeDetectorNeverConsumesAnothersCap(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	for i := 0; i < 70; i++ {
		fmt.Fprintf(&b, "contact%d@example.com ", i)
	}
	b.WriteString("card on file: 4532015112830366, ssn 245-11-1234 on file")

	active := map[string]bool{}
	for _, name := range DetectorNames() {
		if name != "email" {
			active[name] = true
		}
	}
	opts := PromptDetectOptions{MaxFindings: 64, SuppressInCode: true, ActiveDetectors: active}
	findings, truncated := DetectPromptFindings(b.String(), opts)
	if truncated {
		t.Fatalf("body is well under MaxRawInputBytes, must not report truncated")
	}

	var sawCard, sawSSN, sawEmail bool
	for _, f := range findings {
		switch f.Type {
		case "credit_card":
			sawCard = true
		case "us_ssn":
			sawSSN = true
		case "email":
			sawEmail = true
		}
	}
	if !sawCard {
		t.Errorf("credit_card not found — the off-mode email detector's volume starved it (findings=%+v)", findings)
	}
	if !sawSSN {
		t.Errorf("us_ssn not found — the off-mode email detector's volume starved it (findings=%+v)", findings)
	}
	if sawEmail {
		t.Errorf("email detector ran despite being excluded from ActiveDetectors")
	}
}

// TestDetectPromptFindings_PerDetectorCapIsIndependent pins the other
// half of BLOCK-2 directly: even when EVERY detector is active, one
// detector's own high-volume hits must not exhaust a DIFFERENT
// detector's budget. 70 emails (active) plus one card plus one SSN,
// cap=64: the card and SSN must still surface even though email alone
// blows past the 64 cap on its own.
func TestDetectPromptFindings_PerDetectorCapIsIndependent(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	for i := 0; i < 70; i++ {
		fmt.Fprintf(&b, "contact%d@example.com ", i)
	}
	b.WriteString("card on file: 4532015112830366, ssn 245-11-1234 on file")

	findings, _ := DetectPromptFindings(b.String(), PromptDetectOptions{MaxFindings: 64, SuppressInCode: true})
	var sawCard, sawSSN int
	emailCount := 0
	for _, f := range findings {
		switch f.Type {
		case "credit_card":
			sawCard++
		case "us_ssn":
			sawSSN++
		case "email":
			emailCount++
		}
	}
	if sawCard == 0 {
		t.Errorf("credit_card not found even with per-detector caps (findings=%d email, %d card, %d ssn)", emailCount, sawCard, sawSSN)
	}
	if sawSSN == 0 {
		t.Errorf("us_ssn not found even with per-detector caps (findings=%d email, %d card, %d ssn)", emailCount, sawCard, sawSSN)
	}
	if emailCount > 64 {
		t.Errorf("email findings %d exceeded its own per-detector cap of 64", emailCount)
	}
}

// TestDetectorClass pins the Part B item 4 CLI seam (`observer guard
// prompt allow <detector>` needs to know whether a name is a
// secret or PII detector to pick R-172 vs R-190): every name
// DetectorNames() returns must resolve via DetectorClass, "entropy"
// resolves ClassSecret, a known PII name resolves ClassPII, and an
// unknown name reports ok=false rather than a guessed class.
func TestDetectorClass(t *testing.T) {
	for _, name := range DetectorNames() {
		class, ok := DetectorClass(name)
		if !ok {
			t.Errorf("DetectorClass(%q) ok = false, want true (every DetectorNames() entry must resolve)", name)
		}
		if class != ClassSecret && class != ClassPII {
			t.Errorf("DetectorClass(%q) = %q, want ClassSecret or ClassPII", name, class)
		}
	}
	if class, ok := DetectorClass("entropy"); !ok || class != ClassSecret {
		t.Errorf(`DetectorClass("entropy") = (%q, %v), want (ClassSecret, true)`, class, ok)
	}
	if class, ok := DetectorClass("credit_card"); !ok || class != ClassPII {
		t.Errorf(`DetectorClass("credit_card") = (%q, %v), want (ClassPII, true)`, class, ok)
	}
	if _, ok := DetectorClass("definitely-not-a-detector"); ok {
		t.Error("DetectorClass returned ok=true for an unknown name")
	}
}
