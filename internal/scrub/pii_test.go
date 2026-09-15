package scrub

import (
	"strings"
	"testing"
)

// repeatToLen builds a string of exactly n bytes by repeating s — used
// throughout so fixture lengths (the {22,}/{35}/{10,} floors in the new
// detector patterns) are computed, not hand-counted.
func repeatToLen(s string, n int) string {
	if len(s) == 0 {
		panic("repeatToLen: empty s")
	}
	out := strings.Repeat(s, n/len(s)+2)
	return out[:n]
}

// mustValidAadhaar appends the Verhoeff check digit (0-9, exactly one
// works) to an 11-digit prefix, so Aadhaar fixtures are generated from
// the SAME algorithm under test rather than hand-computed and risking a
// transcription error.
func mustValidAadhaar(t *testing.T, prefix string) string {
	t.Helper()
	for d := byte('0'); d <= '9'; d++ {
		cand := prefix + string(d)
		if verhoeffValid(cand) {
			return cand
		}
	}
	t.Fatalf("no valid Verhoeff check digit for prefix %q", prefix)
	return ""
}

// ---------------------------------------------------------------------
// Checksum/structural unit tests (pii.go functions in isolation)
// ---------------------------------------------------------------------

func TestLuhnValid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		digits string
		want   bool
	}{
		{"4111111111111111", true},  // well-known Luhn-valid Visa test shape
		{"4242424242424242", true},  // Stripe test PAN — also Luhn-valid
		{"4111111111111112", false}, // last digit tampered
		{"", false},
		{"41111111x1111111", false}, // non-digit byte
	}
	for _, tc := range cases {
		if got := luhnValid(tc.digits); got != tc.want {
			t.Errorf("luhnValid(%q) = %v, want %v", tc.digits, got, tc.want)
		}
	}
}

func TestCreditCardIINValid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		digits string
		want   bool
	}{
		{"4111111111111111", true},  // Visa
		{"5105105105105100", true},  // Mastercard legacy range
		{"2223003122003222", true},  // Mastercard 2017 range
		{"378282246310005", true},   // Amex
		{"6011111111111117", true},  // Discover
		{"30569300090200", true},    // Diners (300-305)
		{"3530111333300000", true},  // JCB
		{"6200000000000005", true},  // UnionPay
		{"1234567890123456", false}, // no recognized IIN
	}
	for _, tc := range cases {
		if got := creditCardIINValid(tc.digits); got != tc.want {
			t.Errorf("creditCardIINValid(%q) = %v, want %v", tc.digits, got, tc.want)
		}
	}
}

func TestIBANMod97Valid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		iban string
		want bool
	}{
		{"GB29NWBK60161331926819", true},  // textbook-valid example
		{"DE89370400440532013000", true},  // textbook-valid example
		{"GB29NWBK60161331926818", false}, // last digit tampered
		{"XX00", false},                   // too short to be plausible
	}
	for _, tc := range cases {
		if got := ibanMod97Valid(tc.iban); got != tc.want {
			t.Errorf("ibanMod97Valid(%q) = %v, want %v", tc.iban, got, tc.want)
		}
	}
}

func TestSSNStructuralValid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		area, group, serial string
		want                bool
	}{
		{"245", "11", "1234", true},
		{"000", "11", "1234", false}, // area 000
		{"666", "11", "1234", false}, // area 666
		{"901", "11", "1234", false}, // area >= 900
		{"245", "00", "1234", false}, // group 00
		{"245", "11", "0000", false}, // serial 0000
	}
	for _, tc := range cases {
		if got := ssnStructuralValid(tc.area, tc.group, tc.serial); got != tc.want {
			t.Errorf("ssnStructuralValid(%q,%q,%q) = %v, want %v", tc.area, tc.group, tc.serial, got, tc.want)
		}
	}
}

func TestNINOStructuralValid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		prefix string
		want   bool
	}{
		{"AB", true},
		{"DA", false}, // first letter D banned (also a disallowed pair)
		{"ZO", false}, // second letter O banned
		{"GB", false}, // disallowed exact pair
		{"BG", false}, // disallowed exact pair
	}
	for _, tc := range cases {
		if got := ninoStructuralValid(tc.prefix); got != tc.want {
			t.Errorf("ninoStructuralValid(%q) = %v, want %v", tc.prefix, got, tc.want)
		}
	}
}

func TestVerhoeffValid(t *testing.T) {
	t.Parallel()
	valid := mustValidAadhaar(t, "23456789012")
	// Tamper the check digit: every OTHER digit 0-9 must now fail
	// (Verhoeff guarantees exactly one valid check digit per prefix).
	tampered := valid[:11] + string('0'+(valid[11]-'0'+1)%10)
	if !verhoeffValid(valid) {
		t.Fatalf("verhoeffValid(%q) = false, want true", valid)
	}
	if verhoeffValid(tampered) {
		t.Fatalf("verhoeffValid(%q) = true, want false (tampered check digit)", tampered)
	}
	if verhoeffValid("") {
		t.Fatal("verhoeffValid(\"\") = true, want false")
	}
	if verhoeffValid("1234567890a") {
		t.Fatal("verhoeffValid with non-digit byte = true, want false")
	}
}

func TestPANEntityCodeValid(t *testing.T) {
	t.Parallel()
	for _, b := range []byte("PCHABGJLFTE") {
		if !panEntityCodeValid(b) {
			t.Errorf("panEntityCodeValid(%q) = false, want true", b)
		}
	}
	for _, b := range []byte("DIKMOQRSUVWXYZ") {
		if panEntityCodeValid(b) {
			t.Errorf("panEntityCodeValid(%q) = true, want false", b)
		}
	}
}

// ---------------------------------------------------------------------
// Full-pipeline table tests: positive / negative / test-value /
// code-context, per PII detector (§10 item 1 acceptance gate, §18).
// ---------------------------------------------------------------------

// piiTypeFindings runs the class-aware DetectPromptFindings (round-2
// review B2 moved PII-classified rows off the secret-only
// DetectSecrets, so this helper now uses the prompt-submit entry
// point) with the built-in defaults (unbounded findings, code-context
// suppression on — the historical unconditional behavior these tests
// pin) and returns the PII-classified subset.
func piiTypeFindings(body string) []TypedFinding {
	var out []TypedFinding
	findings, _ := DetectPromptFindings(body, PromptDetectOptions{SuppressInCode: true})
	for _, f := range findings {
		if f.Class == classPII {
			out = append(out, f)
		}
	}
	return out
}

func hasPIIType(body, want string) bool {
	for _, f := range piiTypeFindings(body) {
		if f.Type == want {
			return true
		}
	}
	return false
}

func TestDetectPII_CreditCard(t *testing.T) {
	t.Parallel()
	// A non-published Luhn+IIN-valid PAN (round-2 review F4): the
	// obvious "4111111111111111" is now itself in testValues (it's the
	// single most-pasted "fake Visa" on the internet — Visa/Braintree's
	// own published test PAN), so a positive-detection test must use a
	// value that ISN'T on that suppression list.
	valid := "4532015112830366"
	stripeTest := "4242424242424242"
	classicVisaTest := "4111111111111111"

	if !hasPIIType("card on file: "+valid, "credit_card") {
		t.Errorf("valid Luhn+IIN card not detected")
	}
	if hasPIIType("card on file: "+valid[:len(valid)-1]+"2", "credit_card") {
		t.Errorf("Luhn-invalid card was flagged")
	}
	if hasPIIType("order id "+repeatToLen("1", 20), "credit_card") {
		t.Errorf("a 20-digit id run was flagged as a credit card (must not match inside a longer run)")
	}
	if hasPIIType("value: "+stripeTest, "credit_card") {
		t.Errorf("Stripe test PAN was NOT suppressed by test-value rule")
	}
	if hasPIIType("value: "+classicVisaTest, "credit_card") {
		t.Errorf("classic published Visa/Braintree test PAN was NOT suppressed by test-value rule")
	}
	fenced := "```\ncard: " + valid + "\n```"
	if hasPIIType(fenced, "credit_card") {
		t.Errorf("card inside a fenced code block was NOT suppressed")
	}
	// The same shape OUTSIDE a code fence must still fire.
	if !hasPIIType("card: "+valid, "credit_card") {
		t.Errorf("card outside code context unexpectedly suppressed")
	}
}

// TestDetectPII_CreditCard_PublishedTestPANs pins the full set of
// classic Visa/Braintree/Stripe published test PANs added to
// testValues (round-2 review F4) — every one of these must be
// suppressed even though its shape (and Luhn checksum) is valid.
func TestDetectPII_CreditCard_PublishedTestPANs(t *testing.T) {
	t.Parallel()
	for _, pan := range []string{
		"4111111111111111", // Visa (Braintree/everyone's go-to test card)
		"4012888888881881", // Visa (Braintree sandbox)
		"4000000000000002", // Visa (generic decline-test PAN)
	} {
		if hasPIIType("card on file: "+pan, "credit_card") {
			t.Errorf("published test PAN %q was NOT suppressed", pan)
		}
	}
}

func TestDetectPII_IBAN(t *testing.T) {
	t.Parallel()
	valid := "GB29NWBK60161331926819"
	invalid := "GB29NWBK60161331926818"

	if !hasPIIType("IBAN: "+valid, "iban") {
		t.Errorf("valid IBAN not detected (gate requires the literal word IBAN somewhere in body)")
	}
	if hasPIIType("IBAN: "+invalid, "iban") {
		t.Errorf("mod-97-invalid IBAN was flagged")
	}
	if hasPIIType("IBAN: DE89370400440532013000", "iban") {
		t.Errorf("canonical IBAN test value was NOT suppressed")
	}
	if hasPIIType("just prose with no bank details here, no gate word", "iban") {
		t.Errorf("iban fired without its gate word present")
	}
}

func TestDetectPII_USSSN(t *testing.T) {
	t.Parallel()
	if !hasPIIType("SSN 245-11-1234 on file", "us_ssn") {
		t.Errorf("structurally valid SSN not detected")
	}
	if hasPIIType("SSN 666-11-1234 on file", "us_ssn") {
		t.Errorf("area 666 SSN was flagged")
	}
	if hasPIIType("SSN 000-11-1234 on file", "us_ssn") {
		t.Errorf("area 000 SSN was flagged")
	}
	if hasPIIType("SSN 123-45-6789 on file", "us_ssn") {
		t.Errorf("canonical fake SSN was NOT suppressed")
	}
	if hasPIIType("order 245111234 shipped", "us_ssn") {
		t.Errorf("unhyphenated 9-digit run was flagged (v1 is hyphenated-only)")
	}
	fenced := "```\nssn: 245-11-1234\n```"
	if hasPIIType(fenced, "us_ssn") {
		t.Errorf("SSN inside a fenced code block was NOT suppressed")
	}
}

func TestDetectPII_UKNINO(t *testing.T) {
	t.Parallel()
	if !hasPIIType("my nino is AB123456C", "uk_nino") {
		t.Errorf("valid NINO with context word not detected")
	}
	if hasPIIType("AB123456C appeared with no context word nearby at all in this sentence padded out well past the sixty byte radius on both sides of the match so the window cannot see any trigger word", "uk_nino") {
		t.Errorf("NINO fired without a context word within radius")
	}
	if hasPIIType("national insurance: GB123456C", "uk_nino") {
		t.Errorf("disallowed prefix GB was flagged")
	}
}

func TestDetectPII_InAadhaar(t *testing.T) {
	t.Parallel()
	valid := mustValidAadhaar(t, "23456789012")
	tampered := valid[:11] + string('0'+(valid[11]-'0'+1)%10)

	if !hasPIIType("aadhaar number "+valid, "in_aadhaar") {
		t.Errorf("valid Aadhaar with context word not detected")
	}
	if hasPIIType("aadhaar number "+tampered, "in_aadhaar") {
		t.Errorf("Verhoeff-invalid Aadhaar was flagged")
	}
	if hasPIIType(valid+" appeared here with absolutely no trigger word anywhere close enough to it, padded out well past the sixty byte context radius on either side of the number", "in_aadhaar") {
		t.Errorf("Aadhaar fired without a context word within radius")
	}
	if hasPIIType("uidai ref 1234567890", "in_aadhaar") {
		t.Errorf("10-digit run (too short) was flagged as Aadhaar")
	}
}

func TestDetectPII_InPAN(t *testing.T) {
	t.Parallel()
	if !hasPIIType("pan is ABCPE1234F", "in_pan") {
		t.Errorf("valid PAN (entity code P) with context word not detected")
	}
	if hasPIIType("pan is ABCDE1234F", "in_pan") {
		t.Errorf("PAN with invalid entity-type code (D) was flagged")
	}
	if hasPIIType("ABCPE1234F shipped with no trigger word close enough to it, padded out well past the sixty byte context radius on either side of the code so it cannot see a nearby trigger", "in_pan") {
		t.Errorf("PAN fired without a context word within radius")
	}
}

func TestDetectPII_Email(t *testing.T) {
	t.Parallel()
	if !hasPIIType("contact me at foo.bar@example.com please", "email") {
		t.Errorf("valid email not detected")
	}
	if hasPIIType("not an email: foo.bar_at_example_dot_com", "email") {
		t.Errorf("non-email prose was flagged")
	}
	fenced := "```\nEMAIL=foo.bar@example.com\n```"
	if hasPIIType(fenced, "email") {
		t.Errorf("email inside a fenced code block was NOT suppressed")
	}
}

func TestDetectPII_PhoneE164(t *testing.T) {
	t.Parallel()
	if !hasPIIType("call +15551234567 now", "phone_e164") {
		t.Errorf("valid E.164 number not detected")
	}
	if hasPIIType("build $+15551234567", "phone_e164") {
		t.Errorf("number preceded by $ was flagged")
	}
	if hasPIIType("ticket #+15551234567", "phone_e164") {
		t.Errorf("number preceded by # was flagged")
	}
}

func TestDetectPII_PhoneNANP(t *testing.T) {
	t.Parallel()
	if !hasPIIType("call me at (415) 555-2671 today", "phone_nanp") {
		t.Errorf("valid NANP number with context word not detected")
	}
	if hasPIIType("(415) 555-2671 appeared in a log line with no trigger word anywhere close enough, padded out well past the sixty byte context radius on either side of the number", "phone_nanp") {
		t.Errorf("NANP number fired without a context word within radius")
	}
	if hasPIIType("call (115) 555-2671 now", "phone_nanp") {
		t.Errorf("area code starting with 1 (invalid NANP area) was flagged")
	}
}

// ---------------------------------------------------------------------
// Fuzz-lite corpus (§10 item 1 acceptance gate): a representative
// source-code-like corpus must produce ZERO PII findings. Every number
// here is deliberately id/hash/timestamp/version-shaped, never a real
// checksummed PII value.
// ---------------------------------------------------------------------

const fuzzLiteCorpus = `
package main

import (
	"fmt"
	"net/http"
)

// requestID: 550e8400-e29b-41d4-a716-446655440000
// commit: 9f8c3b2a1e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b
const version = "v1.8.3"
const buildTimestamp = "2026-09-07T12:34:56Z"

func main() {
	client := &http.Client{Timeout: 30}
	resp, err := client.Get("http://192.168.1.1:8080/api/v1/status")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer resp.Body.Close()

	orderID := "1000000000000001" // internal sequential id, 16 digits
	sessionCount := 123456789
	fmt.Printf("order=%s sessions=%d port=%d\n", orderID, sessionCount, 8443)

	// SHA-256 of an empty string, for reference:
	// e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

	dottedVersionString := "2.15.10.20260907"
	_ = dottedVersionString
}
`

func TestDetectPII_FuzzLiteCorpus(t *testing.T) {
	t.Parallel()
	findings := piiTypeFindings(fuzzLiteCorpus)
	if len(findings) != 0 {
		t.Fatalf("fuzz-lite corpus produced %d PII findings, want 0: %+v", len(findings), findings)
	}
}
