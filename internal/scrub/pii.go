package scrub

import (
	"regexp"
	"strconv"
	"strings"
)

// This file holds the Phase 0 PII detector support code (contract
// docs/plans/prompt-submit-intervention-exploration-2026-09-07.md §4.2):
// the checksum/structural validators each `typedDetector.validate` row
// wires up, plus the two PII-only false-positive controls (test-value
// suppression, code-context suppression — §4.3 items 1 and 2). Every
// function here is pure (string/byte in, bool/string out) and
// independently unit-testable — see pii_test.go.

// ---------------------------------------------------------------------
// Normalization helpers
// ---------------------------------------------------------------------

// normalizeDigits strips everything except ASCII digits from s.
func normalizeDigits(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b = append(b, s[i])
		}
	}
	return string(b)
}

// normalizeAlnumUpper strips everything except ASCII letters/digits from
// s and upper-cases the result (IBAN normalization: ISO 7064 works over
// an uppercase alphanumeric string with no separators).
func normalizeAlnumUpper(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			b = append(b, c)
		case c >= 'a' && c <= 'z':
			b = append(b, c-('a'-'A'))
		case c >= 'A' && c <= 'Z':
			b = append(b, c)
		}
	}
	return string(b)
}

// ---------------------------------------------------------------------
// Luhn (credit_card)
// ---------------------------------------------------------------------

// luhnValid implements the Luhn mod-10 checksum used by every major
// card network. digits must already be normalized to ASCII digits only
// (see normalizeDigits); a non-digit byte or an empty string is invalid.
func luhnValid(digits string) bool {
	if digits == "" {
		return false
	}
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		c := digits[i]
		if c < '0' || c > '9' {
			return false
		}
		d := int(c - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// iinRange is one brand's IIN (issuer identification number) range,
// matched against a fixed-width digit prefix of the PAN. Table-driven
// per CLAUDE.md rule 5 — one row per documented brand range, no
// nested conditionals.
type iinRange struct {
	brand  string
	width  int // how many leading digits this range is defined over
	lo, hi int // inclusive range over that width (lo == hi for a single value)
}

// creditCardIINRanges is the brand-range table creditCardIINValid
// walks. Source: the contract's §4.2 credit_card row (Visa/Mastercard/
// Amex/Discover/Diners Club/JCB/UnionPay).
var creditCardIINRanges = []iinRange{
	{brand: "visa", width: 1, lo: 4, hi: 4},
	{brand: "mastercard_legacy", width: 2, lo: 51, hi: 55},
	{brand: "mastercard_2017", width: 4, lo: 2221, hi: 2720},
	{brand: "amex", width: 2, lo: 34, hi: 34},
	{brand: "amex", width: 2, lo: 37, hi: 37},
	{brand: "discover_6011", width: 4, lo: 6011, hi: 6011},
	{brand: "discover_644_649", width: 3, lo: 644, hi: 649},
	{brand: "discover_65", width: 2, lo: 65, hi: 65},
	{brand: "diners_300_305", width: 3, lo: 300, hi: 305},
	{brand: "diners_3095", width: 4, lo: 3095, hi: 3095},
	{brand: "diners_36", width: 2, lo: 36, hi: 36},
	{brand: "diners_38_39", width: 2, lo: 38, hi: 39},
	{brand: "jcb", width: 4, lo: 3528, hi: 3589},
	{brand: "unionpay", width: 2, lo: 62, hi: 62},
}

// creditCardIINValid reports whether digits' leading prefix falls in
// any documented brand IIN range (contract §4.2). One table walk, no
// per-brand branching.
func creditCardIINValid(digits string) bool {
	for _, r := range creditCardIINRanges {
		if r.width > len(digits) {
			continue
		}
		v, err := strconv.Atoi(digits[:r.width])
		if err != nil {
			continue
		}
		if v >= r.lo && v <= r.hi {
			return true
		}
	}
	return false
}

// creditCardValidate is the typedDetector.validate for the credit_card
// row: normalize (strip `-`/space separators), check the 13-19 digit
// length band, the IIN range, and finally Luhn. Test-value suppression
// (Stripe's published test PANs, shape-based placeholders) runs
// separately in detectorMatch — a shape-valid test PAN legitimately
// passes both checks here and must still be dropped downstream.
func creditCardValidate(raw string) bool {
	digits := normalizeDigits(raw)
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	if !creditCardIINValid(digits) {
		return false
	}
	return luhnValid(digits)
}

// ---------------------------------------------------------------------
// IBAN mod-97 (iban)
// ---------------------------------------------------------------------

// ibanLengths is the ISO 13616 per-country-code total IBAN length
// table. An unrecognized country code is rejected outright (contract
// §4.2) rather than guessed at.
var ibanLengths = map[string]int{
	"AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16,
	"BG": 22, "BH": 22, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28,
	"CZ": 24, "DE": 22, "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24,
	"FI": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18,
	"GR": 27, "GT": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23,
	"IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32,
	"LI": 21, "LT": 20, "LU": 20, "LV": 21, "LY": 25, "MC": 27, "MD": 24,
	"ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15,
	"PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22,
	"SA": 24, "SC": 31, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "ST": 25,
	"SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24,
	"XK": 20,
}

// ibanMod97Valid implements the ISO 7064 mod-97-10 check: move the
// first four characters (country code + check digits) to the end,
// convert every letter to its two-digit ordinal (A=10 ... Z=35), and
// require the resulting decimal string mod 97 == 1. iban must already
// be normalized (uppercase, no separators — see normalizeAlnumUpper).
func ibanMod97Valid(iban string) bool {
	if len(iban) < 4 {
		return false
	}
	rearranged := iban[4:] + iban[:4]
	remainder := 0
	for i := 0; i < len(rearranged); i++ {
		c := rearranged[i]
		switch {
		case c >= '0' && c <= '9':
			remainder = (remainder*10 + int(c-'0')) % 97
		case c >= 'A' && c <= 'Z':
			ord := int(c-'A') + 10 // two-digit value 10-35
			remainder = (remainder*10 + ord/10) % 97
			remainder = (remainder*10 + ord%10) % 97
		default:
			return false
		}
	}
	return remainder == 1
}

// ibanValidate is the typedDetector.validate for the iban row:
// normalize, check the country's registered total length, then run the
// mod-97 checksum. An unrecognized country code is rejected.
func ibanValidate(raw string) bool {
	iban := normalizeAlnumUpper(raw)
	if len(iban) < 4 {
		return false
	}
	country := iban[:2]
	wantLen, ok := ibanLengths[country]
	if !ok || len(iban) != wantLen {
		return false
	}
	return ibanMod97Valid(iban)
}

// ---------------------------------------------------------------------
// US SSN structural rules (us_ssn)
// ---------------------------------------------------------------------

// ssnStructuralValid implements the US SSN allocation rules: area ∉
// {000, 666, 900-999}, group ≠ 00, serial ≠ 0000. area/group/serial are
// the three hyphen-delimited digit groups (3/2/4 digits).
func ssnStructuralValid(area, group, serial string) bool {
	a, err := strconv.Atoi(area)
	if err != nil || a == 0 || a == 666 || a >= 900 {
		return false
	}
	g, err := strconv.Atoi(group)
	if err != nil || g == 0 {
		return false
	}
	s, err := strconv.Atoi(serial)
	if err != nil || s == 0 {
		return false
	}
	return true
}

// ssnValidate is the typedDetector.validate for the us_ssn row
// (hyphenated form only — `\d{3}-\d{2}-\d{4}`).
func ssnValidate(raw string) bool {
	digits := normalizeDigits(raw)
	if len(digits) != 9 {
		return false
	}
	return ssnStructuralValid(digits[0:3], digits[3:5], digits[5:9])
}

// ---------------------------------------------------------------------
// UK NINO structural rules (uk_nino)
// ---------------------------------------------------------------------

// ninoDisallowedPrefixes are the two-letter NINO prefixes reserved and
// never issued (contract §4.2).
var ninoDisallowedPrefixes = map[string]bool{
	"BG": true, "DA": true, "FP": true, "FY": true, "GB": true, "IU": true,
	"KN": true, "MW": true, "NC": true, "NK": true, "NT": true, "OA": true,
	"PP": true, "PZ": true, "TN": true, "ZZ": true,
}

// ninoStructuralValid implements the UK National Insurance Number
// prefix rules: the first letter is never D, F, I, Q, U or V; the
// second letter is never O; and the two-letter prefix is never one of
// the reserved ninoDisallowedPrefixes.
func ninoStructuralValid(prefix string) bool {
	if len(prefix) != 2 {
		return false
	}
	switch prefix[0] {
	case 'D', 'F', 'I', 'Q', 'U', 'V':
		return false
	}
	if prefix[1] == 'O' {
		return false
	}
	return !ninoDisallowedPrefixes[prefix]
}

// ninoValidate is the typedDetector.validate for the uk_nino row.
func ninoValidate(raw string) bool {
	if len(raw) < 2 {
		return false
	}
	return ninoStructuralValid(strings.ToUpper(raw[:2]))
}

// ---------------------------------------------------------------------
// Verhoeff checksum (in_aadhaar)
// ---------------------------------------------------------------------

// verhoeffD is the Verhoeff algorithm's D5 dihedral-group multiplication
// table.
var verhoeffD = [10][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
	{2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
	{3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
	{4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
	{5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
	{6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
	{7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
	{8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
	{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
}

// verhoeffP is the Verhoeff algorithm's permutation table, indexed by
// (position mod 8).
var verhoeffP = [8][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
	{5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
	{8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
	{9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
	{4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
	{2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
	{7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
}

// verhoeffValid reports whether digits (a 12-digit Aadhaar number, check
// digit last) satisfies the Verhoeff checksum — the dihedral-group D5
// algorithm, resistant to every single-digit error and every adjacent
// transposition (unlike Luhn). digits must be ASCII digits only.
func verhoeffValid(digits string) bool {
	if digits == "" {
		return false
	}
	c := 0
	n := len(digits)
	for i := 0; i < n; i++ {
		ch := digits[n-1-i]
		if ch < '0' || ch > '9' {
			return false
		}
		c = verhoeffD[c][verhoeffP[i%8][ch-'0']]
	}
	return c == 0
}

// aadhaarValidate is the typedDetector.validate for the in_aadhaar row:
// normalize (strip optional grouping spaces), check the 12-digit
// length and the 2-9 leading-digit rule, then run Verhoeff.
func aadhaarValidate(raw string) bool {
	digits := normalizeDigits(raw)
	if len(digits) != 12 || digits[0] < '2' || digits[0] > '9' {
		return false
	}
	return verhoeffValid(digits)
}

// ---------------------------------------------------------------------
// Indian PAN entity code (in_pan)
// ---------------------------------------------------------------------

// panEntityCodeValid reports whether b is a recognized PAN 4th-character
// holder-type code: P individual, C company, H HUF, A AOP, B BOI,
// G government, J artificial juridical person, L local authority,
// F firm, T trust, E LLP.
func panEntityCodeValid(b byte) bool {
	switch b {
	case 'P', 'C', 'H', 'A', 'B', 'G', 'J', 'L', 'F', 'T', 'E':
		return true
	}
	return false
}

// panValidate is the typedDetector.validate for the in_pan row
// (`[A-Z]{5}\d{4}[A-Z]`, 10 characters total; the 4th character —
// index 3 — carries the holder-type code).
func panValidate(raw string) bool {
	if len(raw) != 10 {
		return false
	}
	return panEntityCodeValid(raw[3])
}

// ---------------------------------------------------------------------
// NANP phone structural check (phone_nanp)
// ---------------------------------------------------------------------

// phoneNANPValidate re-checks the area-code and exchange-code ≥2 rule
// already baked into the phone_nanp regex's character classes — a
// belt-and-suspenders structural gate so the rule survives even if the
// pattern is ever loosened.
func phoneNANPValidate(raw string) bool {
	digits := normalizeDigits(raw)
	if len(digits) == 11 && digits[0] == '1' {
		digits = digits[1:]
	}
	if len(digits) != 10 {
		return false
	}
	return digits[0] >= '2' && digits[3] >= '2'
}

// ---------------------------------------------------------------------
// §4.3.1 — Test-value suppression (PII findings only)
// ---------------------------------------------------------------------

// testValues holds well-known placeholder values that must never
// interrupt a PII detector even though their SHAPE (and, for the PANs,
// their Luhn checksum) is valid: Stripe's published test PANs
// (docs.stripe.com/testing brand-representative head), the two
// canonical IBAN test values, and the three canonical fake SSNs used in
// examples and fixtures industry-wide. Consulted for PII findings only
// (§4.3 item 1) — secrets are never suppressed this way, since a real
// key pasted into a fixture is still a real key.
var testValues = map[string]bool{
	// Stripe test PANs.
	"4242424242424242": true,
	"4000056655665556": true,
	"5555555555554444": true,
	"2223003122003222": true,
	"5105105105105100": true,
	"378282246310005":  true,
	"371449635398431":  true,
	"6011111111111117": true,
	"6011000990139424": true,
	"3056930009020004": true,
	"36227206271667":   true,
	"3566002020360505": true,
	"6200000000000005": true,
	// Classic Visa test PANs published by Visa/Braintree and echoed by
	// nearly every payment-gateway sandbox — the single most-pasted
	// "fake card" shape on the internet (round-2 review F4). Any of
	// these appearing in a prompt is a fixture/example, never a real
	// card.
	"4111111111111111": true, // Visa (the canonical "test card" everyone knows)
	"4012888888881881": true, // Visa (Braintree sandbox)
	"4000000000000002": true, // Visa (generic decline-test PAN)
	// IBAN test values (registry-documented examples).
	"DE89370400440532013000": true,
	"GB82WEST12345698765432": true,
	// Canonical fake SSNs, normalized (hyphens stripped).
	"123456789": true, // 123-45-6789
	"078051120": true, // 078-05-1120
	"219099999": true, // 219-09-9999
}

// isTestValue reports whether raw is a well-known placeholder (a
// published Stripe test PAN, a canonical IBAN test value, or a
// canonical fake SSN) or matches a shape-based placeholder pattern —
// all-identical digits, a strictly ascending digit run, or a digit
// string built from one repeated 4-digit block (§4.3 item 1). Applied
// to PII findings only.
func isTestValue(raw string) bool {
	digits := normalizeDigits(raw)
	if digits != "" {
		if testValues[digits] {
			return true
		}
		if len(digits) >= 8 && (allIdenticalDigits(digits) || strictlyAscendingDigits(digits) || repeated4DigitBlock(digits)) {
			return true
		}
	}
	alnum := normalizeAlnumUpper(raw)
	if alnum != "" && testValues[alnum] {
		return true
	}
	return false
}

// allIdenticalDigits reports whether every digit in d is the same
// (e.g. "1111111111111111").
func allIdenticalDigits(d string) bool {
	for i := 1; i < len(d); i++ {
		if d[i] != d[0] {
			return false
		}
	}
	return true
}

// strictlyAscendingDigits reports whether d is a strictly ascending run
// of digits (e.g. "12345678"). Ascension wraps are NOT accepted — each
// digit must be exactly one more than the previous.
func strictlyAscendingDigits(d string) bool {
	for i := 1; i < len(d); i++ {
		if int(d[i]-'0') != int(d[i-1]-'0')+1 {
			return false
		}
	}
	return true
}

// repeated4DigitBlock reports whether d is made of one 4-digit block
// repeated end to end (e.g. "42484248"), a common shape for
// placeholder/example numbers.
func repeated4DigitBlock(d string) bool {
	if len(d) < 8 || len(d)%4 != 0 {
		return false
	}
	block := d[:4]
	for i := 4; i < len(d); i += 4 {
		if d[i:i+4] != block {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------
// §4.3.2 — Code-context suppression (PII findings only)
// ---------------------------------------------------------------------

// commentLineRE matches a line that is entirely (ignoring leading
// whitespace) a comment in one of the common source-code comment
// styles — `//`, `#`, `*` (block-comment continuation), `--`.
var commentLineRE = regexp.MustCompile(`^\s*(//|#|\*|--)`)

// inCodeContext/insideFencedCodeBlock moved to detect.go as
// detectState methods (round-2 review B4): the fenced-code-block
// boundary list is now precomputed ONCE per scan instead of rescanned
// from byte zero on every PII candidate. lineBounds and
// insideInlineCodeSpan below are still the line-local helpers that
// implementation calls.

// lineBounds returns the [start,end) byte range of the line containing
// pos (end excludes the trailing newline, if any).
func lineBounds(body string, pos int) (int, int) {
	start := strings.LastIndexByte(body[:pos], '\n') + 1
	end := strings.IndexByte(body[pos:], '\n')
	if end < 0 {
		end = len(body)
	} else {
		end += pos
	}
	return start, end
}

// insideInlineCodeSpan reports whether [start,end) within line sits
// between a backtick before start and a backtick at or after end on the
// same line — a Markdown inline-code span.
func insideInlineCodeSpan(line string, start, end int) bool {
	before := strings.LastIndexByte(line[:start], '`')
	if before < 0 {
		return false
	}
	after := strings.IndexByte(line[end:], '`')
	return after >= 0
}
