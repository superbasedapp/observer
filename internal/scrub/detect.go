package scrub

import (
	"math"
	"regexp"
	"sort"
	"strings"
)

// Typed secret detection (guard spec §8.2, G9). The plain Scrubber
// redacts secrets destructively for STORAGE (everything becomes
// "[REDACTED]"); the typed surface here answers a different question —
// WHAT kind of secret appears WHERE — so the proxy egress scan can
// flag/mask/deny with a per-type decision and the R-172 shell-arg rule
// can name the detector that hit. The two surfaces share the same
// shape vocabulary deliberately: a value the Scrubber would redact in
// stored excerpts is a value the egress scan flags on the wire.
//
// Privacy contract: TypedFinding.Value holds the MATCHED SECRET and
// exists only so callers can apply allowlists ([guard.proxy]
// egress_allow) in memory. It must NEVER be persisted, logged, or
// placed on a verdict Reason — callers persist Type counts only.

// TypedFinding is one typed secret detection.
type TypedFinding struct {
	// Type is the stable detector name ("github_pat", "bearer_token",
	// "aws_access_key", ... , "entropy"). Stable strings — they appear
	// in guard_events reasons (as counts) and in [REDACTED:<type>]
	// mask markers.
	Type string
	// Certain reports a pattern-certain detection (a shape that is a
	// secret by construction or by key context). The entropy heuristic
	// is the only non-certain detector; spec §8.2 gates masking on
	// certainty.
	Certain bool
	// Value is the matched secret text — IN-MEMORY ONLY (see the
	// package privacy contract above). Used for egress_allow matching.
	Value string
	// Class distinguishes a secret-shaped finding ("secret": github_pat,
	// bearer_token, entropy, ...) from a personally-identifiable one
	// ("pii": credit_card, iban, us_ssn, ...) so a caller (the
	// prompt-submit intervention mode table, an org-push privacy
	// posture) can branch on the row's kind without a name switch
	// (CLAUDE.md module-boundary rule 3).
	Class string
	// Start and End are the byte offsets of the matched span within the
	// SCANNED input (post-shielding — see the package privacy contract
	// above). Used downstream for fingerprinting and code-context
	// suppression; never persisted as raw content, only ever as a span
	// length.
	Start, End int
}

// Finding classes (TypedFinding.Class / typedDetector.class).
//
// ClassSecret/ClassPII are exported (nit, round-2 re-review) so a
// caller outside this package (internal/guard's BuildPromptFindings)
// branches on the class via the named constant instead of a bare
// string literal; classSecret/classPII stay as this file's own
// shorthand, same values.
const (
	ClassSecret = "secret"
	ClassPII    = "pii"

	classSecret = ClassSecret
	classPII    = ClassPII
)

// typedDetector is one row of the typed detection table. Rows reuse
// the defaultPatterns shapes where those are value-bearing, adding a
// stable type name, a value capture group and a cheap literal gate so
// the regex only runs on bodies that can possibly match (latency
// budget §17.9: the proxy egress scan runs per request).
type typedDetector struct {
	// name is the stable TypedFinding.Type.
	name string
	// re is the detection regex.
	re *regexp.Regexp
	// valueGroup is the submatch index holding the secret value
	// (0 = the full match).
	valueGroup int
	// gates are lowercase literals, ANY of which must appear in the
	// lowercased input for the regex to run. Empty means "always run".
	gates []string
	// certain marks pattern-certain rows (everything but entropy).
	certain bool
	// lowercase marks rows whose pattern is WRITTEN lowercase and
	// matched against the ASCII-lowered input instead of carrying
	// (?i). Go's RE2 loses its literal-prefix fast paths under (?i),
	// which blew the §17.9 budget ~5× on realistic bodies; ASCII
	// lowering is length-preserving, so match spans map 1:1 back to
	// the original bytes (values are extracted case-preserved).
	// Case-SENSITIVE rows (AKIA, gh*_, PEM headers) keep
	// lowercase=false and match the original input.
	lowercase bool
	// anchored switches the row from one full-body FindAll pass to
	// anchored attempts at each gate-literal occurrence (the match
	// must BEGIN at the gate, offset by anchorBack / backScanKey).
	// This is the second §17.9 lever: keyword-alternation patterns
	// ("password|secret|token…") have no usable literal prefix, so a
	// full-body NFA scan costs ~16MB/s — while an \A-anchored attempt
	// per occurrence costs O(match length). Rows whose pattern starts
	// with a selective literal (gh*_, AKIA, "-----BEGIN", "://") stay
	// unanchored: RE2's literal-prefix fast path already handles them.
	anchored bool
	// anchorBack is the fixed byte count the match starts BEFORE the
	// gate occurrence (json_secret_value: the opening quote).
	anchorBack int
	// backScanKey, for env_secret_value, walks back over [a-z0-9_]
	// from the gate occurrence to the opening quote (the keyword may
	// sit mid-key: "github_token").
	backScanKey bool
	// class is "secret" or "pii" (the classSecret/classPII constants).
	// Every row must set it — it drives the PII-only false-positive
	// controls below (test-value suppression, code-context suppression,
	// the 64-finding cap) without a name switch.
	class string
	// validate, when set, is an additional checksum/structural check
	// run against the matched span (case-preserved, separators intact —
	// each validator normalizes internally) before a finding is
	// emitted. nil means "shape is sufficient" (the five new secret
	// rows, and the email/phone_e164 PII rows, which have no checksum
	// per contract §4.2). Every OTHER PII row sets one — v1 emits no
	// bare-shape PII finding.
	validate func(string) bool
	// contextWords, when non-empty, requires at least one of these
	// lowercase words to appear within contextRadius bytes of the
	// matched span (case-insensitive substring search, clamped to the
	// body's bounds) or the finding is DROPPED, not merely marked
	// uncertain (uk_nino, in_aadhaar, in_pan, phone_nanp — §4.2).
	contextWords []string
	// contextRadius is the ± byte window checked by contextWords (60
	// for every row that sets one — §4.2).
	contextRadius int
	// numericCandidate marks the five digit-shaped PII rows with no
	// usable literal gate (credit_card, us_ssn, in_aadhaar, phone_nanp,
	// phone_e164). These are skipped in the normal gate/anchor walk and
	// evaluated only against the shared numeric-run pre-pass candidate
	// spans (§4.5) — one manual scan instead of five full-body regex
	// passes.
	numericCandidate bool
	// rejectPrecedingBytes, when non-empty, drops a match whose matched
	// span is immediately preceded (no gap) by any byte in this string —
	// phone_e164's "not preceded by $ or #" rule (§4.2).
	rejectPrecedingBytes string
	// idx is this row's position in typedDetectors, assigned once by
	// init() below. Used as a plain slice index for the per-detector
	// PII cap (detectState.piiSeenByDetector) — a fixed-size []int
	// indexed by idx is measurably cheaper than a map[string]int on
	// the PII-dense hot path (BenchmarkDetectPII's §17.9 budget is
	// tight enough that switching the BLOCK-2 per-detector cap to a
	// map regressed it from ~6.8ms/op to ~8.8ms/op on a 128KB
	// PII-dense body; the array form has no hashing/allocation cost
	// per candidate).
	idx int
}

// typedDetectors is the detection table, walked in order. Earlier rows
// win span-overlap ties (github_pat beats the generic entropy row on
// the same bytes). One test case per row minimum (§18).
var typedDetectors = []typedDetector{
	{
		name: "github_pat", certain: true, class: classSecret,
		re:    regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`),
		gates: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"},
	},
	{
		name: "bearer_token", certain: true, class: classSecret, lowercase: true, anchored: true,
		// Keep the "bearer " prefix out of the value so masking yields
		// "Bearer [REDACTED:bearer_token]" — still header-shaped. The
		// {8,} floor (absent from the storage pattern) cuts FPs on
		// prose like "Bearer of".
		re:         regexp.MustCompile(`\Abearer\s+([a-z0-9\-._~+/]{8,}=*)`),
		valueGroup: 1,
		gates:      []string{"bearer"},
	},
	{
		name: "api_key_prefixed", certain: true, class: classSecret, lowercase: true, anchored: true,
		re:    regexp.MustCompile(`\A(?:sk|pk|ak)[_-][a-z0-9_-]{16,}`),
		gates: []string{"sk-", "sk_", "pk-", "pk_", "ak-", "ak_"},
	},
	{
		name: "api_key_named", certain: true, class: classSecret, lowercase: true, anchored: true,
		re:    regexp.MustCompile(`\Aapi[_-]?key[_-]?[a-z0-9_]{20,}`),
		gates: []string{"api_key", "api-key", "apikey"},
	},
	{
		name: "aws_access_key", certain: true, class: classSecret,
		re:    regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		gates: []string{"akia"},
	},
	{
		name: "private_key_block", certain: true, class: classSecret,
		// Lazy dotall body up to the END marker (or end of input for a
		// truncated paste) so masking removes the key material, not
		// just the header. Typed-path only — deliberately NOT added to
		// the storage defaultPatterns in this commit, so stored-excerpt
		// behavior is unchanged (additive rule §17.6).
		re:    regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)`),
		gates: []string{"private key-----"},
	},
	{
		name: "json_secret_value", certain: true, class: classSecret, lowercase: true, anchored: true, anchorBack: 1,
		// `"password": "value"` and friends — the key context makes the
		// value certain. The value group excludes the quotes so the
		// mask marker stays inside a valid JSON string. Gates anchor at
		// the keyword; the match begins one byte earlier (the opening
		// quote — anchorBack), so `"input_tokens": 42` fails in O(1).
		re:         regexp.MustCompile(`\A"(?:password|secret|token|credential|api[_-]?key|auth[_-]?token)"\s*:\s*"([^"]+)"`),
		valueGroup: 1,
		gates:      []string{"password", "secret", "token", "credential", "api_key", "api-key", "apikey", "auth_token", "auth-token", "authtoken"},
	},
	{
		name: "env_secret_value", certain: true, class: classSecret, lowercase: true, anchored: true, backScanKey: true,
		// Env-var-style quoted keys ("GITHUB_TOKEN": "..."): the
		// keyword may sit mid-key, so backScanKey walks back over
		// [a-z_] to the opening quote before the anchored attempt.
		re:         regexp.MustCompile(`\A"[a-z_]*(?:secret|token|password|credential|(?:api|access|private|master|encryption|signing|hmac)_key)[a-z_]*"\s*:\s*"([^"]+)"`),
		valueGroup: 1,
		gates:      []string{"secret", "token", "password", "credential", "_key"},
	},
	{
		name: "secret_assignment", certain: true, class: classSecret, lowercase: true, anchored: true,
		// `password=...` / `token: ...` outside JSON (shell args, env
		// files). The {8,} floor keeps prose ("token: yes") quiet.
		re:         regexp.MustCompile(`\A(?:password|secret|credential|token)\s*[=:]\s*(\S{8,})`),
		valueGroup: 1,
		gates:      []string{"password", "secret", "credential", "token"},
	},
	{
		name: "api_key_assignment", certain: true, class: classSecret, lowercase: true, anchored: true,
		re:         regexp.MustCompile(`\Aapi[_-]?key\s*[=:]\s*(\S{8,})`),
		valueGroup: 1,
		gates:      []string{"api_key", "api-key", "apikey"},
	},
	{
		name: "export_secret", certain: true, class: classSecret, lowercase: true, anchored: true,
		re:         regexp.MustCompile(`\Aexport\s+\w*(?:secret|key|token|password|credential)\w*\s*=\s*(\S+)`),
		valueGroup: 1,
		gates:      []string{"export"},
	},
	{
		name: "connection_string_password", certain: true, class: classSecret,
		re:         regexp.MustCompile(`://[^:/\s]+:([^@\s]+)@`),
		valueGroup: 1,
		gates:      []string{"://"},
	},

	// --- Phase 0 secret-shape gap closes (contract §4.1) ---

	{
		// GitHub fine-grained PATs: `github_pat_` is a disjoint prefix
		// from `gh[pousr]_` above (the github_pat row can never claim
		// it), so this is a separate row, not an extension of it.
		name: "github_pat_fine", certain: true, class: classSecret,
		re:    regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`),
		gates: []string{"github_pat_"},
	},
	{
		// Google Cloud API keys. Case-sensitive (the body is mixed-case
		// base62-ish) — gates are always matched against the lowercased
		// body regardless of a row's own `lowercase` setting (see
		// gatesOpen), so the literal is written lowercase here even
		// though the pattern itself matches the original-case input.
		name: "gcp_api_key", certain: true, class: classSecret,
		re:    regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		gates: []string{"aiza"},
	},
	{
		// Slack bot/user/app/config tokens (xoxb-/xoxo-/xoxa-/xoxp-/
		// xoxr-/xoxs-) plus the newer xapp- Socket Mode app tokens.
		name: "slack_token", certain: true, class: classSecret,
		re:    regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,}|xapp-[0-9A-Za-z-]{10,}`),
		gates: []string{"xox", "xapp-"},
	},
	{
		// A bare three-segment JWT. Deliberately narrower than the
		// generic base64 entropy heuristic: requires BOTH segments to
		// start with the `eyJ` JSON-object-base64 signature (header and
		// payload are always JSON objects), never a bare base64 run.
		name: "jwt", certain: true, class: classSecret,
		re:    regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
		gates: []string{"eyj"},
	},
	{
		// AWS secret access keys have no distinguishing shape of their
		// own (a 40-char base64 run is indistinguishable from any other
		// base64 blob) — certain ONLY via an aws_secret_(access_)key
		// assignment, mirroring api_key_assignment/env_secret_value. A
		// bare 40-char base64 run stays entropy-class (contract §4.1).
		name: "aws_secret_key", certain: true, class: classSecret, lowercase: true, anchored: true,
		re:         regexp.MustCompile(`\Aaws_secret_(?:access_)?key"?\s*[:=]\s*"?([a-z0-9/+=]{30,})"?`),
		valueGroup: 1,
		gates:      []string{"aws_secret_access_key", "aws_secret_key"},
	},

	// --- Phase 0 PII detectors (contract §4.2) — every row certain,
	// every row backed by a checksum or structural validator, never a
	// bare shape. The five digit-shaped rows (numericCandidate: true)
	// carry no gate: they are matched only against the shared
	// numeric-run pre-pass candidates built in findTypedShielded (§4.5),
	// never as an independent full-body regex pass. ---

	{
		name: "credit_card", certain: true, class: classPII, numericCandidate: true,
		re:       regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`),
		validate: creditCardValidate,
	},
	{
		// Hyphenated form only in v1 — an unhyphenated 9-digit run is
		// indistinguishable from an order id (contract §4.2).
		name: "us_ssn", certain: true, class: classPII, numericCandidate: true,
		re:       regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		validate: ssnValidate,
	},
	{
		name: "in_aadhaar", certain: true, class: classPII, numericCandidate: true,
		re:            regexp.MustCompile(`\b[2-9]\d{3}(?: ?\d{4}){2}\b`),
		validate:      aadhaarValidate,
		contextWords:  []string{"aadhaar", "aadhar", "uidai"},
		contextRadius: 60,
	},
	{
		// area/exchange-digit ≥2 rule is baked into the character
		// classes below AND re-checked in phoneNANPValidate as a
		// belt-and-suspenders structural gate.
		name: "phone_nanp", certain: true, class: classPII, numericCandidate: true,
		re:            regexp.MustCompile(`\b(?:\+?1[-. ])?\(?[2-9]\d{2}\)?[-. ]?[2-9]\d{2}[-. ]?\d{4}\b`),
		validate:      phoneNANPValidate,
		contextWords:  []string{"phone", "tel", "mobile", "call"},
		contextRadius: 60,
	},
	{
		// No checksum exists for E.164 shape (contract §4.2: "none") —
		// precision comes from the boundary rules instead: never
		// preceded by `$`/`#`, and \b-bounded so it can't claim a
		// fragment of a longer version/hash-looking digit run.
		//
		// A context-word requirement was added post-review (round-2
		// review B2): the bare shape with no checksum and no context
		// gate matched unified-diff addition lines ("+1234567890"),
		// Unix epoch timestamps, and ordinary "+1"-prefixed numeric
		// constants — none of which are phone numbers. This mirrors
		// phone_nanp's own context requirement; the detector still
		// defaults to `off` in [guard.prompt.detectors], so this only
		// matters once an operator turns it on.
		name: "phone_e164", certain: true, class: classPII, numericCandidate: true,
		re:                   regexp.MustCompile(`\+[1-9]\d{7,14}\b`),
		rejectPrecedingBytes: "$#",
		contextWords:         []string{"phone", "tel", "mobile", "call"},
		contextRadius:        60,
	},
	{
		// No cheap literal prefix exists for an IBAN's own characters,
		// so the gate is the word "IBAN" appearing ANYWHERE in the body
		// (contract §4.5 lists this as an accepted example gate) — a
		// deliberate superset of true proximity, traded for one cheap
		// substring check instead of an unconditional full-body regex
		// pass on every request.
		name: "iban", certain: true, class: classPII,
		re:       regexp.MustCompile(`\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b`),
		gates:    []string{"iban"},
		validate: ibanValidate,
	},
	{
		// UK National Insurance Number. Case-sensitive (conventionally
		// upper-case). Gated on its own required context words (§4.2) —
		// a superset of the ±60-byte proximity check below, same trade
		// as the iban gate.
		name: "uk_nino", certain: true, class: classPII,
		re:            regexp.MustCompile(`\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D ]?\b`),
		gates:         []string{"nino", "national insurance"},
		validate:      ninoValidate,
		contextWords:  []string{"nino", "national insurance"},
		contextRadius: 60,
	},
	{
		// Indian PAN (Permanent Account Number). Case-sensitive.
		name: "in_pan", certain: true, class: classPII,
		re:            regexp.MustCompile(`\b[A-Z]{5}\d{4}[A-Z]\b`),
		gates:         []string{"pan"},
		validate:      panValidate,
		contextWords:  []string{"pan"},
		contextRadius: 60,
	},
	{
		// RFC-5322-lite email address. No checksum exists (contract
		// §4.2: "none") — off-by-default lives one layer up in the
		// [guard.prompt] mode config (a separate workstream); this row
		// only needs to detect the shape correctly and cheaply.
		name: "email", certain: true, class: classPII,
		re:    regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`),
		gates: []string{"@"},
	},
}

// init assigns each typedDetectors row its stable slice index (see the
// idx field's doc comment) once, at package load, and derives the
// secret-only ActiveDetectors set DetectSecrets scans with.
func init() {
	for i := range typedDetectors {
		typedDetectors[i].idx = i
	}
	secretOnlyDetectors = make(map[string]bool, len(typedDetectors)+1)
	for i := range typedDetectors {
		if typedDetectors[i].class == classSecret {
			secretOnlyDetectors[typedDetectors[i].name] = true
		}
	}
	// "entropy" has no table row of its own (it is emitted dynamically by
	// entropyFindings) but is CLASS-SECRET by definition — DetectorClass
	// says so — so it must be in the active set or DetectSecrets would
	// silently lose the heuristic half of its answer.
	secretOnlyDetectors["entropy"] = true
}

// secretOnlyDetectors is the detectOptions.active set covering exactly the
// class-secret rows of typedDetectors plus "entropy" — the ActiveDetectors
// mechanism (BLOCK-2) reused as a PERFORMANCE gate for the proxy egress hot
// path (MHC-3, codebase audit 2026-09-16).
//
// Before this, DetectSecrets ran the FULL table — the numeric pre-pass, the
// Luhn/ISO/checksum validators, the fenced-code suppression walk — over every
// egress body and then threw every PII finding away in filterFindings. On the
// audit's 128 KB PII-dense body that cost ~11.6 ms/op against the §17.9 8 ms
// budget, all of it work whose result was discarded by construction.
//
// Built once in init() from the table itself, never hand-listed: a new
// class-secret row joins it automatically, and a new PII row stays out of it
// automatically. Never mutated after init.
var secretOnlyDetectors map[string]bool

// typedMatch is one located finding with its span on the SHIELDED
// input (spans are internal — shielding changes offsets, so they are
// never exposed to callers).
type typedMatch struct {
	start, end int
	finding    TypedFinding
}

// DetectorClass returns the class ("secret" or "pii", the
// ClassSecret/ClassPII constants) of a detector NAME from
// DetectorNames()'s vocabulary, and whether the name was recognized at
// all. Added for the `observer guard prompt allow <detector>` CLI seam
// (Part B item 4): it needs to know whether a detector name maps to
// the R-172 (secret) or R-190 (PII) rule row before delegating to the
// existing rule-scoped guard_approvals mechanism (guard approve).
// "entropy" (the dynamically-emitted heuristic finding, no table row
// of its own) is ClassSecret — it is only ever produced by
// DetectSecrets' context-gated heuristic.
func DetectorClass(name string) (class string, ok bool) {
	if name == "entropy" {
		return ClassSecret, true
	}
	for _, d := range typedDetectors {
		if d.name == name {
			return d.class, true
		}
	}
	return "", false
}

// DetectorNames returns the stable ids of every row in the typed
// detection table, plus "entropy" (the context-gated heuristic finding
// type, which is emitted dynamically and has no table row of its own).
// This is the full detector vocabulary [guard.prompt.detectors] keys
// are allowed to name — internal/config's validateGuard uses this
// instead of hand-duplicating the list (F5, round-2 review;
// internal/config already imports internal/scrub for
// scrub.ValidatePatterns, so this closes a real drift source rather
// than opening a new dependency).
func DetectorNames() []string {
	names := make([]string, 0, len(typedDetectors)+1)
	for _, d := range typedDetectors {
		names = append(names, d.name)
	}
	names = append(names, "entropy")
	return names
}

// DetectSecrets runs the typed detector table plus the
// context-gated entropy heuristic over v and returns the SECRET-CLASS
// findings only, in span order. Fernet `encrypted_content` values are
// shielded first (the same mechanism Scrubber.String uses) so OpenAI
// ZDR reasoning blobs can't false-positive.
//
// PII-classified rows (credit_card, us_ssn, email, ...) are DELIBERATELY
// excluded here (round-2 review B2): the same typedDetectors table now
// carries both classes, and every EXISTING consumer of DetectSecrets/
// CertainSecretTypes/MaskSecrets — the proxy egress scanner
// (internal/guard/proxyguard.go), the R-172 shell-arg rule
// (internal/guard/guard.go), the Plane-A admission gate
// (internal/obs/admissionsvc.go, cmd/observer/obs_wire.go), and the
// process-argv masker (cmd/observer/processobs.go) — treats
// "detected" as "this is a leaked credential": egress-deny, mask,
// admission-block. None of them should ever flag/mask/deny a
// developer's own email address or phone number as if it were a
// secret. The class-aware superset lives at DetectPromptFindings,
// whose ONLY caller is the prompt-submit intervention boundary
// (internal/guard/promptguard.go's BuildPromptFindings).
//
// Since MHC-3 (codebase audit 2026-09-16) the PII rows are not merely
// filtered out of the RESULT, they are never SCANNED: the pass runs with
// secretOnlyDetectors as its ActiveDetectors set. What changes is that the
// numeric pre-pass, the Luhn/ISO/checksum validators and the PII
// suppression walk no longer run on the proxy egress hot path for work
// that was discarded by construction. The trailing filterFindings call is
// kept as a cheap structural backstop: if a future row is misclassified
// into the active set, the contract ("secret-class findings only") still
// holds at the boundary.
//
// EQUIVALENCE, AND ITS ONE HONEST RESIDUAL. The returned findings are
// equivalent to the old scan-everything-then-filter behavior over the
// pinned corpus (TestSecretOnlyScanMatchesFullTableScan) and over the
// fuzz corpus (FuzzSecretOnlyScanMatchesFullTable) — not proven identical
// for ALL inputs, and the claim is deliberately no stronger than that.
// findTypedShielded resolves span OVERLAPS before the class filter runs,
// so under the old code a PII match starting before an overlapping secret
// match could suppress that secret; narrowing the active set removes the
// PII match and the secret then survives. Every such divergence can only
// ADD a secret finding the old path swallowed, never drop one — the
// failure direction is toward detecting more, which is the safe one for
// an egress scan — and no input exhibiting it has been found. If one is
// ever found, it is a bug in the OLD behavior.
func DetectSecrets(v string) []TypedFinding {
	return filterFindings(findTyped(v), classPII, true)
}

// DetectPromptFindings runs the SAME typed detector table as
// DetectSecrets but returns BOTH secret- and PII-classified findings —
// the ONE class-aware entry point the prompt-submit intervention
// feature reads (contract §4.4, round-2 review B2). Every other
// consumer of this package's detection surface must keep using the
// secret-only DetectSecrets/CertainSecretTypes/MaskSecrets.
//
// opts threads the operator's [guard.prompt] knobs through (F7,
// round-2 review) instead of the fixed defaults every other caller
// gets — see PromptDetectOptions.
//
// truncated reports whether the body exceeded MaxRawInputBytes, in
// which case PII detection silently ran over NOTHING for this call
// (findTypedShielded's own piiBounded gate — the SECRET half of the
// table still scanned the full body regardless of size, see that
// function's doc comment). Before FIX-2 (round-2 re-review) this was
// invisible to every caller: a prompt just over the bound forwarded
// with no PII findings and no signal that detection had been skipped
// rather than genuinely come back clean. The caller (guard.
// EvaluatePrompt) degrades an oversize prompt to warn (or block under
// mode=block) with an explicit reason instead of silently treating
// "too big to scan" the same as "scanned clean".
func DetectPromptFindings(v string, opts PromptDetectOptions) (findings []TypedFinding, truncated bool) {
	shielded, _ := shieldFernetEncryptedContent(v)
	matches := findTypedShielded(shielded, opts.resolve())
	out := make([]TypedFinding, 0, len(matches))
	for _, m := range matches {
		out = append(out, m.finding)
	}
	return out, len(shielded) > MaxRawInputBytes
}

// filterFindings converts matches to findings, optionally dropping
// every row whose Class equals excludeClass (exclude=true) — the
// shared plumbing behind DetectSecrets' PII exclusion.
func filterFindings(matches []typedMatch, excludeClass string, exclude bool) []TypedFinding {
	out := make([]TypedFinding, 0, len(matches))
	for _, m := range matches {
		if exclude && m.finding.Class == excludeClass {
			continue
		}
		out = append(out, m.finding)
	}
	return out
}

// excludeClassMatches drops every typedMatch whose finding Class
// equals excludeClass, preserving order — MaskSecrets' PII exclusion
// (round-2 review B2), applied to the match slice itself (not just the
// returned findings) so a PII span is never a masking candidate either.
func excludeClassMatches(matches []typedMatch, excludeClass string) []typedMatch {
	out := matches[:0]
	for _, m := range matches {
		if m.finding.Class == excludeClass {
			continue
		}
		out = append(out, m)
	}
	return out
}

// CertainSecretTypes returns the type names of pattern-certain,
// SECRET-CLASS findings in v, deduplicated, in first-seen order (built
// on the now secret-only DetectSecrets — round-2 review B2: a
// commit-trailer email or a phone number in a shell arg must never
// trip the R-172 secret rule). This is the injectable detector for the
// R-172 shell-arg rule (policy.Config.SecretDetect) — entropy hits are
// excluded there by design: random-looking tokens are routine in shell
// args (commit SHAs, cache keys) and the heuristic would drown the
// rule.
func CertainSecretTypes(v string) []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range DetectSecrets(v) {
		if !f.Certain || seen[f.Type] {
			continue
		}
		seen[f.Type] = true
		out = append(out, f.Type)
	}
	return out
}

// MaskSecrets rewrites v with each finding for which shouldMask
// returns true replaced by "[REDACTED:<type>]", and returns the
// rewritten string plus ALL SECRET-CLASS findings (masked or not) — PII
// rows are excluded here too (round-2 review B2), the same secret-only
// posture as DetectSecrets: this is the egress-scan masking primitive,
// and a caller's shouldMask predicate should never even see a PII
// finding to accidentally mask/report as a secret. A nil shouldMask
// masks nothing (pure detection). Shield-aware like DetectSecrets:
// encrypted_content values survive byte-identical.
func MaskSecrets(v string, shouldMask func(TypedFinding) bool) (string, []TypedFinding) {
	shielded, restorations := shieldFernetEncryptedContent(v)
	matches := excludeClassMatches(findTypedShielded(shielded, secretOnlyDetectOptions()), classPII)
	findings := make([]TypedFinding, 0, len(matches))
	for _, m := range matches {
		findings = append(findings, m.finding)
	}
	if shouldMask == nil {
		return v, findings
	}
	var b strings.Builder
	b.Grow(len(shielded))
	last := 0
	masked := false
	for _, m := range matches {
		if !shouldMask(m.finding) {
			continue
		}
		b.WriteString(shielded[last:m.start])
		b.WriteString("[REDACTED:" + m.finding.Type + "]")
		last = m.end
		masked = true
	}
	if !masked {
		return v, findings
	}
	b.WriteString(shielded[last:])
	return restoreShielded(b.String(), restorations), findings
}

// findTyped shields v and locates SECRET-CLASS findings on the shielded
// form using the package's built-in caps (the historical maxPIIFindings
// cap and unconditional code-context suppression) restricted to the
// secret-only detector set — DetectPromptFindings is the only caller that
// threads its own PromptDetectOptions through instead (F7, round-2
// review), and it is the only one that wants the PII half at all.
func findTyped(v string) []typedMatch {
	shielded, _ := shieldFernetEncryptedContent(v)
	return findTypedShielded(shielded, secretOnlyDetectOptions())
}

// secretOnlyDetectOptions is defaultDetectOptions restricted to
// secretOnlyDetectors — the options every SECRET-ONLY entry point
// (DetectSecrets/CertainSecretTypes via findTyped, MaskSecrets) scans
// with (MHC-3). The caps are unchanged; only the detector set narrows,
// and it narrows to exactly the rows whose findings those entry points
// keep, so the returned secret findings match the full-table scan's over
// the pinned and fuzz corpora — see DetectSecrets' "EQUIVALENCE, AND ITS
// ONE HONEST RESIDUAL" note for why that is not stated as an identity for
// all inputs.
func secretOnlyDetectOptions() detectOptions {
	o := defaultDetectOptions()
	o.active = secretOnlyDetectors
	return o
}

// anyNumericCandidateActive reports whether the active set (nil = every
// detector) admits at least one numericCandidate row. When it does not —
// the secret-only case, since all five digit-shaped rows are PII — the
// shared numeric-run pre-pass has nothing to feed and its whole
// candidate-collection scan is skipped, which is where most of the
// PII-dense hot-path cost lived.
func anyNumericCandidateActive(active map[string]bool) bool {
	for i := range typedDetectors {
		if !typedDetectors[i].numericCandidate {
			continue
		}
		if active == nil || active[typedDetectors[i].name] {
			return true
		}
	}
	return false
}

// detectOptions configures one findTypedShielded pass. defaultDetectOptions
// reproduces the historical unconditional behavior (every caller except
// the prompt-submit path uses it); PromptDetectOptions.resolve produces
// the operator-configured variant.
type detectOptions struct {
	maxFindings    int
	suppressInCode bool
	// active, when non-nil, restricts detection to these detector ids
	// (BLOCK-2, round-2 re-review — see PromptDetectOptions.ActiveDetectors).
	// nil means unrestricted: every caller except the prompt-submit path
	// keeps that behavior.
	active map[string]bool
}

// maxPIIFindings is the built-in PII-finding cap (§4.5 hard bound) used
// whenever a caller doesn't override it. Secret findings are never
// capped — the cap exists so a body that is mostly a giant CSV of ids
// doesn't turn every request into a wall of PII interruptions.
const maxPIIFindings = 64

func defaultDetectOptions() detectOptions {
	return detectOptions{maxFindings: maxPIIFindings, suppressInCode: true}
}

// PromptDetectOptions is the [guard.prompt]-shaped configuration for
// DetectPromptFindings (F7, round-2 review): MaxFindings threads
// [guard.prompt].max_findings through instead of the fixed
// maxPIIFindings constant every other caller uses, and SuppressInCode
// makes the (precomputed, see detectState) code-context suppression
// actually togglable — previously a dead knob, since PII rows applied
// it unconditionally regardless of what the config said.
type PromptDetectOptions struct {
	// MaxFindings caps a SINGLE DETECTOR's PII-classified findings for
	// this scan (round-2 re-review BLOCK-2: the cap used to be one
	// budget SHARED across every PII detector, consumed in table
	// order — 64 mode-"off" email hits could exhaust it before the
	// numeric pre-pass (credit_card/us_ssn) ever ran, silently
	// swallowing a live PAN+SSN pass with no interrupt. The cap is now
	// per-detector: each detector id gets its own maxFindings budget,
	// so an unrelated detector's volume can never starve another's).
	// <= 0 falls back to the built-in default (maxPIIFindings).
	MaxFindings int
	// SuppressInCode gates fenced/indented/inline-code/comment-line
	// suppression for PII findings. Secrets are NEVER suppressed this
	// way regardless of this flag (contract §4.3 — a real key pasted
	// into a fixture is still a real key).
	SuppressInCode bool
	// ActiveDetectors, when non-nil, restricts scanning to these
	// detector ids (round-2 re-review BLOCK-2, other half of the fix):
	// a detector whose [guard.prompt] effective mode resolves to "off"
	// must never be SCANNED at all, not merely filtered out after the
	// fact — scanning it anyway wastes the regex/numeric-run work AND
	// lets it consume its own per-detector cap for nothing. Callers
	// build this from scrub.DetectorNames() filtered to the
	// non-off ids (see guard.BuildPromptFindings). A nil map means "no
	// restriction" — every known detector runs, the pre-Block-2
	// behavior every other resolve() caller keeps.
	ActiveDetectors map[string]bool
}

func (o PromptDetectOptions) resolve() detectOptions {
	max := o.MaxFindings
	if max <= 0 {
		max = maxPIIFindings
	}
	return detectOptions{maxFindings: max, suppressInCode: o.SuppressInCode, active: o.ActiveDetectors}
}

// findTypedShielded walks the detector table over an already-shielded
// input, applies the entropy heuristic, sorts by span and drops
// overlaps (earlier table rows win — the table order tie-break).
// Lowercase rows match against the ASCII-lowered copy (computed once);
// values always extract from the original, case preserved.
//
// Bounding (round-2 review B3): the §4.5 MaxRawInputBytes bound
// applies ONLY to the PII detection surface — the gated/anchored
// PII-classified table rows (iban, uk_nino, in_pan, email) and the
// numeric-run pre-pass. The SECRET half of this table (this function's
// original purpose, long before the PII rows landed) always scans the
// FULL body regardless of size: a padded body that pushes a real key
// past the 1 MiB mark must never silently bypass secret detection —
// that would be a trivial bypass of the pre-existing egress scan.
func findTypedShielded(shielded string, opts detectOptions) []typedMatch {
	lower := asciiLower(shielded)
	state := newDetectState(shielded, opts)
	piiBounded := len(shielded) <= MaxRawInputBytes

	var all []typedMatch
	for i := range typedDetectors {
		d := &typedDetectors[i]
		if opts.active != nil && !opts.active[d.name] {
			// BLOCK-2 (round-2 re-review): an off-mode detector is
			// never scanned — not merely filtered afterward — so its
			// hits can neither cost regex time nor consume ANY
			// detector's per-detector cap.
			continue
		}
		if d.numericCandidate {
			// Handled below by the shared numeric-run pre-pass —
			// these rows have no usable literal gate (§4.5).
			continue
		}
		if d.class == classPII && !piiBounded {
			continue
		}
		input := shielded
		if d.lowercase {
			input = lower
		}
		if d.anchored {
			all = append(all, anchoredMatches(d, input, shielded, lower, state)...)
			continue
		}
		if !gatesOpen(lower, d.gates) {
			continue
		}
		for _, idx := range d.re.FindAllStringSubmatchIndex(input, -1) {
			if m, ok := detectorMatch(d, shielded, lower, idx, 0, state); ok {
				all = append(all, m)
			}
		}
	}
	// The numeric pre-pass exists solely for the five digit-shaped PII rows
	// (§4.5). When none of them is active — every secret-only caller, which
	// is the proxy egress hot path — skip the whole candidate-collection
	// scan, not just the per-row regex fan-out numericPrepassMatches already
	// skips (MHC-3).
	if piiBounded && anyNumericCandidateActive(opts.active) {
		all = append(all, numericPrepassMatches(shielded, lower, state)...)
	}
	if opts.active == nil || opts.active["entropy"] {
		all = append(all, entropyFindings(shielded, lower)...)
	}
	// Stable sort: span order; ties keep table order (append order).
	// The maxFindings cap is now applied INLINE, inside detectorMatch,
	// as each PII candidate is discovered (round-2 review B4) — not as
	// a post-hoc filter here — so the expensive suppression checks
	// (isTestValue/inCodeContext) short-circuit for a candidate once
	// the cap is already reached instead of running on every candidate
	// and discarding the overflow afterward.
	sort.SliceStable(all, func(i, j int) bool { return all[i].start < all[j].start })
	out := all[:0]
	lastEnd := -1
	for _, m := range all {
		if m.start < lastEnd {
			continue // overlap: the earlier (certain) finding wins
		}
		out = append(out, m)
		lastEnd = m.end
	}
	return out
}

// asciiLower lowers ASCII letters only — length-preserving by
// construction (unlike strings.ToLower, whose Unicode folding can
// change byte length), so spans found on the lowered copy map 1:1
// onto the original. Returns the input unchanged (no allocation) when
// nothing needs lowering.
func asciiLower(s string) string {
	hasUpper := false
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			hasUpper = true
			break
		}
	}
	if !hasUpper {
		return s
	}
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if c := b[i]; c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// gatesOpen reports whether any gate literal appears in the lowercased
// input (no gates = always open).
func gatesOpen(lower string, gates []string) bool {
	if len(gates) == 0 {
		return true
	}
	for _, g := range gates {
		if strings.Contains(lower, g) {
			return true
		}
	}
	return false
}

// anchoredMatches runs one anchored detector at every gate-literal
// occurrence: the \A-prefixed regex attempts only from the anchor
// position, so cost is O(occurrences × match length) instead of one
// O(body) NFA scan per detector — the §17.9 fix for keyword
// patterns whose alternations defeat RE2's literal-prefix fast path.
func anchoredMatches(d *typedDetector, input, shielded, lower string, state *detectState) []typedMatch {
	var out []typedMatch
	for _, gate := range d.gates {
		from := 0
		for {
			i := strings.Index(lower[from:], gate)
			if i < 0 {
				break
			}
			pos := from + i
			from = pos + len(gate)
			start := pos - d.anchorBack
			if d.backScanKey {
				start = backScanQuotedKey(lower, pos)
			}
			if start < 0 {
				continue
			}
			idx := d.re.FindStringSubmatchIndex(input[start:])
			if idx == nil {
				continue
			}
			if m, ok := detectorMatch(d, shielded, lower, idx, start, state); ok {
				out = append(out, m)
			}
		}
	}
	return out
}

// backScanQuotedKey walks back over [a-z_] from a keyword occurrence
// to the opening quote of a JSON key, returning the quote's offset
// (-1 when the shape doesn't hold within 64 bytes — keys are short).
func backScanQuotedKey(lower string, pos int) int {
	for i := pos - 1; i >= 0 && pos-i <= 64; i-- {
		c := lower[i]
		if c == '"' {
			return i
		}
		if (c < 'a' || c > 'z') && c != '_' {
			return -1
		}
	}
	return -1
}

// detectState carries the per-scan precomputed data and running
// counters detectorMatch consults for the PII-only controls (round-2
// review B4). fences precomputes the fenced-code-block boundary list
// ONCE per scan instead of the old insideFencedCodeBlock's O(n)
// rescan-from-zero on EVERY PII candidate (measured 271ms/op on a
// 128KB body against the 8ms budget); maxFindings/piiSeen let the
// maxPIIFindings-style cap short-circuit the expensive suppression
// checks (isTestValue/inCodeContext) for a PII candidate once the cap
// is already reached, instead of running every check on every
// candidate and discarding the overflow only afterward;
// suppressInCode threads [guard.prompt].suppress_in_code (F7 —
// previously a dead knob applied unconditionally regardless of the
// config value).
type detectState struct {
	fences      []int
	maxFindings int
	// piiSeenByDetector counts findings PER DETECTOR (indexed by
	// typedDetector.idx), not one shared total (round-2 re-review
	// BLOCK-2): the cap used to be a single budget consumed in table
	// order, so a high-volume off-mode detector (or simply an earlier
	// one) could exhaust it before a later detector's own candidates
	// were ever tried. Each detector now gets its own independent
	// maxFindings budget. A plain []int indexed by idx, not a
	// map[string]int — the PII-dense §17.9 benchmark regressed ~30%
	// when this was a map (hashing/lookup cost on a hot path visited
	// thousands of times per scan); a fixed-size slice has neither.
	piiSeenByDetector []int
	suppressInCode    bool
	active            map[string]bool
}

// newDetectState precomputes state for one findTypedShielded pass.
func newDetectState(body string, opts detectOptions) *detectState {
	return &detectState{
		fences:            fencePositions(body),
		maxFindings:       opts.maxFindings,
		piiSeenByDetector: make([]int, len(typedDetectors)),
		suppressInCode:    opts.suppressInCode,
		active:            opts.active,
	}
}

// piiCapped reports whether the detector at idx has already reached
// ITS OWN PII-finding cap — a maxFindings <= 0 means "uncapped"
// (defensive; every real caller resolves a positive value, see
// defaultDetectOptions/PromptDetectOptions.resolve). Per-detector, not
// shared (BLOCK-2).
func (s *detectState) piiCapped(idx int) bool {
	return s.maxFindings > 0 && s.piiSeenByDetector[idx] >= s.maxFindings
}

// fencePositions returns every fence marker's START byte offset in
// body, in ascending order — the one-pass replacement for
// insideFencedCodeBlock's former per-candidate rescan-from-zero.
//
// A fence marker is any MAXIMAL run of three or more backticks OR
// three or more tildes (nit, round-2 re-review: the original only
// matched a literal "```" and advanced past exactly three bytes, so a
// 4- or 6-backtick fence — Markdown's own escape for code that itself
// contains a triple-backtick run — produced TWO or more toggle events
// from what is structurally ONE fence, silently flipping the
// inside/outside parity for everything after it; `~~~` fences, the
// other CommonMark delimiter, were not recognized at all). This is
// still a lightweight heuristic, not a full CommonMark parser (it
// doesn't require the closing run to match the opening character or
// length) — but treating one run as one toggle, and recognizing both
// delimiter families, is what §4.3 control 2 needs: a fixture/example
// value inside either fence style must not interrupt.
func fencePositions(body string) []int {
	var fences []int
	idx := 0
	for idx < len(body) {
		i := strings.IndexAny(body[idx:], "`~")
		if i < 0 {
			break
		}
		start := idx + i
		ch := body[start]
		end := start
		for end < len(body) && body[end] == ch {
			end++
		}
		if end-start >= 3 {
			fences = append(fences, start)
		}
		idx = end
	}
	return fences
}

// insideFencedCodeBlock reports whether pos sits inside a fenced code
// block, using the precomputed fence position list: count of fence
// occurrences whose start is strictly before pos — an odd count means
// pos sits between an opening and a not-yet-closed closing fence
// (byte-identical semantics to the original per-call implementation,
// now O(log n) via binary search instead of an O(n) rescan from zero).
func (s *detectState) insideFencedCodeBlock(pos int) bool {
	n := sort.Search(len(s.fences), func(i int) bool { return s.fences[i] >= pos })
	return n%2 == 1
}

// inCodeContext reports whether the span [start,end) in body sits
// inside a fenced code block (precomputed, see insideFencedCodeBlock),
// an indented 4-space/tab block, an inline-code span (`...`), or a
// comment line — the .env.example / fixture / test-data case (§4.3
// item 2). Secret findings never consult this: a real key pasted into
// a fence is still a real key.
func (s *detectState) inCodeContext(body string, start, end int) bool {
	if s.insideFencedCodeBlock(start) {
		return true
	}
	lineStart, lineEnd := lineBounds(body, start)
	line := body[lineStart:lineEnd]
	if strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "\t") {
		return true
	}
	if commentLineRE.MatchString(line) {
		return true
	}
	relStart, relEnd := start-lineStart, end-lineStart
	if relStart < 0 || relEnd > len(line) {
		return false
	}
	return insideInlineCodeSpan(line, relStart, relEnd)
}

// detectorMatch shapes one regex match (span index slice + base
// offset) into a typedMatch, applying every additive false-positive
// control a row declares: the numeric-prepass full-body boundary
// re-check, the reject-preceding-byte rule, the checksum/structural
// validator, the ±radius context-word requirement, and (PII rows only)
// the cap short-circuit plus test-value + code-context suppression
// (§4.2, §4.3). ok=false when the value group is absent or any control
// rejects the candidate.
func detectorMatch(d *typedDetector, shielded, lower string, idx []int, base int, state *detectState) (typedMatch, bool) {
	g := d.valueGroup * 2
	if g+1 >= len(idx) || idx[g] < 0 {
		return typedMatch{}, false
	}
	start, end := base+idx[g], base+idx[g+1]
	value := shielded[start:end]

	if d.numericCandidate && !fullBodyWordBoundary(shielded, start, end) {
		return typedMatch{}, false
	}
	if d.rejectPrecedingBytes != "" && start > 0 && strings.IndexByte(d.rejectPrecedingBytes, shielded[start-1]) >= 0 {
		return typedMatch{}, false
	}
	if d.validate != nil && !d.validate(value) {
		return typedMatch{}, false
	}
	if len(d.contextWords) > 0 && !hasContextWord(lower, start, end, d.contextRadius, d.contextWords) {
		return typedMatch{}, false
	}
	if d.class == classPII {
		// Cap check FIRST (round-2 review B4, now per-detector per
		// BLOCK-2): once THIS detector's own cap is already reached,
		// skip the expensive suppression checks entirely for every
		// subsequent candidate of the SAME detector — a different
		// detector's volume never affects this one's budget.
		if state.piiCapped(d.idx) {
			return typedMatch{}, false
		}
		if isTestValue(value) {
			return typedMatch{}, false
		}
		if state.suppressInCode && state.inCodeContext(shielded, start, end) {
			return typedMatch{}, false
		}
		state.piiSeenByDetector[d.idx]++
	}

	return typedMatch{
		start: start,
		end:   end,
		finding: TypedFinding{
			Type:    d.name,
			Certain: d.certain,
			Value:   value,
			Class:   d.class,
			Start:   start,
			End:     end,
		},
	}, true
}

// isWordByte reports ASCII "word" membership ([0-9A-Za-z_]) — the same
// class regexp's \b tests against, used here to re-check a numeric-
// prepass candidate's edges against the FULL body (see
// fullBodyWordBoundary).
func isWordByte(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

// fullBodyWordBoundary re-checks a numeric-run-pre-pass candidate's
// edges against the FULL body rather than its isolated numeric-run
// substring. The pre-pass alphabet (digits + separators) stops at the
// first byte outside it — including a LETTER, which is still part of
// the same alphanumeric token (e.g. a 16-digit run immediately followed
// by a letter is a longer identifier, not a card number). A \b anchored
// only within the isolated span can't see that letter and would
// wrongly treat the span's own edge as a boundary. Contract §4.3 item
// 4: "must not match inside a longer alphanumeric run."
func fullBodyWordBoundary(shielded string, start, end int) bool {
	if start > 0 && isWordByte(shielded[start-1]) && isWordByte(shielded[start]) {
		return false
	}
	if end < len(shielded) && isWordByte(shielded[end-1]) && isWordByte(shielded[end]) {
		return false
	}
	return true
}

// hasContextWord reports whether any of words (lowercase literals)
// appears in lower within radius bytes of [start,end), clamped to the
// body's bounds — the ±60-byte context-word requirement for uk_nino,
// in_aadhaar, in_pan and phone_nanp (§4.2). A finding whose required
// context word is absent is DROPPED, not merely marked uncertain.
func hasContextWord(lower string, start, end, radius int, words []string) bool {
	lo := start - radius
	if lo < 0 {
		lo = 0
	}
	hi := end + radius
	if hi > len(lower) {
		hi = len(lower)
	}
	window := lower[lo:hi]
	for _, w := range words {
		if strings.Contains(window, w) {
			return true
		}
	}
	return false
}

// numericRunMinLen is the minimum length of a candidate digit/separator
// run collected by numericRuns (§4.5).
const numericRunMinLen = 9

// maxNumericRuns caps the number of candidate spans numericRuns yields
// per body (§4.5 hard bound).
const maxNumericRuns = 4096

// isNumericRunByte reports membership in the digit/separator alphabet
// scanned for the shared numeric-run pre-pass: plain digits plus the
// separators the five digit-shaped detectors' own patterns use
// (hyphen, space, dot, parens for phone_nanp, plus for phone_e164).
func isNumericRunByte(c byte) bool {
	switch c {
	case '-', ' ', '.', '(', ')', '+':
		return true
	}
	return c >= '0' && c <= '9'
}

// numericRuns yields the maximal isNumericRunByte runs of length ≥
// numericRunMinLen in s as [start,end) spans, capped at maxNumericRuns.
// A manual scan — the base64Runs precedent (§4.5): the digit-shaped
// detectors (credit_card, us_ssn, in_aadhaar, phone_nanp, phone_e164)
// have no usable literal gate, so they share ONE pass over the body
// instead of five independent full-body regex passes.
func numericRuns(s string, yield func(start, end int)) {
	runStart := -1
	count := 0
	for i := 0; i <= len(s); i++ {
		if count >= maxNumericRuns {
			return
		}
		if i < len(s) && isNumericRunByte(s[i]) {
			if runStart < 0 {
				runStart = i
			}
			continue
		}
		if runStart >= 0 && i-runStart >= numericRunMinLen {
			yield(runStart, i)
			count++
		}
		runStart = -1
	}
}

// numericPrepassMatches runs every numericCandidate detector row against
// the shared numericRuns candidate spans — one manual scan, N cheap
// regex+validate attempts per candidate instead of N full-body regex
// passes (§4.5).
func numericPrepassMatches(shielded, lower string, state *detectState) []typedMatch {
	var out []typedMatch
	numericRuns(shielded, func(rs, reEnd int) {
		span := shielded[rs:reEnd]
		for i := range typedDetectors {
			d := &typedDetectors[i]
			if !d.numericCandidate {
				continue
			}
			if state.active != nil && !state.active[d.name] {
				// BLOCK-2: an off-mode numeric detector (e.g.
				// phone_nanp configured "off") is skipped entirely —
				// never attempted, never touches any cap.
				continue
			}
			if state.piiCapped(d.idx) {
				// Round-2 review B4 follow-through, now per-detector
				// (BLOCK-2): once THIS detector's own cap is already
				// reached, don't even ATTEMPT its regex against this
				// (or any later) candidate span — a digit/phone-dense
				// body otherwise pays that regex fan-out cost for
				// every remaining candidate only to have detectorMatch
				// discard it at the same cap check. A DIFFERENT
				// detector (credit_card, say, while us_ssn is capped)
				// still gets its own attempt.
				continue
			}
			for _, idx := range d.re.FindAllStringSubmatchIndex(span, -1) {
				if m, ok := detectorMatch(d, shielded, lower, idx, rs, state); ok {
					out = append(out, m)
				}
			}
		}
	})
	return out
}

// Entropy heuristic (spec §8.2: "high-entropy heuristic gated by
// length+context to control FP rate"). A candidate token is examined
// ONLY inside a window around a secret-context word — never over the
// whole body — which both controls false positives (a git SHA in
// ordinary output has no secret context) and keeps the scan cheap
// (windows are rare and bounded).
const (
	// entropyWindow is the half-width of the context window scanned
	// around each context-word occurrence.
	entropyWindow = 200
	// entropyMinLen is the candidate length floor.
	entropyMinLen = 32
	// entropyMinBits is the Shannon entropy floor in bits/char.
	// Mixed-case base64 secrets sit near 5; hex SHAs near 3.9 — the
	// 4.2 floor plus the mixed-class requirement below keeps hex
	// digests and lowercase identifiers out.
	entropyMinBits = 4.2
)

// entropyContextWords are the lowercase context literals that open an
// entropy window. Table-driven; extend here.
var entropyContextWords = []string{
	"secret", "passwd", "password", "credential", "api_key", "api-key",
	"apikey", "access_key", "private_key", "bearer", "auth",
}

// isBase64Byte reports membership in the candidate alphabet
// (base64 + url-safe variants).
func isBase64Byte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '+' || c == '/' || c == '_' || c == '-'
}

// base64Runs yields the maximal alphabet runs of length ≥
// entropyMinLen in s as [start,end) spans. A manual scan — the
// equivalent counted-repeat regex ran at ~16MB/s on the NFA path and
// blew the §17.9 budget on context-word-dense bodies.
func base64Runs(s string, yield func(start, end int)) {
	runStart := -1
	for i := 0; i <= len(s); i++ {
		if i < len(s) && isBase64Byte(s[i]) {
			if runStart < 0 {
				runStart = i
			}
			continue
		}
		if runStart >= 0 && i-runStart >= entropyMinLen {
			yield(runStart, i)
		}
		runStart = -1
	}
}

// entropyFindings scans the context windows for high-entropy
// candidates. Findings are Certain=false — spec §8.2 keeps them out of
// mask/deny decisions by default.
//
// Window mechanics (§17.9): all context-word hits are collected
// first, their ±entropyWindow spans MERGED, and the candidate regex
// runs once per merged region — a body dense with context words
// (every "no secrets here" line opens one) degrades to a single
// full-body pass of a cheap character-class regex instead of
// thousands of overlapping window scans.
func entropyFindings(shielded, lower string) []typedMatch {
	regions := entropyRegions(lower, len(shielded))
	if len(regions) == 0 {
		return nil
	}
	var out []typedMatch
	for _, r := range regions {
		base64Runs(shielded[r[0]:r[1]], func(s, e int) {
			start, end := r[0]+s, r[0]+e
			tok := shielded[start:end]
			if !mixedClasses(tok) || shannonBits(tok) < entropyMinBits {
				return
			}
			out = append(out, typedMatch{
				start: start,
				end:   end,
				finding: TypedFinding{
					Type: "entropy", Certain: false, Value: tok,
					Class: classSecret, Start: start, End: end,
				},
			})
		})
	}
	return out
}

// entropyRegions returns the merged, sorted ±entropyWindow spans
// around every context-word occurrence.
func entropyRegions(lower string, n int) [][2]int {
	var spans [][2]int
	for _, w := range entropyContextWords {
		from := 0
		for {
			i := strings.Index(lower[from:], w)
			if i < 0 {
				break
			}
			at := from + i
			lo, hi := at-entropyWindow, at+entropyWindow
			if lo < 0 {
				lo = 0
			}
			if hi > n {
				hi = n
			}
			spans = append(spans, [2]int{lo, hi})
			from = at + len(w)
		}
	}
	if len(spans) == 0 {
		return nil
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i][0] < spans[j][0] })
	merged := spans[:1]
	for _, s := range spans[1:] {
		last := &merged[len(merged)-1]
		if s[0] <= last[1] {
			if s[1] > last[1] {
				last[1] = s[1]
			}
			continue
		}
		merged = append(merged, s)
	}
	return merged
}

// mixedClasses requires upper + lower + digit — the cheap pre-grade
// that rejects hex digests (no uppercase) and ALL-CAPS identifiers.
func mixedClasses(s string) bool {
	var hasUpper, hasLower, hasDigit bool
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		}
	}
	return hasUpper && hasLower && hasDigit
}

// shannonBits computes the Shannon entropy of s in bits per byte.
func shannonBits(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var bits float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		bits -= p * math.Log2(p)
	}
	return bits
}
