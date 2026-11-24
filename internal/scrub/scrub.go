package scrub

import (
	"encoding/json"
	"regexp"
	"strings"
)

// MaxRawInputBytes is the cap applied to raw_tool_input after scrubbing.
//
// v1.6.29 raised this from the spec §8.2 default of 2 KiB to 1 MiB so
// the dashboard's on-demand full-text endpoint can serve the operator
// the actual content they prompted with or the tool result they want
// to copy. The 1 MiB ceiling is a defensive belt against pathological
// rows (e.g. a multi-MB paste-bin dump) and matches internal/contentcap.
// Anything under the cap flows through untruncated; oversized payloads
// get the trailing "…[truncated]" marker so callers can tell.
const MaxRawInputBytes = 1 << 20 // 1 MiB

// Redacted is the replacement string substituted in place of secret values.
const Redacted = "[REDACTED]"

// Scrubber applies a list of compiled redaction patterns to strings.
// The zero value is unusable — call New or NewWithExtra.
type Scrubber struct {
	patterns []pattern
}

type pattern struct {
	re      *regexp.Regexp
	replace string // If empty, the full match is replaced with Redacted.
	// If replace uses references like $1[REDACTED]$2, callers must include
	// the full template.
	// validate, when set, is a structural check on the whole match: a
	// match it rejects is left in place (the JWT row, whose regex only
	// finds candidates). replace must then be a literal (no $ refs).
	validate func(string) bool
}

// sensitiveKeyRE matches JSON/map keys whose string values should always be
// scrubbed, regardless of value content.
//
// Catches:
//   - Word-bearing names: password, secret, token, credential, auth*
//   - Common API key fields: api_key, api-key
//   - Env-var style: *_API_KEY, *_ACCESS_KEY, *_PRIVATE_KEY, *_MASTER_KEY,
//     *_ENCRYPTION_KEY, *_SIGNING_KEY, *_HMAC_KEY (any of these as a
//     suffix or with surrounding underscores).
//
// Deliberately does NOT match bare `*_key` suffixes — fields like
// `prompt_cache_key` (codex's OpenAI prefix-cache lookup key),
// `idempotency_key` (Stripe), `partition_key` (DBs), and `cache_key`
// carry hash/identifier values the scrubber would corrupt. Redacting
// codex's `prompt_cache_key` in particular would break the OpenAI
// prefix-cache hit on every turn — significantly worse than the
// hypothetical leak risk of an unredacted UUID.
var sensitiveKeyRE = regexp.MustCompile(`(?i)(password|secret|token|credential|api[_-]?key|auth)|(^|[_-])(?:api|access|private|master|encryption|signing|hmac)[_-]?key($|[_-])`)

var defaultPatterns = []pattern{
	// The full-match value rows below write the TYPED marker
	// "[REDACTED:<type>]" naming the scrub.DetectorNames() row with the
	// same shape (audit P4, prompt-guard coverage 2026-10-02): the post-hoc
	// prompt guard reads a typed marker in a stored prompt as a certain
	// finding, so a classic token typed into a tool with no pre-send seam
	// is flagged, not just redacted. A bare "[REDACTED]" is never read that
	// way. Context rows (JSON keys, assignments, export, connection
	// strings) stay bare: their key word makes the value certain, but
	// they also redact prose ("max token: 4096"), so they are not evidence.
	//
	// GitHub Personal Access Tokens: ghp_, gho_, ghu_, ghs_, ghr_ prefix.
	{re: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`), replace: TypedRedactedMarker("github_pat")},
	// Bearer tokens. Split on the typed detector's {8,} value floor: a
	// header-length value gets the bearer_token marker, a short one
	// ("Bearer token auth", "Bearer of") stays a bare redaction exactly as
	// before, so prose is never promoted to a finding.
	// A match whose whole value is one English word ("Bearer tokens are
	// accepted", "Bearer authentication") is prose and stays
	// (bearerprose.go, operator ruling 2026-11-15).
	{re: regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9\-._~+/]{8,}=*`), replace: TypedRedactedMarker("bearer_token"), validate: bearerNotProse},
	{re: regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*`), validate: bearerNotProse},
	// Common API key prefixes: sk-..., pk-..., ak-..., api_key=..., etc.
	// Allow underscores AND hyphens inside the body: pk_test_abc123... and
	// Anthropic's sk-ant-api03-... both carry separators past the prefix.
	// Without `-` the match died at `sk-ant`, passing the key through
	// unredacted (grokbot Phase-0 finding, 2026-08-29).
	{re: regexp.MustCompile(`(?i)(?:sk|pk|ak)[_-][A-Za-z0-9_-]{16,}`), replace: TypedRedactedMarker("api_key_prefixed")},
	// Claude Code's "Detected a custom API key" prompt shows the key's
	// last 20 characters after a truncation mark ("sk-ant-..." beside the
	// ANTHROPIC_API_KEY label), and a terminal capture of that screen
	// carries them into whatever reads it, an agent's tool output among
	// them (build tracker F-058). The row above cannot see a suffix (the
	// dots end its match at "sk-ant"), and the api_key row below cannot
	// either when terminal colour codes sit between the label and its
	// colon. This row keys on the prompt's own rendering: "sk-ant-"
	// followed by the dots or an ellipsis, or the label whose value starts
	// with them, then a suffix of 8 to 64 key characters (so prose such as
	// "ANTHROPIC_API_KEY: ...see below" keeps its word, audit FU12-A3).
	// Colour codes (SGR, raw or JSON-escaped as \u001b) are allowed around
	// the label's colon, after "sk-ant-" and after the mark (FU12-A2). It
	// never matches a bare run of characters and rewrites only the suffix,
	// so a JSON body stays valid. A context row: the bare marker.
	{
		re:      apiKeyPromptSuffixRE,
		replace: `$1` + Redacted,
	},
	{re: regexp.MustCompile(`(?i)api[_-]?key[_-]?[A-Za-z0-9_]{20,}`), replace: TypedRedactedMarker("api_key_named")},
	// AWS access key IDs
	{re: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), replace: TypedRedactedMarker("aws_access_key")},
	// JSON-style sensitive key → replace the string value.
	// Matches: "password": "value" / "api_key":"value" / etc.
	{
		re:      regexp.MustCompile(`(?i)("(?:password|secret|token|credential|api[_-]?key|auth[_-]?token)"?\s*:\s*)"[^"]*"`),
		replace: `$1"` + Redacted + `"`,
	},
	// JSON-encoded form of env-var-style secrets:
	// "OPENAI_API_KEY": "sk-..." / "AWS_ACCESS_KEY_ID": "AKIA..." / etc.
	// Same allowlist semantics as sensitiveKeyRE — bare *_KEY suffixes
	// without a recognized secret-prefix word are NOT matched (so codex's
	// "prompt_cache_key", "idempotency_key", and similar pass through
	// untouched).
	{
		re:      regexp.MustCompile(`(?i)("[A-Z_]*(?:SECRET|TOKEN|PASSWORD|CREDENTIAL|(?:API|ACCESS|PRIVATE|MASTER|ENCRYPTION|SIGNING|HMAC)_KEY)[A-Z_]*"\s*:\s*)"[^"]*"`),
		replace: `$1"` + Redacted + `"`,
	},
	// Generic key=value / key: value secrets — redact the value after '=' or ':'.
	{
		re:      regexp.MustCompile(`(?i)(password|secret|token|credential)(\s*[=:]\s*)(\S+)`),
		replace: `$1$2` + Redacted,
	},
	// Explicit "api_key: value" / "api-key = value".
	{
		re:      regexp.MustCompile(`(?i)(api[_-]?key)(\s*[=:]\s*)(\S+)`),
		replace: `$1$2` + Redacted,
	},
	// export SECRET_FOO=bar → export SECRET_FOO=[REDACTED]
	{
		re:      regexp.MustCompile(`(?i)(export\s+\w*(?:SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL)\w*\s*=\s*)(\S+)`),
		replace: `$1` + Redacted,
	},
	// Connection-string user:password@host → user:[REDACTED]@host
	{
		re:      regexp.MustCompile(`(://[^:/\s]+:)([^@\s]+)(@)`),
		replace: `$1` + Redacted + `$3`,
	},

	// --- Fixed-prefix secret shapes the typed detector table (detect.go)
	// already certainly flags but this storage table did not redact
	// (prompt-guard coverage audit 2026-10-02, ledger PGC-1): a GitHub
	// fine-grained PAT typed into an Antigravity CLI prompt was stored
	// verbatim in actions.target / raw_tool_input / otel_content and, on a
	// full-content node, shipped to the org. Same regexes as the typed
	// rows github_pat_fine / gcp_api_key / slack_token, so "a value the
	// egress scan flags is a value storage redacts" holds for them too.
	//
	// They sit LAST and replace with the TYPED marker "[REDACTED:<type>]"
	// (the vocabulary scrub.MaskSecrets already writes on the proxy mask
	// path) rather than the bare Redacted: running after the generic
	// assignment rows means a "token: github_pat_…" assignment is still
	// consumed by those rows as before, while a STANDALONE token keeps its
	// type name. The post-hoc prompt guard (internal/guard, the watcher
	// lane for tools with no pre-send seam) reads a typed marker in a
	// stored prompt as a certain finding of that detector; a bare
	// "[REDACTED]" is never read that way, because the generic rows also
	// redact prose like "Bearer token auth" or "max token: 4096".
	{
		re:      regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`),
		replace: TypedRedactedMarker("github_pat_fine"),
	},
	{
		re:      regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		replace: TypedRedactedMarker("gcp_api_key"),
	},
	{
		re:      slackTokenRE,
		replace: TypedRedactedMarker("slack_token"),
	},
	// JWTs and PEM private-key blocks (audit P5): previously typed-path
	// only. The JWT row is the typed detector's own candidate regex AND
	// structural validator (Sol A2-05). The PEM row is
	// STRICTER than the typed detector's lazy dotall body (pemKeyBlockRE):
	// it needs real key material after the BEGIN line, a base64 line of
	// 40+ characters, so code or prose that merely NAMES the header is
	// never rewritten.
	{
		re:       jwtCandidateRE,
		replace:  TypedRedactedMarker("jwt"),
		validate: jwtValidate,
	},
	{re: pemKeyBlockRE, replace: TypedRedactedMarker("private_key_block")},
}

// apiKeyPromptSuffixRE is the F-058 row's pattern: Claude Code's custom API
// key prompt ("sk-ant-..." and the key's last 20 characters, beside the
// ANTHROPIC_API_KEY label), with SGR colour codes, raw or JSON-escaped,
// allowed between its parts. Group 1 is everything before the suffix.
var apiKeyPromptSuffixRE = func() *regexp.Regexp {
	const sgr = `(?:(?:\x1b|\\u001b)\[[0-9;]*m)*`
	const mark = `(?:\.\.\.|…)`
	return regexp.MustCompile(`(sk-ant-` + sgr + mark + sgr +
		`|ANTHROPIC_API_KEY` + sgr + `:[ \t]*` + sgr + `[ \t]*` + mark + sgr +
		`)[A-Za-z0-9_-]{8,64}`)
}()

// pemKeyBlockRE matches a PEM private-key block for the storage table:
// the BEGIN line; optional Proc-Type / DEK-Info header lines (an
// encrypted key); at least one base64 line of 40+ characters; further
// base64 lines of 16+; then the END line (a short last line before it is
// taken too) or nothing at all for a truncated paste. A separator is
// whitespace or a JSON-escaped newline (\n, \r), so a block inside a
// stored JSON string matches as well.
var pemKeyBlockRE = regexp.MustCompile(
	`-----BEGIN [A-Z ]*PRIVATE KEY-----` +
		`(?:(?:\s|\\[nr])+(?:Proc-Type|DEK-Info):[^\n\\]*)*` +
		`(?:\s|\\[nr])+[A-Za-z0-9+/=]{40,}` +
		`(?:(?:\s|\\[nr])+[A-Za-z0-9+/=]{16,})*` +
		`(?:(?:\s|\\[nr])+[A-Za-z0-9+/=]{1,15}(?:\s|\\[nr])*-----END [A-Z ]*PRIVATE KEY-----|(?:\s|\\[nr])*-----END [A-Z ]*PRIVATE KEY-----)?`)

// TypedRedactedMarker is the "[REDACTED:<type>]" marker that names the
// detector whose value was removed — the shape MaskSecrets writes on the
// proxy mask path and the storage table writes for the fixed-prefix rows
// above. detector must be a scrub.DetectorNames() id.
func TypedRedactedMarker(detector string) string {
	return "[REDACTED:" + detector + "]"
}

// typedRedactedMarkerRE matches a typed marker and captures the detector id.
var typedRedactedMarkerRE = regexp.MustCompile(`\[REDACTED:([a-z0-9_]+)\]`)

// HasRedaction reports whether v carries a storage redaction marker of
// either form: the bare Redacted or a typed "[REDACTED:<type>]". Callers
// asking "was something removed here" use this rather than Contains on
// the bare marker, which a typed marker does not contain.
func HasRedaction(v string) bool {
	return strings.Contains(v, Redacted) || strings.Contains(v, "[REDACTED:")
}

// TypedRedactedMarkers returns, in order of appearance, the detector id of
// every "[REDACTED:<type>]" marker in v whose type is a known SECRET-class
// detector. Unknown ids and PII-class ids are skipped, so a marker can only
// ever stand for a detector this package actually runs. A bare
// "[REDACTED]" is never returned (see the storage-table comment above for
// why it is not evidence of a certain secret).
func TypedRedactedMarkers(v string) []string {
	if !strings.Contains(v, "[REDACTED:") {
		return nil
	}
	var out []string
	for _, m := range typedRedactedMarkerRE.FindAllStringSubmatch(v, -1) {
		if class, ok := DetectorClass(m[1]); ok && class == ClassSecret {
			out = append(out, m[1])
		}
	}
	return out
}

// New returns a Scrubber loaded with the default patterns (spec §8.1).
func New() *Scrubber {
	return NewWithExtra(nil)
}

// NewWithExtra returns a Scrubber loaded with the default patterns plus any
// additional full-match regex patterns supplied by the user.
// Invalid regexes are silently skipped — callers should validate config with
// ValidatePatterns first if they want to surface errors.
func NewWithExtra(extra []string) *Scrubber {
	s := &Scrubber{patterns: append([]pattern{}, defaultPatterns...)}
	for _, p := range extra {
		re, err := regexp.Compile(p)
		if err != nil {
			continue
		}
		s.patterns = append(s.patterns, pattern{re: re})
	}
	return s
}

// ValidatePatterns reports the first invalid regex in patterns, if any.
func ValidatePatterns(patterns []string) error {
	for _, p := range patterns {
		if _, err := regexp.Compile(p); err != nil {
			return err
		}
	}
	return nil
}

// String applies every pattern to s, returning the scrubbed result.
// Full-match patterns replace their entire match with [REDACTED]; patterns
// with an explicit replace template use that template (supporting $1 $2 etc.).
//
// Before applying patterns, values of allowlisted fields (currently
// `encrypted_content` — OpenAI Responses API ZDR-mode reasoning blobs)
// are extracted to placeholders so the global secret-prefix regexes
// can't false-positive on substrings inside them. Without this, codex's
// chatgpt-auth turns return `invalid_encrypted_content` on every
// reasoning continuation past turn 1: Fernet tokens are hundreds of
// base64 chars long, and a substring like `ghp_<random>` (matching the
// GitHub PAT pattern) or `sk-<random>` (matching the OpenAI key
// pattern) appears in roughly every fourth token. Redacting that
// substring corrupts the Fernet HMAC and the upstream rejects.
//
// Shielding is byte-position aware — placeholders are unique per call
// site and replaced back after patterns run, so the rest of the body
// (including JSON keys/values that overlap shielded values) still gets
// the full secret-redacting pass.
func (s *Scrubber) String(v string) string {
	shielded, restorations := shieldFernetEncryptedContent(v)
	out := shielded
	for _, p := range s.patterns {
		switch {
		case p.validate != nil:
			repl := p.replace
			if repl == "" {
				repl = Redacted
			}
			check := p.validate
			out = p.re.ReplaceAllStringFunc(out, func(m string) string {
				if check(m) {
					return repl
				}
				return m
			})
		case p.replace == "":
			out = p.re.ReplaceAllString(out, Redacted)
		default:
			out = p.re.ReplaceAllString(out, p.replace)
		}
	}
	return restoreShielded(out, restorations)
}

// ScrubForward redacts secrets from a body that will be FORWARDED
// upstream (the proxy request path), not stored. Unlike [Scrubber.String],
// it guarantees the output is still valid JSON whenever the input was.
//
// [Scrubber.String] applies line-oriented regexes across the WHOLE body
// with no awareness of JSON structure. On compact JSON (which
// conversation.marshalEnvelope emits — no whitespace) the generic
// `(password|secret|token|credential):<value>` and `api_key:<value>`
// patterns' trailing `\S+` matches every non-whitespace byte from the
// trigger word to the next space — i.e. potentially the entire rest of
// the body, quotes and braces included — and replaces it with
// "[REDACTED]", truncating the JSON so the upstream rejects the whole
// request with 400 "unexpected character". (The `"key":"[^"]*"` patterns
// have a sibling failure: `[^"]*` stops at the first escaped `\"` inside a
// value, stranding the remainder.) This bit large claude-code requests
// once they grew past the size where a trigger word was near-certain.
//
// Fast path (cache-friendly): scrub with String. When nothing matched —
// output byte-identical to input, the common case — return the input
// slice unchanged so the proxy's prefix-cache byte stability is
// preserved. When something matched, String's output is accepted only
// when it has the SAME JSON SHAPE as the input (same delimiters, keys and
// literals in the same order; only ordinary string values changed; kept
// values byte-identical). "Still valid JSON" is not enough: a greedy
// `\S+` row can swallow whole array items and leave valid JSON behind
// (lane sr-openai-n2). Otherwise the body is scrubbed token by token and
// only the changed tokens are spliced back into the original bytes:
// member names go through String, string values follow the
// [Scrubber.JSONValue] rules, and structure, key order and kept values are
// never rewritten (forward.go). The one kept value is a string that is the
// DIRECT value of a member named literally `encrypted_content`, which
// String's own shield already covers.
// Unlike [Scrubber.RawJSON] this never truncates — the forward path must
// not silently drop a large legitimate body. Non-JSON input falls through
// to String's output (best effort; the proxy hard-guard is the final
// backstop).
//
// A body bound for the LLM provider that produced its reasoning or
// thinking items uses [Scrubber.ScrubProviderRequest] instead.
func (s *Scrubber) ScrubForward(raw []byte) []byte {
	return s.scrubForward(raw, false)
}

// fernetEncryptedContentRE matches a JSON string-valued
// `"encrypted_content"` key — captures the value without the surrounding
// quotes so we can extract it for shielding. Conservative: requires the
// key to be quoted exactly, value to be a string (not array/object). The
// observed shape (codex 0.129.0 ↔ chatgpt.com/backend-api/codex/responses)
// is always `"encrypted_content":"<base64-fernet>"`.
var fernetEncryptedContentRE = regexp.MustCompile(`"encrypted_content"\s*:\s*"((?:[^"\\]|\\.)*)"`)

// shieldFernetEncryptedContent rewrites the body so each
// encrypted_content value is replaced with a stable, regex-inert
// placeholder. Returns the rewritten body and a slice of original
// values indexed by placeholder N. The placeholder format
// `__OBSERVERSHIELD_<N>__` deliberately uses a non-secret-prefix word
// + zero-padded N + double-underscore terminator so none of the
// scrubber's secret patterns match it (no `gh*_`, `sk[_-]`, `Bearer`,
// `AKIA`, `*_KEY` etc.).
func shieldFernetEncryptedContent(body string) (string, []string) {
	matches := fernetEncryptedContentRE.FindAllStringSubmatchIndex(body, -1)
	if len(matches) == 0 {
		return body, nil
	}
	var b []byte
	restorations := make([]string, 0, len(matches))
	last := 0
	for _, m := range matches {
		// m[0]:m[1] = full match span; m[2]:m[3] = captured group span
		// (the value's bytes WITHOUT surrounding quotes).
		valStart, valEnd := m[2], m[3]
		b = append(b, body[last:valStart]...)
		idx := len(restorations)
		restorations = append(restorations, body[valStart:valEnd])
		// Inert placeholder — no secret-prefix words, no special chars.
		placeholder := "OBSERVERSHIELD" + paddedIdx(idx) + "ENDSHIELD"
		b = append(b, []byte(placeholder)...)
		last = valEnd
	}
	b = append(b, body[last:]...)
	return string(b), restorations
}

// restoreShielded replaces each OBSERVERSHIELD<N>ENDSHIELD placeholder
// with restorations[N]. Patterns may have mutated the body around the
// placeholder, but the placeholder string itself is regex-inert, so it
// survives unchanged.
func restoreShielded(body string, restorations []string) string {
	if len(restorations) == 0 {
		return body
	}
	out := body
	for i, orig := range restorations {
		placeholder := "OBSERVERSHIELD" + paddedIdx(i) + "ENDSHIELD"
		out = strings.ReplaceAll(out, placeholder, orig)
	}
	return out
}

func paddedIdx(n int) string {
	// Six digits — supports up to 1M shielded values per body without
	// wraparound. Plenty for any realistic request.
	const digits = "0123456789"
	buf := []byte("000000")
	for i := len(buf) - 1; i >= 0 && n > 0; i-- {
		buf[i] = digits[n%10]
		n /= 10
	}
	return string(buf)
}

// JSONValue recursively scrubs every string value within an arbitrary
// unmarshaled JSON structure (map[string]any / []any / string / numbers).
// When traversing a map, any string value whose key name matches
// sensitiveKeyRE is replaced with [REDACTED] regardless of content.
// Non-string values are returned unchanged.
func (s *Scrubber) JSONValue(v any) any {
	return s.jsonValue(v, "")
}

// IsSensitiveKey reports whether a JSON or attribute key names a secret
// (password, token, api key, ...): the rule JSONValue applies to decide that
// a string value under the key is redacted whatever its content. Exported so
// a caller that handles some values outside JSONValue (numbers) applies the
// same rule.
func IsSensitiveKey(key string) bool {
	return key != "" && sensitiveKeyRE.MatchString(key)
}

func (s *Scrubber) jsonValue(v any, parentKey string) any {
	switch t := v.(type) {
	case string:
		if parentKey != "" && sensitiveKeyRE.MatchString(parentKey) {
			return Redacted
		}
		return s.String(t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, child := range t {
			out[k] = s.jsonValue(child, k)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, child := range t {
			out[i] = s.jsonValue(child, parentKey)
		}
		return out
	default:
		return v
	}
}

// RawJSON scrubs every string value inside the supplied raw JSON payload and
// returns the re-marshaled, truncated result. If the payload is not valid
// JSON, it falls back to plain-string scrubbing. The output is always
// truncated to MaxRawInputBytes (spec §8.2).
func (s *Scrubber) RawJSON(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return Truncate(s.String(string(raw)))
	}
	scrubbed := s.JSONValue(decoded)
	out, err := json.Marshal(scrubbed)
	if err != nil {
		return Truncate(s.String(string(raw)))
	}
	return Truncate(string(out))
}

// Truncate caps v at MaxRawInputBytes, appending an ellipsis marker if the
// value was cut.
func Truncate(v string) string {
	if len(v) <= MaxRawInputBytes {
		return v
	}
	const marker = "…[truncated]"
	cut := MaxRawInputBytes - len(marker)
	if cut < 0 {
		cut = 0
	}
	return v[:cut] + marker
}

// TruncateN caps v at maxBytes, appending the same trailing "…[truncated]"
// marker as [Truncate] when the value was cut. Unlike Truncate — which is
// pinned to the fixed MaxRawInputBytes (1 MiB) raw_tool_input ceiling — this
// takes a caller-supplied cap, for stores with a tighter size ceiling (e.g.
// otel_content's 32 KiB, mirroring the org gateway's classify.Policy body
// bound). The cut point backs up to a UTF-8 rune boundary (a continuation
// byte is 0b10xxxxxx) so the stored value never ends mid-rune, matching
// classify's own boundBytes convention. maxBytes<=0 returns "" for a
// non-empty v (the degenerate "no room" case).
func TruncateN(v string, maxBytes int) string {
	if maxBytes <= 0 {
		if v == "" {
			return v
		}
		return ""
	}
	if len(v) <= maxBytes {
		return v
	}
	const marker = "…[truncated]"
	cut := maxBytes - len(marker)
	if cut < 0 {
		cut = 0
	}
	for cut > 0 && v[cut]&0xC0 == 0x80 {
		cut--
	}
	return v[:cut] + marker
}
