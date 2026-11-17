package secdetect

import (
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Status is a scan's outcome.
type Status string

const (
	// StatusClean: every byte was scanned within the deadline and nothing
	// blocking was found (low-confidence hits may still be listed).
	StatusClean Status = "clean"
	// StatusHits: at least one blocking-grade hit.
	StatusHits Status = "hits"
	// StatusIncomplete is the plan's scan_incomplete: the deadline was
	// reached or the content was over the cap, so part of it was not
	// scanned. Hits found before the cut are still listed. Never treated as
	// clean.
	StatusIncomplete Status = "scan_incomplete"
)

// IncompleteReason says why a scan is incomplete.
type IncompleteReason string

const (
	// ReasonNone: the scan is complete.
	ReasonNone IncompleteReason = ""
	// ReasonDeadline: the per-call deadline was reached.
	ReasonDeadline IncompleteReason = "deadline"
	// ReasonOverCap: the content is larger than the cap; only the first
	// cap bytes were scanned.
	ReasonOverCap IncompleteReason = "over_cap"
)

// Confidence is a hit's confidence.
type Confidence string

const (
	// ConfidenceHigh: a pattern-certain typed detector.
	ConfidenceHigh Confidence = "high"
	// ConfidenceLow: the entropy heuristic; never blocking.
	ConfidenceLow Confidence = "low"
)

// Hit is one secret detection. It never carries the matched value.
type Hit struct {
	// Type is the stable detector name (scrub.TypedFinding.Type).
	Type string
	// Line is the 1-based line of the hit within the scanned text.
	Line int
	// Confidence is high for a typed detector, low for entropy.
	Confidence Confidence
	// Fixture is set when the path is in a fixture or test-data class
	// (fixturePathClasses): a blocking rule lowers deny to ask there.
	Fixture bool
	// Identity is the keyed, value-free identity of the matched secret
	// (Scanner.Identify's answer; "" when no Identify is set). The value
	// itself never leaves Scan.
	Identity string
}

// Blocking reports whether the hit may block a write or a commit: a
// high-confidence typed detection.
func (h Hit) Blocking() bool { return h.Confidence == ConfidenceHigh }

// Result is one scan's answer.
type Result struct {
	Status Status
	Reason IncompleteReason
	Hits   []Hit
	// Scanned is the number of bytes scanned; Total the input's length.
	Scanned int
	Total   int
}

// Limits bounds one scan.
type Limits struct {
	// MaxBytes is the cap; content past it is not scanned.
	MaxBytes int
	// Deadline is the per-call budget; zero means none.
	Deadline time.Duration
}

const (
	// HookMaxBytes is the fixed in-hook cap (16 KiB, JSP-2).
	HookMaxBytes = 16 << 10
	// HookDeadline is the in-hook per-call deadline: the plan's 5 ms p99
	// budget for the native detectors on a proposed write.
	HookDeadline = 5 * time.Millisecond
	// PostWriteMaxBytesDefault is the post-write seam's default cap, the
	// value of [security.secrets].postwrite_cap_kib = 256 (the daemon reads
	// the key through the floors' seam, cmd/observer
	// securityPostWriteCapInForce).
	PostWriteMaxBytesDefault = 256 << 10
	// PostWriteMaxBytesSmall is the smaller post-write picker value (64
	// KiB): it scans less, so it is honoured on an individual node only; a
	// managed node keeps the default (lane LEFT-SEC, SECP-18).
	PostWriteMaxBytesSmall = 64 << 10
	// QuickScanDeadline is the individual node's fixed quick-scan budget
	// (D-764 Q21).
	QuickScanDeadline = 2 * time.Second
)

// HookLimits are the fixed in-hook limits. They are a value, not a
// setting: the 64 and 256 KiB options were removed from the hook (JSP-2).
var HookLimits = Limits{MaxBytes: HookMaxBytes, Deadline: HookDeadline}

// PostWriteLimits returns the post-write seam's limits for a cap picker
// value in KiB (64 or 256; anything else is the default 256).
func PostWriteLimits(capKiB int) Limits {
	if capKiB == 64 {
		return Limits{MaxBytes: PostWriteMaxBytesSmall}
	}
	return Limits{MaxBytes: PostWriteMaxBytesDefault}
}

// chunkBytes is the slice of input scanned between deadline checks, and
// chunkOverlap the bytes repeated from the previous slice so a secret on a
// boundary is not split. Slices end on a line break where one exists.
const (
	chunkBytes   = 4 << 10
	chunkOverlap = 1 << 10
)

// Scanner scans content under limits. Now is the clock (nil: time.Now);
// Detect is the detector (nil: scrub.DetectSecrets), injectable for tests.
type Scanner struct {
	Now    func() time.Time
	Detect func(string) []scrub.TypedFinding
	// Identify, when set, turns a hit's detector type and matched value
	// into a keyed identity (secfinding.SecretIdentity under the node key)
	// so a finding can be keyed without keeping the value.
	Identify func(typ, value string) string
}

// Scan scans text, the content written to path (path may be ""; it only
// decides the fixture class), under lim.
func (s Scanner) Scan(text, path string, lim Limits) Result {
	now := s.Now
	if now == nil {
		now = time.Now
	}
	detect := s.Detect
	if detect == nil {
		detect = scrub.DetectSecrets
	}
	res := Result{Total: len(text)}
	body := text
	if lim.MaxBytes > 0 && len(body) > lim.MaxBytes {
		body = cutAtLine(body, lim.MaxBytes)
		res.Reason = ReasonOverCap
	}
	var deadline time.Time
	if lim.Deadline > 0 {
		deadline = now().Add(lim.Deadline)
	}
	fixture := IsFixturePath(path)
	seen := map[hitKey]bool{}
	start := 0
	for start < len(body) {
		end := start + chunkBytes
		if end >= len(body) {
			end = len(body)
		} else if nl := strings.LastIndexByte(body[start:end], '\n'); nl > chunkOverlap {
			end = start + nl + 1
		}
		for _, f := range detect(body[start:end]) {
			if knownExample(f) {
				continue
			}
			abs := start + f.Start
			key := hitKey{abs, f.Type}
			if seen[key] {
				continue
			}
			seen[key] = true
			h := Hit{Type: f.Type, Line: 1 + strings.Count(body[:clamp(abs, len(body))], "\n"), Fixture: fixture, Confidence: ConfidenceHigh}
			if s.Identify != nil {
				h.Identity = s.Identify(f.Type, f.Value)
			}
			if !f.Certain || f.Type == "entropy" || codeShapedAssignment(f.Type, f.Value, path) {
				h.Confidence = ConfidenceLow
			}
			res.Hits = append(res.Hits, h)
		}
		res.Scanned = end
		if end == len(body) {
			break
		}
		if !deadline.IsZero() && !now().Before(deadline) {
			res.Reason = ReasonDeadline
			break
		}
		next := end - chunkOverlap
		if nl := strings.IndexByte(body[next:end], '\n'); nl >= 0 {
			next += nl + 1
		}
		if next <= start {
			next = end
		}
		start = next
	}
	sort.SliceStable(res.Hits, func(i, j int) bool { return res.Hits[i].Line < res.Hits[j].Line })
	switch {
	case res.Reason != ReasonNone:
		res.Status = StatusIncomplete
	case anyBlocking(res.Hits):
		res.Status = StatusHits
	default:
		res.Status = StatusClean
	}
	return res
}

// ScanHook is the in-hook entry point: the proposed new text of a write
// (the added text of every edit, joined by the caller) under HookLimits.
func ScanHook(text, path string) Result {
	return Scanner{}.Scan(text, path, HookLimits)
}

// hitKey identifies a hit across overlapping slices.
type hitKey struct {
	offset int
	typ    string
}

// anyBlocking reports whether any hit blocks.
func anyBlocking(hits []Hit) bool {
	for _, h := range hits {
		if h.Blocking() {
			return true
		}
	}
	return false
}

// cutAtLine returns s cut to at most n bytes, at the last line break
// before n when one exists.
func cutAtLine(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if nl := strings.LastIndexByte(s[:n], '\n'); nl > 0 {
		return s[:nl+1]
	}
	return s[:n]
}

func clamp(v, hi int) int {
	if v < 0 {
		return 0
	}
	if v > hi {
		return hi
	}
	return v
}

// knownExampleValues are documentation keys that never fire (the AWS
// documentation pair and the like). Compared in memory only.
var knownExampleValues = map[string]bool{
	"AKIAIOSFODNN7EXAMPLE":                     true,
	"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY": true,
	"AKIAI44QH8DHBEXAMPLE":                     true,
	"je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY": true,
}

// knownExample reports whether f's value is a documentation example: a
// listed value, or an AWS-shaped key ending in EXAMPLE or EXAMPLEKEY.
func knownExample(f scrub.TypedFinding) bool {
	v := strings.Trim(f.Value, "\"' ")
	if knownExampleValues[v] {
		return true
	}
	if strings.HasPrefix(f.Type, "aws_") && (strings.HasSuffix(v, "EXAMPLE") || strings.HasSuffix(v, "EXAMPLEKEY")) {
		return true
	}
	return false
}

// assignmentTypes are the scrub detectors that match "<keyword> = value" or
// "<keyword>: value" by the key alone. In source code the key is often a
// field or variable name that only contains the keyword (a struct field
// listing the environment variable names a credential is read from), and
// the value is code, not a secret.
var assignmentTypes = map[string]bool{"secret_assignment": true, "api_key_assignment": true}

// codeValueExts are the source-code file extensions where an assignment's
// value can be code. Env files, shell scripts, config and data files are
// absent on purpose: there an unquoted value is the secret itself.
var codeValueExts = map[string]bool{
	".go": true, ".ts": true, ".tsx": true, ".js": true, ".jsx": true, ".mjs": true, ".cjs": true,
	".py": true, ".rs": true, ".java": true, ".kt": true, ".cs": true, ".rb": true, ".swift": true,
	".c": true, ".h": true, ".cc": true, ".cpp": true, ".hpp": true, ".php": true, ".scala": true,
}

// codeValueShapes are the value shapes that are code, not a secret, tried in
// order (S-721 false positive, 2026-11-11). A quoted string literal matches
// none of them, so `token: "sk-live-..."` stays a high-confidence hit.
var codeValueShapes = []struct {
	name  string
	match func(v codeValue) bool
}{
	// A composite literal or reference: []string{"X_TOKEN"}, {..}, &cfg, *p.
	{"composite", func(v codeValue) bool { return strings.ContainsAny(v.text[:1], "[{&*") }},
	// A call or an index: envNames(), os.Getenv("X"), cfg.Keys["k"].
	{"call_or_index", func(v codeValue) bool {
		n := identPrefixLen(v.text)
		return n > 0 && n < len(v.text) && (v.text[n] == '(' || v.text[n] == '[')
	}},
	// A bare identifier or selector with no digit, that either ends an
	// expression (a struct field value followed by a comma) or is dotted
	// (cfg.Token). Digits are excluded and a lone word needs the delimiter,
	// so an unquoted alphanumeric secret (a hex key written after the
	// keyword in a comment) is never mistaken for a name.
	{"identifier", func(v codeValue) bool {
		if identPrefixLen(v.text) != len(v.text) || strings.ContainsAny(v.text, "0123456789") {
			return false
		}
		return v.delimited || strings.Contains(v.text, ".")
	}},
}

// codeValue is an assignment's value as the shapes see it: the text without
// a trailing expression delimiter, and whether one was there.
type codeValue struct {
	text      string
	delimited bool
}

// codeShapedAssignment reports whether a keyword-assignment hit in a source
// file has a code-shaped value, which lowers it to low confidence: still
// recorded, never blocking.
func codeShapedAssignment(typ, value, path string) bool {
	if !assignmentTypes[typ] || !codeValueExts[strings.ToLower(pathExt(path))] {
		return false
	}
	raw := strings.TrimSpace(value)
	v := codeValue{text: strings.TrimRight(raw, ",;)")}
	v.delimited = len(v.text) < len(raw)
	if v.text == "" {
		return false
	}
	for _, s := range codeValueShapes {
		if s.match(v) {
			return true
		}
	}
	return false
}

// identPrefixLen is the length of the leading identifier-or-selector run of
// v (letters, digits, '_' and '.', starting with a letter or '_'); 0 when v
// does not start with one.
func identPrefixLen(v string) int {
	for i, r := range v {
		switch {
		case r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
		case i > 0 && ((r >= '0' && r <= '9') || r == '.'):
		default:
			return i
		}
	}
	return len(v)
}

// pathExt returns the extension of the last path element, accepting both
// slash forms (hook paths may be Windows paths).
func pathExt(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		p = p[i+1:]
	}
	if i := strings.LastIndexByte(p, '.'); i > 0 {
		return p[i:]
	}
	return ""
}
