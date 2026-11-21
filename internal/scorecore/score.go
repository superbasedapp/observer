package scorecore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Bounds (contract section 1).
const (
	MaxNameLen          = 64
	MaxValueLen         = 120
	MaxCommentBytes     = 2000
	MaxIDLen            = 128
	MaxScorerNameLen    = 64
	MaxScorerVersionLen = 32
	MaxRunIDLen         = 128
	// MaxBatch is the most scores one write request may carry.
	MaxBatch = 100
)

// Kind is a score's value kind.
type Kind string

// The three value kinds.
const (
	KindNumeric     Kind = "numeric"
	KindBoolean     Kind = "boolean"
	KindCategorical Kind = "categorical"
)

// Kinds is the closed kind vocabulary, in table order.
var Kinds = []Kind{KindNumeric, KindBoolean, KindCategorical}

// ValidKind reports whether k is a known kind.
func ValidKind(k Kind) bool {
	for _, v := range Kinds {
		if v == k {
			return true
		}
	}
	return false
}

// Source names who or what produced a score.
type Source string

// The source vocabulary. The first three predate W3-1 (annotation 052).
const (
	SourceUser     Source = "user"     // a dashboard member
	SourceLLM      Source = "llm"      // an LLM tagging job
	SourceRule     Source = "rule"     // a tagging rule
	SourceSDK      Source = "sdk"      // the app's score()
	SourceFeedback Source = "feedback" // an end user's feedback()
	SourceOTel     Source = "otel"     // a gen_ai.evaluation.result event
	SourceEval     Source = "eval"     // an online rule or an experiment run
	SourceReview   Source = "review"   // the review queue
)

// sourceRow is one row of the source table.
type sourceRow struct {
	Source Source
	// Client marks a source an SDK request may name. Every other source is
	// assigned by the server and refused from a client.
	Client bool
}

// sourceTable is the closed source vocabulary.
var sourceTable = []sourceRow{
	{SourceUser, false},
	{SourceLLM, false},
	{SourceRule, false},
	{SourceSDK, true},
	{SourceFeedback, true},
	{SourceOTel, false},
	{SourceEval, false},
	{SourceReview, false},
}

// Sources returns every known source in table order.
func Sources() []Source {
	out := make([]Source, 0, len(sourceTable))
	for _, r := range sourceTable {
		out = append(out, r.Source)
	}
	return out
}

// ValidSource reports whether s is a known source.
func ValidSource(s Source) bool {
	for _, r := range sourceTable {
		if r.Source == s {
			return true
		}
	}
	return false
}

// ClientSource reports whether a client request may name s.
func ClientSource(s Source) bool {
	for _, r := range sourceTable {
		if r.Source == s {
			return r.Client
		}
	}
	return false
}

// Error is a refused score: a stable machine code and a message.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func errf(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Error codes (contract section 2).
const (
	CodeBadRequest     = "bad_request"
	CodeTooMany        = "too_many"
	CodeInvalidTraceID = "invalid_trace_id"
	CodeInvalidSpanID  = "invalid_span_id"
	CodeInvalidName    = "invalid_name"
	CodeInvalidValue   = "invalid_value"
	CodeKindMismatch   = "kind_mismatch"
	CodeInvalidSource  = "invalid_source"
	CodeInvalidID      = "invalid_id"
	CodeCommentTooLong = "comment_too_long"
	CodeInvalidScorer  = "invalid_scorer"
	CodeInvalidRunID   = "invalid_run_id"
	CodeInvalidTime    = "invalid_timestamp"
)

// Scorer names the automated scorer that produced a value.
type Scorer struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Input is one score as a client sends it (contract section 1).
type Input struct {
	ID        string          `json:"id,omitempty"`
	TraceID   string          `json:"trace_id"`
	SpanID    string          `json:"span_id,omitempty"`
	Name      string          `json:"name"`
	Value     json.RawMessage `json:"value"`
	Kind      Kind            `json:"kind,omitempty"`
	Comment   string          `json:"comment,omitempty"`
	Source    Source          `json:"source,omitempty"`
	Scorer    *Scorer         `json:"scorer,omitempty"`
	RunID     string          `json:"run_id,omitempty"`
	Timestamp string          `json:"timestamp,omitempty"`
}

// Score is one normalized, valid score, ready for a store.
type Score struct {
	TraceID string
	SpanID  string
	// Key is the score name (annotation key).
	Key      string
	Kind     Kind
	Value    string
	ValueNum *float64
	Source   Source
	// Author is the author component of the primary key (AuthorKey).
	Author string
	// ClientID is the client's idempotency id, when it sent one.
	ClientID      string
	Comment       string
	ScorerName    string
	ScorerVersion string
	RunID         string
	At            time.Time
}

// ID is the score's public id (ScoreID over its key fields).
func (s Score) ID() string { return ScoreID(s.TraceID, s.SpanID, s.Key, string(s.Source), s.Author) }

var (
	namePattern = regexp.MustCompile(`^[a-z0-9_.-]+$`)
	idPattern   = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)
	hex32       = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hex16       = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

// ValidClientID reports whether id is a client-chosen id in the scores id
// charset: 1-MaxIDLen characters of [A-Za-z0-9_.:-]. The experiment create
// id (contract experiments.md 4.1) uses the same rule.
func ValidClientID(id string) bool {
	return id != "" && len(id) <= MaxIDLen && idPattern.MatchString(id)
}

// NormalizeTraceID lowercases and validates a W3C trace id.
func NormalizeTraceID(s string) (string, *Error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if !hex32.MatchString(s) || s == strings.Repeat("0", 32) {
		return "", errf(CodeInvalidTraceID, "trace_id must be 32 hex characters and not all zero")
	}
	return s, nil
}

// NormalizeSpanID lowercases and validates a W3C span id; empty is a
// trace-level score.
func NormalizeSpanID(s string) (string, *Error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", nil
	}
	if !hex16.MatchString(s) || s == strings.Repeat("0", 16) {
		return "", errf(CodeInvalidSpanID, "span_id must be 16 hex characters and not all zero, or empty")
	}
	return s, nil
}

// NormalizeName lowercases and validates a score name.
func NormalizeName(s string) (string, *Error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || len(s) > MaxNameLen || !namePattern.MatchString(s) {
		return "", errf(CodeInvalidName, "name must be 1-%d characters of [a-z0-9_.-]", MaxNameLen)
	}
	return s, nil
}

// kindRow is one row of the value-kind table: which JSON value shape a kind
// takes and how it is stored.
type kindRow struct {
	Kind Kind
	// match reports whether a decoded JSON value has this kind's shape.
	match func(v any) bool
	// store renders the value's text and numeric columns.
	store func(v any) (string, *float64, *Error)
}

var kindTable = []kindRow{
	{KindNumeric, func(v any) bool { _, ok := v.(json.Number); return ok }, storeNumeric},
	{KindBoolean, func(v any) bool { _, ok := v.(bool); return ok }, storeBoolean},
	{KindCategorical, func(v any) bool { _, ok := v.(string); return ok }, storeCategorical},
}

func storeNumeric(v any) (string, *float64, *Error) {
	f, err := v.(json.Number).Float64()
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return "", nil, errf(CodeInvalidValue, "value is not a finite number")
	}
	return NumericText(f), &f, nil
}

func storeBoolean(v any) (string, *float64, *Error) {
	if v.(bool) {
		one := 1.0
		return "true", &one, nil
	}
	zero := 0.0
	return "false", &zero, nil
}

func storeCategorical(v any) (string, *float64, *Error) {
	s, err := CategoricalText(v.(string))
	if err != nil {
		return "", nil, err
	}
	return s, nil, nil
}

// NumericText is the stored text of a numeric value.
func NumericText(f float64) string { return strconv.FormatFloat(f, 'g', -1, 64) }

// CategoricalText validates a categorical value's text: trimmed, one line,
// at most MaxValueLen bytes, never truncated.
func CategoricalText(s string) (string, *Error) {
	s = strings.TrimSpace(s)
	if strings.ContainsAny(s, "\r\n") {
		return "", errf(CodeInvalidValue, "a categorical value must be one line")
	}
	if s == "" {
		return "", errf(CodeInvalidValue, "a categorical value must not be empty")
	}
	if len(s) > MaxValueLen {
		return "", errf(CodeInvalidValue, "a categorical value is at most %d bytes (got %d)", MaxValueLen, len(s))
	}
	return s, nil
}

// DecodeValue decodes a JSON value into its kind and stored columns. want,
// when set, must agree with the JSON type.
func DecodeValue(raw json.RawMessage, want Kind) (Kind, string, *float64, *Error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return "", "", nil, errf(CodeInvalidValue, "value is required")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", "", nil, errf(CodeInvalidValue, "value is not valid JSON")
	}
	if want != "" && !ValidKind(want) {
		return "", "", nil, errf(CodeInvalidValue, "kind %q is not one of numeric, boolean, categorical", want)
	}
	for _, row := range kindTable {
		if !row.match(v) {
			continue
		}
		if want != "" && want != row.Kind {
			return "", "", nil, errf(CodeKindMismatch, "kind %s does not match a %s value", want, row.Kind)
		}
		text, num, err := row.store(v)
		if err != nil {
			return "", "", nil, err
		}
		return row.Kind, text, num, nil
	}
	return "", "", nil, errf(CodeInvalidValue, "value must be a number, a boolean or a string")
}

// Options are the server-side facts Normalize needs.
type Options struct {
	// DefaultSource applies when the input names none (SourceSDK for the SDK
	// routes).
	DefaultSource Source
	// AllowServerSources lets a trusted in-process caller set a server
	// source; a client route leaves it false.
	AllowServerSources bool
	// NewID mints an idempotency id when the input has none.
	NewID func() string
	// Now is the receive time (default time.Now).
	Now func() time.Time
}

// Normalize validates one client score. The comment is checked for length
// only; the caller scrubs it before storing.
func Normalize(in Input, opt Options) (Score, *Error) {
	var s Score
	var e *Error
	if s.TraceID, e = NormalizeTraceID(in.TraceID); e != nil {
		return Score{}, e
	}
	if s.SpanID, e = NormalizeSpanID(in.SpanID); e != nil {
		return Score{}, e
	}
	if s.Key, e = NormalizeName(in.Name); e != nil {
		return Score{}, e
	}
	if s.Kind, s.Value, s.ValueNum, e = DecodeValue(in.Value, in.Kind); e != nil {
		return Score{}, e
	}
	src := in.Source
	if src == "" {
		src = opt.DefaultSource
	}
	if src == "" {
		src = SourceSDK
	}
	if !ValidSource(src) || (!opt.AllowServerSources && !ClientSource(src)) {
		return Score{}, errf(CodeInvalidSource, "source %q is not allowed here (want sdk or feedback)", src)
	}
	s.Source = src
	id := strings.TrimSpace(in.ID)
	if id != "" {
		if len(id) > MaxIDLen || !idPattern.MatchString(id) {
			return Score{}, errf(CodeInvalidID, "id must be 1-%d characters of [A-Za-z0-9_.:-]", MaxIDLen)
		}
		s.ClientID = id
	} else if opt.NewID != nil {
		id = opt.NewID()
	}
	if len(in.Comment) > MaxCommentBytes {
		return Score{}, errf(CodeCommentTooLong, "comment is at most %d bytes (got %d)", MaxCommentBytes, len(in.Comment))
	}
	s.Comment = strings.TrimSpace(in.Comment)
	if in.Scorer != nil {
		s.ScorerName = strings.TrimSpace(in.Scorer.Name)
		s.ScorerVersion = strings.TrimSpace(in.Scorer.Version)
		if len(s.ScorerName) > MaxScorerNameLen || len(s.ScorerVersion) > MaxScorerVersionLen ||
			(s.ScorerVersion != "" && s.ScorerName == "") {
			return Score{}, errf(CodeInvalidScorer, "scorer name is at most %d and version at most %d characters, and a version needs a name", MaxScorerNameLen, MaxScorerVersionLen)
		}
	}
	s.RunID = strings.TrimSpace(in.RunID)
	if len(s.RunID) > MaxRunIDLen || (s.RunID != "" && !idPattern.MatchString(s.RunID)) {
		return Score{}, errf(CodeInvalidRunID, "run_id must be at most %d characters of [A-Za-z0-9_.:-]", MaxRunIDLen)
	}
	now := time.Now
	if opt.Now != nil {
		now = opt.Now
	}
	s.At = now().UTC()
	if ts := strings.TrimSpace(in.Timestamp); ts != "" {
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return Score{}, errf(CodeInvalidTime, "timestamp must be RFC 3339")
		}
		s.At = t.UTC()
	}
	s.Author = AuthorKey(s.Source, AuthorParts{ID: id})
	return s, nil
}

// AuthorParts are the facts an author key may be built from.
type AuthorParts struct {
	// ID is the idempotency id (sdk, feedback, otel with superbased.score.id).
	ID string
	// EventDigest is the otel fallback when the event has no id.
	EventDigest string
	// Member is the dashboard member or reviewer id (user, review).
	Member string
	// Run is the run, rule or job id (eval, llm, rule).
	Run string
	// Version is the scorer version (eval).
	Version string
}

// authorRow is one row of the author-key table.
type authorRow struct {
	Source Source
	Key    func(p AuthorParts) string
}

func idOr(prefix string) func(p AuthorParts) string {
	return func(p AuthorParts) string {
		if p.ID != "" {
			return "id:" + p.ID
		}
		if p.EventDigest != "" {
			return "ev:" + p.EventDigest
		}
		return prefix
	}
}

func member(p AuthorParts) string {
	if p.Member == "" {
		return ""
	}
	return "user:" + p.Member
}

func run(p AuthorParts) string {
	if p.Run == "" {
		return ""
	}
	return "run:" + p.Run
}

// authorTable is the author-key rule per source (contract section 1). A row
// that yields "" keeps the pre-330 one-row-per-(key, source) behaviour.
var authorTable = []authorRow{
	{SourceSDK, idOr("")},
	{SourceFeedback, idOr("")},
	{SourceOTel, idOr("")},
	{SourceUser, member},
	{SourceReview, member},
	{SourceEval, func(p AuthorParts) string {
		if p.Run == "" {
			return ""
		}
		return "run:" + p.Run + "@" + p.Version
	}},
	{SourceLLM, run},
	{SourceRule, run},
}

// AuthorKey returns the author component of a score's primary key.
func AuthorKey(src Source, p AuthorParts) string {
	for _, r := range authorTable {
		if r.Source == src {
			return r.Key(p)
		}
	}
	return ""
}

// ScoreID is the public id of a score: "sc_" + 24 hex of a sha256 over its
// key fields, joined by 0x1f.
func ScoreID(traceID, spanID, key, source, author string) string {
	h := sha256.New()
	for i, part := range []string{traceID, spanID, key, source, author} {
		if i > 0 {
			h.Write([]byte{0x1f})
		}
		h.Write([]byte(part))
	}
	return "sc_" + hex.EncodeToString(h.Sum(nil))[:24]
}

// CommentHash is the sha256 hex of a (scrubbed) comment, "" for none.
func CommentHash(comment string) string {
	if comment == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(comment))
	return hex.EncodeToString(sum[:])
}

// DecodeBatch decodes a write body: one score object, or {"scores": [...]}
// with 1-MaxBatch scores.
func DecodeBatch(body []byte) ([]Input, *Error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 || body[0] != '{' {
		return nil, errf(CodeBadRequest, "the body must be a JSON object")
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(body, &probe); err != nil {
		return nil, errf(CodeBadRequest, "the body is not valid JSON")
	}
	if raw, ok := probe["scores"]; ok {
		var list []Input
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil, errf(CodeBadRequest, "scores must be an array of score objects")
		}
		if len(list) == 0 {
			return nil, errf(CodeBadRequest, "scores is empty")
		}
		if len(list) > MaxBatch {
			return nil, errf(CodeTooMany, "at most %d scores per request (got %d)", MaxBatch, len(list))
		}
		return list, nil
	}
	var one Input
	if err := json.Unmarshal(body, &one); err != nil {
		return nil, errf(CodeBadRequest, "the body is not a score object")
	}
	return []Input{one}, nil
}

// failLabels are categorical values that count as not passed.
var failLabels = map[string]bool{"fail": true, "failed": true, "false": true, "no": true, "bad": true, "incorrect": true}

// Passed is the pass/fail reading of a score for run tallies (contract
// experiments.md 4.2): boolean true, numeric ≥ 0.5, categorical not a fail
// label.
func Passed(kind Kind, value string, num *float64) bool {
	switch kind {
	case KindBoolean, KindNumeric:
		return num != nil && *num >= 0.5
	default:
		return value != "" && !failLabels[strings.ToLower(value)]
	}
}
