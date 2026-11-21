package scorecore

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/genaiattr"
)

// Refusal codes of an evaluation event that is not stored (contract
// scores.md section 4). They are counted by the caller, never silent.
const (
	CodeEvaluationError = "evaluation_error"
	CodeNoValue         = "no_value"
)

// FromEvaluation turns one gen_ai.evaluation.result event into a score.
// traceID and spanID are the evaluated span; at is the event time, part of
// the author digest when the event carries no superbased.score.id, so a
// re-delivered event lands on the same row.
func FromEvaluation(ev genaiattr.Evaluation, traceID, spanID string, at time.Time) (Score, *Error) {
	if strings.TrimSpace(ev.ErrorType) != "" {
		return Score{}, errf(CodeEvaluationError, "the evaluation reported error.type %q", ev.ErrorType)
	}
	var s Score
	var e *Error
	if s.TraceID, e = NormalizeTraceID(traceID); e != nil {
		return Score{}, e
	}
	if s.SpanID, e = NormalizeSpanID(spanID); e != nil {
		return Score{}, e
	}
	if s.Key, e = NormalizeName(ev.Name); e != nil {
		return Score{}, e
	}
	label := strings.TrimSpace(ev.Label)
	switch {
	case ev.ScoreValue != nil:
		f := *ev.ScoreValue
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return Score{}, errf(CodeInvalidValue, "gen_ai.evaluation.score.value is not finite")
		}
		s.Kind, s.ValueNum, s.Value = KindNumeric, &f, NumericText(f)
		if label != "" {
			if txt, err := CategoricalText(label); err == nil {
				s.Value = txt
			}
		}
	case label != "":
		if s.Value, e = CategoricalText(label); e != nil {
			return Score{}, e
		}
		s.Kind = KindCategorical
	default:
		return Score{}, errf(CodeNoValue, "the evaluation carried neither score.value nor score.label")
	}
	s.Source = SourceOTel
	if strings.EqualFold(strings.TrimSpace(ev.Source), string(SourceFeedback)) {
		s.Source = SourceFeedback
	}
	id := strings.TrimSpace(ev.ScoreID)
	if id != "" && (len(id) > MaxIDLen || !idPattern.MatchString(id)) {
		return Score{}, errf(CodeInvalidID, "superbased.score.id must be 1-%d characters of [A-Za-z0-9_.:-]", MaxIDLen)
	}
	s.ClientID = id
	if len(ev.Explanation) > MaxCommentBytes {
		return Score{}, errf(CodeCommentTooLong, "gen_ai.evaluation.explanation is at most %d bytes", MaxCommentBytes)
	}
	s.Comment = strings.TrimSpace(ev.Explanation)
	s.ScorerName = clipTo(strings.TrimSpace(ev.ScorerName), MaxScorerNameLen)
	s.ScorerVersion = clipTo(strings.TrimSpace(ev.ScorerVersion), MaxScorerVersionLen)
	if r := strings.TrimSpace(ev.RunID); r != "" && len(r) <= MaxRunIDLen && idPattern.MatchString(r) {
		s.RunID = r
	}
	s.At = at.UTC()
	digest := ""
	if id == "" {
		digest = eventDigest(s.TraceID, s.SpanID, s.Key, at)
	}
	// Under feedback the event digest still keys the row (an id-less
	// feedback event is one row per event).
	parts := AuthorParts{ID: id, EventDigest: digest}
	s.Author = AuthorKey(s.Source, parts)
	if s.Author == "" {
		s.Author = "ev:" + digest
	}
	return s, nil
}

func eventDigest(traceID, spanID, key string, at time.Time) string {
	sum := sha256.Sum256([]byte(traceID + "\x1f" + spanID + "\x1f" + key + "\x1f" + strconv.FormatInt(at.UnixNano(), 10)))
	return hex.EncodeToString(sum[:])[:16]
}

// clipTo bounds an optional descriptive field from an event (an event's
// scorer name is advisory, so an over-long one is cut, never refused).
func clipTo(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
