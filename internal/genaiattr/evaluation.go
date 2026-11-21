package genaiattr

import "strings"

// The gen_ai.evaluation.result event (Plane A build-out W3-1, lane B7;
// contract docs/plans/plane-a-sdk-buildout/contracts/scores.md section 4).
// The pinned semconv defines it as an event carried either as a span event on
// the evaluated span or as a log record whose span context names that span.
// Its keys are rows of the one vocabulary table (evaluationRows, mounted in
// registry.go), so the node mapper and the gateway mapper read the same names.

// EvaluationEventName is the event name of an evaluation result.
const EvaluationEventName = "gen_ai.evaluation.result"

// Evaluation fields.
const (
	FieldEvalName        Field = "evaluation_name"
	FieldEvalScoreValue  Field = "evaluation_score_value"
	FieldEvalScoreLabel  Field = "evaluation_score_label"
	FieldEvalExplanation Field = "evaluation_explanation"
	// The superbased.* extension keys: an idempotency id, a feedback marker,
	// an experiment run and the scorer that produced the value.
	FieldEvalScoreID       Field = "evaluation_score_id"
	FieldEvalSource        Field = "evaluation_source"
	FieldEvalRunID         Field = "evaluation_run_id"
	FieldEvalScorerName    Field = "evaluation_scorer_name"
	FieldEvalScorerVersion Field = "evaluation_scorer_version"
)

// evaluationRows are the evaluation event's vocabulary rows.
func evaluationRows() []Key {
	return concat(
		rows(FieldEvalName, "gen_ai.evaluation.name", g),
		rows(FieldEvalScoreValue, "gen_ai.evaluation.score.value", g),
		rows(FieldEvalScoreLabel, "gen_ai.evaluation.score.label", g),
		rows(FieldEvalExplanation, "gen_ai.evaluation.explanation", g),
		rows(FieldEvalScoreID, "superbased.score.id", gn),
		rows(FieldEvalSource, "superbased.score.source", gn),
		rows(FieldEvalRunID, "superbased.score.run_id", gn),
		rows(FieldEvalScorerName, "superbased.scorer.name", gn),
		rows(FieldEvalScorerVersion, "superbased.scorer.version", gn),
	)
}

// Evaluation is one decoded gen_ai.evaluation.result event. ScoreValue is nil
// when the event carried no numeric score.
type Evaluation struct {
	Name          string
	ScoreValue    *float64
	Label         string
	Explanation   string
	ErrorType     string
	ScoreID       string
	Source        string
	RunID         string
	ScorerName    string
	ScorerVersion string
}

// IsEvaluationEvent reports whether an event or log record name is the
// evaluation result. The match is exact (the semconv name), after trimming.
func IsEvaluationEvent(name string) bool {
	return strings.TrimSpace(name) == EvaluationEventName
}

// ReadEvaluation decodes an evaluation event's attributes. It validates
// nothing: internal/scorecore decides what is a valid score.
func ReadEvaluation(a Attrs) Evaluation {
	return Evaluation{
		Name:          a.First(Keys(FieldEvalName)),
		ScoreValue:    a.Float(Keys(FieldEvalScoreValue)),
		Label:         a.First(Keys(FieldEvalScoreLabel)),
		Explanation:   a.First(Keys(FieldEvalExplanation)),
		ErrorType:     a.First(Keys(FieldErrorType)),
		ScoreID:       a.First(Keys(FieldEvalScoreID)),
		Source:        a.First(Keys(FieldEvalSource)),
		RunID:         a.First(Keys(FieldEvalRunID)),
		ScorerName:    a.First(Keys(FieldEvalScorerName)),
		ScorerVersion: a.First(Keys(FieldEvalScorerVersion)),
	}
}
