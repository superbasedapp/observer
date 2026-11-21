package cvss4

import (
	"strings"
)

// Prefix is the version header every CVSS 4.0 vector starts with.
const Prefix = "CVSS:4.0/"

// MaxVectorLen bounds the vector Parse reads. A base vector is 64 bytes; the
// bound only keeps a hostile string from being walked.
const MaxVectorLen = 128

// ErrorCode names why a vector was refused. The set is closed so a caller can
// table-drive its reaction (the assessment validator maps each code to one
// refusal row) and never has to echo the agent's text.
type ErrorCode string

// The refusal codes of Parse.
const (
	// CodeEmpty is an empty vector.
	CodeEmpty ErrorCode = "empty"
	// CodeTooLong is a vector longer than MaxVectorLen.
	CodeTooLong ErrorCode = "too_long"
	// CodeBadPrefix is a vector that does not start with "CVSS:4.0/" (another
	// version, or no header).
	CodeBadPrefix ErrorCode = "bad_prefix"
	// CodeBadSyntax is a part that is not KEY:VALUE.
	CodeBadSyntax ErrorCode = "bad_syntax"
	// CodeNotBase is a threat, environmental or supplemental metric. A copy of
	// an application in an assessment box has none of those, so a base vector
	// that carries one is refused, not scored without it.
	CodeNotBase ErrorCode = "not_base"
	// CodeBadMetric is a metric that does not exist, repeats, or is out of the
	// order the specification fixes.
	CodeBadMetric ErrorCode = "bad_metric"
	// CodeMissingMetric is a vector that stops before SA.
	CodeMissingMetric ErrorCode = "missing_metric"
	// CodeBadValue is a value the metric does not take (including lower case).
	CodeBadValue ErrorCode = "bad_value"
)

// ParseError is the refusal Parse returns. It carries a code and, when the
// refusal is about one of the eleven base metrics, that metric's key (always
// one of Observer's own table keys, never text from the vector).
type ParseError struct {
	Code   ErrorCode
	Metric string
}

// Error describes the refusal without repeating the vector.
func (e *ParseError) Error() string {
	if e.Metric != "" {
		return "cvss4: vector refused: " + string(e.Code) + " at " + e.Metric
	}
	return "cvss4: vector refused: " + string(e.Code)
}

// Base is a parsed, validated CVSS 4.0 base vector: one value for each of the
// eleven base metrics, in vector order.
type Base struct {
	v [11]string
}

// BaseMetricKeys returns the eleven base metric keys in vector order.
func BaseMetricKeys() []string {
	out := make([]string, len(baseMetricDefs))
	for i, d := range baseMetricDefs {
		out[i] = d.Key
	}
	return out
}

// Value returns the value of a base metric ("N" for "AV" in a network
// vector), and false for a key that is not a base metric.
func (b Base) Value(key string) (string, bool) {
	for i, d := range baseMetricDefs {
		if d.Key == key {
			return b.v[i], true
		}
	}
	return "", false
}

// Vector returns the canonical vector string.
func (b Base) Vector() string {
	var sb strings.Builder
	sb.WriteString(Prefix)
	for i, d := range baseMetricDefs {
		if i > 0 {
			sb.WriteByte('/')
		}
		sb.WriteString(d.Key)
		sb.WriteByte(':')
		sb.WriteString(b.v[i])
	}
	return sb.String()
}

func isKnownMetric(key string) bool {
	for _, k := range knownMetricKeys {
		if k == key {
			return true
		}
	}
	return false
}

func validValue(d baseMetricDef, v string) bool {
	for _, ok := range d.Values {
		if ok == v {
			return true
		}
	}
	return false
}

// Parse reads a CVSS 4.0 base vector. The grammar is exact: the "CVSS:4.0/"
// header, then the eleven base metrics AV AC AT PR UI VC VI VA SC SI SA, once
// each, in that order, each as KEY:VALUE with a value from the metric's own
// set, separated by "/", with nothing before or after (no spaces, no
// trailing slash, no lower case). Anything else is a *ParseError with a code
// from the closed set above.
func Parse(vector string) (Base, error) {
	var b Base
	switch {
	case vector == "":
		return b, &ParseError{Code: CodeEmpty}
	case len(vector) > MaxVectorLen:
		return b, &ParseError{Code: CodeTooLong}
	case !strings.HasPrefix(vector, Prefix):
		return b, &ParseError{Code: CodeBadPrefix}
	}
	parts := strings.Split(vector[len(Prefix):], "/")
	for i, part := range parts {
		key, value, ok := strings.Cut(part, ":")
		if !ok || key == "" || value == "" || strings.Contains(value, ":") {
			return Base{}, &ParseError{Code: CodeBadSyntax}
		}
		if i >= len(baseMetricDefs) {
			if isKnownMetric(key) {
				return Base{}, &ParseError{Code: CodeNotBase}
			}
			return Base{}, &ParseError{Code: CodeBadMetric}
		}
		d := baseMetricDefs[i]
		if key != d.Key {
			if isKnownMetric(key) && !isBaseKey(key) {
				return Base{}, &ParseError{Code: CodeNotBase}
			}
			return Base{}, &ParseError{Code: CodeBadMetric, Metric: d.Key}
		}
		if !validValue(d, value) {
			return Base{}, &ParseError{Code: CodeBadValue, Metric: d.Key}
		}
		b.v[i] = value
	}
	if len(parts) < len(baseMetricDefs) {
		return Base{}, &ParseError{Code: CodeMissingMetric, Metric: baseMetricDefs[len(parts)].Key}
	}
	return b, nil
}

func isBaseKey(key string) bool {
	for _, d := range baseMetricDefs {
		if d.Key == key {
			return true
		}
	}
	return false
}
