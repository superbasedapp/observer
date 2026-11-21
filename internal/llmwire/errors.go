package llmwire

import (
	"errors"
	"fmt"
	"strings"
)

// ErrorClass is the retry-relevant class of a non-2xx response.
type ErrorClass string

// Error classes.
const (
	// ClassQuota is a rate limit or quota response.
	ClassQuota ErrorClass = "quota"
	// ClassTimeout is a gateway or request timeout.
	ClassTimeout ErrorClass = "timeout"
	// ClassAuth is a rejected credential.
	ClassAuth ErrorClass = "auth"
	// ClassRequest is a request the server refuses as malformed or too large.
	ClassRequest ErrorClass = "request"
	// ClassServer is a server-side failure.
	ClassServer ErrorClass = "server"
	// ClassOther is any other non-2xx status.
	ClassOther ErrorClass = "other"
)

// statusRule is one row of the classification table: the first row whose
// range contains the status wins.
type statusRule struct {
	from, to int
	class    ErrorClass
}

var statusRules = []statusRule{
	{429, 429, ClassQuota},
	{408, 408, ClassTimeout},
	{504, 504, ClassTimeout},
	{401, 403, ClassAuth},
	{400, 499, ClassRequest},
	{500, 599, ClassServer},
}

// ClassifyStatus maps an HTTP status onto its class.
func ClassifyStatus(status int) ErrorClass {
	for _, r := range statusRules {
		if status >= r.from && status <= r.to {
			return r.class
		}
	}
	return ClassOther
}

// Sentinel errors a caller classifies on with errors.Is.
var (
	// ErrQuota is a quota or rate-limit response (HTTP 429).
	ErrQuota = errors.New("llmwire: provider quota/rate-limit (429)")
	// ErrTimeout is a timed-out call: a deadline, a network timeout, or a
	// 408/504 response.
	ErrTimeout = errors.New("llmwire: provider call timed out")
)

// StatusError is a non-2xx response that is neither quota nor timeout. Body
// is the PROVIDER's error document; callers truncate it before logging.
type StatusError struct {
	StatusCode int
	Class      ErrorClass
	Body       string
}

func (e *StatusError) Error() string {
	b := e.Body
	if len(b) > 256 {
		b = b[:256] + "..."
	}
	return fmt.Sprintf("llmwire: provider status %d (%s): %s", e.StatusCode, e.Class, strings.TrimSpace(b))
}

// ErrorFor turns a non-2xx status and body into the error Complete returns:
// ErrQuota, ErrTimeout, or a *StatusError.
func ErrorFor(status int, body []byte) error {
	switch class := ClassifyStatus(status); class {
	case ClassQuota:
		return ErrQuota
	case ClassTimeout:
		return ErrTimeout
	default:
		return &StatusError{StatusCode: status, Class: class, Body: string(body)}
	}
}
