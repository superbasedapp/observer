package planlimits

import (
	"errors"
	"fmt"
	"io"
	"time"
)

// Driver errors. Drivers wrap one of these so the backoff table can classify
// an outcome without reading prose.
var (
	// ErrShape: a 2xx body without the documented shape (the driver canary).
	// Counts toward endpoint_changed; never stored as zero.
	ErrShape = errors.New("planlimits: unexpected response shape")
	// ErrAuth: the credential was refused or is missing / expired. Polling
	// stops until the user acts; Observer never refreshes another app's token.
	ErrAuth = errors.New("planlimits: sign-in needed")
	// ErrRateLimited: the vendor asked us to slow down (429 / 503).
	ErrRateLimited = errors.New("planlimits: rate limited")
	// ErrTransient: a network error, timeout or 5xx.
	ErrTransient = errors.New("planlimits: transient failure")
	// ErrGone: the endpoint answered 404 / 410.
	ErrGone = errors.New("planlimits: endpoint not found")
	// ErrNotApplicable: the account cannot report through this source (an
	// API-key login, a seat billed to an org). Not a failure of the source.
	ErrNotApplicable = errors.New("planlimits: not applicable to this account")
	// ErrUnavailable: the vendor tool or file is not on this machine.
	ErrUnavailable = errors.New("planlimits: not available on this machine")
)

// ReqKind is how a Request is executed.
type ReqKind string

// Request kinds.
const (
	ReqHTTP ReqKind = "http" // one HTTPS call through internal/planlimitsnet
	ReqExec ReqKind = "exec" // a vendor CLI run with a fixed argv, no shell
)

// Request is one action a driver needs performed. It is built purely; the
// egress package performs it. SecretHeaders carry credential values and are
// never logged, stored or returned.
type Request struct {
	Key           string
	Kind          ReqKind
	Method        string
	URL           string
	Header        map[string]string
	SecretHeaders map[string]string
	Body          []byte
	// Optional: a failure of this request does not fail the refresh.
	Optional bool
	// Base is the account's self-hosted gateway base URL (ledger SUBS-5).
	// Only a UserBaseURL source sets it; the egress package checks the
	// request against it and refuses it on any fixed-host source. It is
	// never sent.
	Base string
	// Argv / Env / Timeout apply to ReqExec.
	Argv    []string
	Env     []string
	Timeout time.Duration
}

// Response is the outcome of one Request. Body is capped by the egress
// package. For ReqExec, Status is the exit code and Body is the output.
type Response struct {
	Key        string
	Status     int
	RetryAfter time.Duration
	Body       []byte
	Err        error // transport error (wrapped ErrTransient / ErrUnavailable)
}

// PlanInput is everything a driver may read to plan a refresh.
type PlanInput struct {
	Params  map[string]string
	Secrets map[string]string // from the keystore, in memory only
	Local   map[string][]byte // vendor-local reads, in memory only
	Now     time.Time
}

// ParseInput is everything a driver may read to build a snapshot.
type ParseInput struct {
	Params    map[string]string
	Local     map[string][]byte
	Responses map[string]Response
	Now       time.Time
}

// Driver is the pure half of one source.
type Driver struct {
	// Plan returns the requests to perform. nil requests with a nil error is
	// valid (a manual or local-only source).
	Plan func(PlanInput) ([]Request, error)
	// Parse maps the responses onto a snapshot.
	Parse func(ParseInput) (Snapshot, error)
	// Converse, when set, drives a vendor process over its stdin/stdout
	// instead of Plan/Parse (the codex app-server JSON-RPC session).
	Converse func(w io.Writer, r io.Reader, in PlanInput) (Snapshot, error)
	// Argv is the process Converse talks to.
	Argv []string
}

// Drivers maps a source id to its driver. Passive sources have none: they are
// mapped by the passive functions over data Observer already has.
var Drivers = map[string]Driver{}

// register adds a driver; each driver file calls it from init.
func register(id string, d Driver) { Drivers[id] = d }

// httpErr turns a non-2xx response or a transport error into a classified
// error; nil for a 2xx.
func httpErr(r Response, ok bool) error {
	switch {
	case !ok:
		return fmt.Errorf("%w: no response", ErrTransient)
	case r.Err != nil:
		return r.Err
	case r.Status >= 200 && r.Status < 300:
		return nil
	case r.Status == 401 || r.Status == 403:
		return fmt.Errorf("%w: http %d", ErrAuth, r.Status)
	case r.Status == 429 || r.Status == 503:
		return fmt.Errorf("%w: http %d", ErrRateLimited, r.Status)
	case r.Status == 404 || r.Status == 410:
		return fmt.Errorf("%w: http %d", ErrGone, r.Status)
	default:
		return fmt.Errorf("%w: http %d", ErrTransient, r.Status)
	}
}

// need returns the response body for key, or the classified error.
func need(in ParseInput, key string) ([]byte, error) {
	r, ok := in.Responses[key]
	if err := httpErr(r, ok); err != nil {
		return nil, err
	}
	return r.Body, nil
}

// bearer builds a secret Authorization header map.
func bearer(tok string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + tok}
}

// shapeErr wraps ErrShape with context.
func shapeErr(what string, err error) error {
	if err != nil {
		return fmt.Errorf("%w: %s: %s", ErrShape, what, err.Error())
	}
	return fmt.Errorf("%w: %s", ErrShape, what)
}
