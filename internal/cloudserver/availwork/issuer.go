package availwork

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/availcompose"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/components"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// Defaults.
const (
	// DefaultMaxSignAttempts bounds how often one issue asks the signer
	// again after a version_not_newer answer.
	DefaultMaxSignAttempts = 4
	// DefaultMaxFailures is how many passes in a row one request may fail
	// (signer or store unreachable) before it is marked failed.
	DefaultMaxFailures = 5
)

// IssueStore is the issuer's store seam (*store.Store bound to sbci_worker).
type IssueStore interface {
	PendingAvailabilityIssue(ctx context.Context) (store.AvailabilityIssueRequest, error)
	AvailabilityInputsForIssue(ctx context.Context) ([]store.AvailabilityInputRow, error)
	LatestAvailabilityDocument(ctx context.Context) (pc.AvailabilityDocument, error)
	DocumentVersionFloor(ctx context.Context, kind pc.DocumentKind, scope string) (int64, error)
	IssueAvailabilityDocument(ctx context.Context, requestID string, doc pc.AvailabilityDocument, issuedBy string, issuedAt time.Time) error
	FinishAvailabilityIssue(ctx context.Context, requestID, state, errorClass string, now time.Time) error
}

// Signer signs an availability body at a version (the document signer's
// sign_document for kind availability). An error wrapping
// platformcontract.ErrVersionNotNewer means it already signed that version
// or a later one.
type Signer interface {
	SignAvailability(ctx context.Context, version int64, body []byte) (sig []byte, keyID string, err error)
}

// SignerFunc adapts a function to Signer.
type SignerFunc func(ctx context.Context, version int64, body []byte) ([]byte, string, error)

// SignAvailability implements Signer.
func (f SignerFunc) SignAvailability(ctx context.Context, version int64, body []byte) ([]byte, string, error) {
	return f(ctx, version, body)
}

// IssuerConfig configures an Issuer. Store, Signer and Keys are required.
type IssuerConfig struct {
	Store  IssueStore
	Signer Signer
	// Keys verifies every signed envelope before it is stored: the keys
	// every host verifies under. The worker passes the compiled-in
	// availability keys when the build has any (hosts prefer them,
	// orgavail.HostAvailabilityKeys), else the signer's published
	// availability keys.
	Keys pc.KeySet
	// Now is the clock (nil: time.Now).
	Now func() time.Time
	// MaxSignAttempts bounds the signer retries (0: DefaultMaxSignAttempts).
	MaxSignAttempts int
	// MaxFailures bounds the failed passes of one request (0:
	// DefaultMaxFailures).
	MaxFailures int
}

// Issuer carries out availability issue requests. One Issuer runs in one
// worker; the store keeps two workers from issuing one request twice.
type Issuer struct {
	cfg      IssuerConfig
	failures map[string]int
}

// NewIssuer builds an Issuer.
func NewIssuer(cfg IssuerConfig) (*Issuer, error) {
	if cfg.Store == nil || cfg.Signer == nil || len(cfg.Keys) == 0 {
		return nil, errors.New("availwork.NewIssuer: Store, Signer and Keys are required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MaxSignAttempts <= 0 {
		cfg.MaxSignAttempts = DefaultMaxSignAttempts
	}
	if cfg.MaxFailures <= 0 {
		cfg.MaxFailures = DefaultMaxFailures
	}
	return &Issuer{cfg: cfg, failures: map[string]int{}}, nil
}

// Outcome is what one IssueOnce did.
type Outcome string

// Outcomes.
const (
	// OutcomeIdle: no request is pending.
	OutcomeIdle Outcome = "idle"
	// OutcomeIssued: a new envelope was signed and stored.
	OutcomeIssued Outcome = "issued"
	// OutcomeStale: the request was refused as stale (error class says why).
	OutcomeStale Outcome = "stale"
	// OutcomeFailed: the request was marked failed.
	OutcomeFailed Outcome = "failed"
	// OutcomeRetry: this pass failed; the request stays pending.
	OutcomeRetry Outcome = "retry"
)

// Stale and failed error classes (availability_issue_requests.error_class).
const (
	ClassInputsChanged = "inputs_changed"
	ClassVersionMoved  = "version_moved"
	ClassNothingToDo   = "nothing_to_issue"
	ClassInvalidInputs = "invalid_inputs"
	ClassCompose       = "compose"
	ClassSign          = "sign"
	ClassVerify        = "verify"
	ClassStore         = "store"
)

// staleRule is one row of the staleness table, walked top down before a
// request is signed: the first match refuses it with its class.
type staleRule struct {
	class string
	stale func(f issueFacts) bool
}

// issueFacts is what the issuer read for one request.
type issueFacts struct {
	req      store.AvailabilityIssueRequest
	digest   string
	base     int64
	prev     *pc.AvailabilityBody
	composed availcompose.Composed
}

var staleRules = []staleRule{
	{class: ClassInputsChanged, stale: func(f issueFacts) bool { return f.digest != f.req.InputsDigest }},
	{class: ClassVersionMoved, stale: func(f issueFacts) bool { return f.base != f.req.BaseVersion }},
	{class: ClassNothingToDo, stale: func(f issueFacts) bool {
		return len(f.composed.Problems) == 0 && len(availcompose.Diff(f.prev, &f.composed.Body)) == 0
	}},
}

// IssueOnce carries out the pending request, if any.
func (i *Issuer) IssueOnce(ctx context.Context) (Outcome, error) {
	req, err := i.cfg.Store.PendingAvailabilityIssue(ctx)
	if errors.Is(err, store.ErrNotFound) {
		// A request finished elsewhere (cancelled by staff) leaves no
		// failure count behind.
		clear(i.failures)
		return OutcomeIdle, nil
	}
	if err != nil {
		return OutcomeRetry, fmt.Errorf("availwork.IssueOnce: pending: %w", err)
	}
	out, err := i.issue(ctx, req)
	if out == OutcomeRetry {
		i.failures[req.RequestID]++
		if i.failures[req.RequestID] >= i.cfg.MaxFailures {
			class := ClassSign
			if errors.Is(err, errStoreStep) {
				class = ClassStore
			}
			if ferr := i.finish(ctx, req, store.IssueStateFailed, class); ferr != nil {
				return OutcomeRetry, errors.Join(err, ferr)
			}
			delete(i.failures, req.RequestID)
			return OutcomeFailed, err
		}
		return OutcomeRetry, err
	}
	delete(i.failures, req.RequestID)
	return out, err
}

// errStoreStep marks a retryable failure of a store read or write.
var errStoreStep = errors.New("availwork: store step failed")

func (i *Issuer) finish(ctx context.Context, req store.AvailabilityIssueRequest, state, class string) error {
	err := i.cfg.Store.FinishAvailabilityIssue(ctx, req.RequestID, state, class, i.cfg.Now())
	if err != nil && !errors.Is(err, store.ErrIssueNotPending) {
		return fmt.Errorf("availwork: finish %s: %w", req.RequestID, err)
	}
	return nil
}

func (i *Issuer) issue(ctx context.Context, req store.AvailabilityIssueRequest) (Outcome, error) {
	now := i.cfg.Now()
	f, err := i.read(ctx, req, now)
	if err != nil {
		return OutcomeRetry, err
	}
	for _, r := range staleRules {
		if r.stale(f) {
			return OutcomeStale, i.finish(ctx, req, store.IssueStateStale, r.class)
		}
	}
	if len(f.composed.Problems) > 0 {
		return OutcomeFailed, i.finish(ctx, req, store.IssueStateFailed, ClassInvalidInputs)
	}
	floor, err := i.cfg.Store.DocumentVersionFloor(ctx, pc.KindAvailability, pc.AvailabilityScope)
	if err != nil {
		return OutcomeRetry, fmt.Errorf("availwork: version floor: %w: %w", errStoreStep, err)
	}
	last := max(f.base, floor)
	doc, err := i.sign(ctx, max(last+1, now.Unix()), f.composed.JSON)
	if err != nil {
		return OutcomeRetry, err
	}
	if err := Verify(doc, i.cfg.Keys, last); err != nil {
		return OutcomeFailed, errors.Join(fmt.Errorf("availwork: the signed envelope does not verify: %w", err),
			i.finish(ctx, req, store.IssueStateFailed, ClassVerify))
	}
	switch err := i.cfg.Store.IssueAvailabilityDocument(ctx, req.RequestID, doc, req.RequestedBy, now); {
	case err == nil:
		return OutcomeIssued, nil
	case errors.Is(err, pc.ErrVersionNotNewer):
		return OutcomeStale, i.finish(ctx, req, store.IssueStateStale, ClassVersionMoved)
	case errors.Is(err, store.ErrIssueNotPending):
		return OutcomeStale, nil
	default:
		return OutcomeRetry, fmt.Errorf("availwork: store: %w: %w", errStoreStep, err)
	}
}

// read gathers the facts the staleness table and the composer need.
func (i *Issuer) read(ctx context.Context, req store.AvailabilityIssueRequest, now time.Time) (issueFacts, error) {
	rows, err := i.cfg.Store.AvailabilityInputsForIssue(ctx)
	if err != nil {
		return issueFacts{}, fmt.Errorf("availwork: inputs: %w: %w", errStoreStep, err)
	}
	inputs := InputsFromRows(rows)
	f := issueFacts{req: req, digest: availcompose.Digest(inputs)}
	latest, err := i.cfg.Store.LatestAvailabilityDocument(ctx)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return issueFacts{}, fmt.Errorf("availwork: latest envelope: %w: %w", errStoreStep, err)
	default:
		f.base = latest.Version
		if b, derr := availcompose.DecodeBody(latest.Body); derr == nil {
			f.prev = &b
		}
	}
	f.composed, err = availcompose.Compose(inputs, now)
	if err != nil {
		// A rule across rows that the rows alone pass: report it as a
		// problem rather than retry forever.
		f.composed = availcompose.Composed{Problems: []availcompose.Problem{{Section: "body", Key: "-", Reason: err.Error()}}}
	}
	return f, nil
}

// sign asks the signer for version, bumping it after each version_not_newer
// answer, at most MaxSignAttempts times.
func (i *Issuer) sign(ctx context.Context, version int64, body []byte) (pc.AvailabilityDocument, error) {
	var err error
	for range i.cfg.MaxSignAttempts {
		var sig []byte
		var keyID string
		sig, keyID, err = i.cfg.Signer.SignAvailability(ctx, version, body)
		if err == nil {
			return pc.AvailabilityDocument{Version: version, Body: body, Signature: sig, KeyID: keyID}, nil
		}
		if !errors.Is(err, pc.ErrVersionNotNewer) {
			break
		}
		version++
	}
	return pc.AvailabilityDocument{}, fmt.Errorf("availwork: sign: %w", err)
}

// Verify checks a signed envelope the way a pooled host accepts one
// (orgavail.AcceptEnvelope), stricter where the issuer must be: the
// signature under keys and the version above last, then the body decoded
// strictly, its rules, and the catalog's with no unknown component.
func Verify(doc pc.AvailabilityDocument, keys pc.KeySet, last int64) error {
	if err := pc.VerifyAvailability(doc, keys, last); err != nil {
		return err
	}
	b, err := availcompose.DecodeBody(doc.Body)
	if err != nil {
		return err
	}
	return components.CheckEnvelope(b)
}

// InputsFromRows turns stored inputs into the composer's inputs.
func InputsFromRows(rows []store.AvailabilityInputRow) []availcompose.Input {
	out := make([]availcompose.Input, 0, len(rows))
	for _, r := range rows {
		out = append(out, availcompose.Input{Section: r.Section, Key: r.Key, Value: r.Value, Reason: r.Reason, Author: r.Author})
	}
	return out
}
