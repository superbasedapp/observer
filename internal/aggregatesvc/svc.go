//go:build !sbo_omit_egress_aggregate_share

package aggregatesvc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/aggregate"
	"github.com/marmutapp/superbased-observer/internal/aggregateclient"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Store is the node-local persistence the collector needs: the consent receipt
// and the per-month submission ledger. *store.Store satisfies it; a fake
// satisfies it in tests. It is the ONLY door to SQL — the collector itself
// writes none.
type Store interface {
	LoadConsentReceipt(ctx context.Context) (*aggregate.Receipt, error)
	LoadAggregateState(ctx context.Context, month string) (*store.AggregateSubmissionRow, error)
	StartAggregateAttempt(ctx context.Context, month, submissionID, payloadHash, payloadJSON string, schemaVersion int, now time.Time) (string, error)
	MarkAggregateSubmitted(ctx context.Context, month string, now time.Time) error
	MarkAggregateFailed(ctx context.Context, month, errMsg string, now time.Time) error
	ListAggregateStates(ctx context.Context) ([]store.AggregateSubmissionRow, error)
}

// Builder assembles the pure aggregate submission for a finalized month with a
// given submission_id. The real implementation (wired in cmd) reads the joint
// (model x tool) cost cut through internal/aggregatesource; a fixture builder
// stands in for unit tests. It is the collector's ONLY door to the local
// tables — the collector never touches the DB directly.
type Builder func(ctx context.Context, month, submissionID string) (aggregate.Submission, error)

// Submitter is the egress capability the collector needs, implemented by
// *aggregateclient.Client. Submit requires a Gate that only
// aggregateclient.Authorize (on ConsentValid) can mint, so an unconsented send
// is structurally impossible even through this indirection.
type Submitter interface {
	Submit(ctx context.Context, gate aggregateclient.Gate, sub aggregate.Submission) error
	Endpoint() string
}

// Config wires a Collector. Store, Build, and Live are required; the rest have
// safe production defaults (real Authorize/aggregateclient, wall clock, random
// id) that tests may override.
type Config struct {
	Store Store
	Build Builder
	// Live returns the current runtime posture the consent receipt is checked
	// against (enabled flag, wire schema version, endpoint, tool-registry
	// version). Re-read on every call so `enable`/`disable` take effect
	// without a restart (design §6.6).
	Live func() aggregate.LiveState

	// Authorize mints a consent Gate from a status; defaults to
	// aggregateclient.Authorize (only ConsentValid mints).
	Authorize func(aggregate.ConsentStatus) (aggregateclient.Gate, error)
	// NewClient builds the egress client for an endpoint; defaults to a thin
	// wrapper over aggregateclient.New. Constructed lazily at real-send time,
	// so the inert / dry-run paths never build one.
	NewClient func(endpoint string) (Submitter, error)
	// Now is the clock (default time.Now().UTC); NewID mints a fresh random
	// submission_id (default 16-byte hex, uuid4-class).
	Now   func() time.Time
	NewID func() string
}

// Collector is the single node-side aggregate-submission seam (design §6).
type Collector struct {
	store     Store
	build     Builder
	live      func() aggregate.LiveState
	authorize func(aggregate.ConsentStatus) (aggregateclient.Gate, error)
	newClient func(endpoint string) (Submitter, error)
	now       func() time.Time
	newID     func() string
}

// New validates required deps and fills production defaults.
func New(cfg Config) (*Collector, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("aggregatesvc.New: Store is required")
	}
	if cfg.Build == nil {
		return nil, fmt.Errorf("aggregatesvc.New: Build is required")
	}
	if cfg.Live == nil {
		return nil, fmt.Errorf("aggregatesvc.New: Live is required")
	}
	c := &Collector{
		store:     cfg.Store,
		build:     cfg.Build,
		live:      cfg.Live,
		authorize: cfg.Authorize,
		newClient: cfg.NewClient,
		now:       cfg.Now,
		newID:     cfg.NewID,
	}
	if c.authorize == nil {
		c.authorize = aggregateclient.Authorize
	}
	if c.newClient == nil {
		c.newClient = defaultNewClient
	}
	if c.now == nil {
		c.now = func() time.Time { return time.Now().UTC() }
	}
	if c.newID == nil {
		c.newID = randomID
	}
	return c, nil
}

// Result describes the outcome of a submission attempt so a surface can render
// it. Sub carries the built payload for preview/dry-run rendering; it is the
// exact allow-listed wire shape and carries no content.
type Result struct {
	Month        string
	Status       aggregate.ConsentStatus
	SubmissionID string
	Endpoint     string
	Cells        int
	Bytes        int
	Attempts     int
	Sent         bool   // a real POST happened and succeeded
	DryRun       bool   // built + gated, nothing sent, ledger untouched
	Skipped      string // non-empty reason nothing was sent (already submitted, etc.)
	Sub          aggregate.Submission
}

// StatusReport is the read-only posture surfaced by `observer aggregate
// status`: the live state, the resolved consent status, the current receipt
// (if any), and the per-month ledger.
type StatusReport struct {
	Live    aggregate.LiveState
	Status  aggregate.ConsentStatus
	Receipt *aggregate.Receipt
	States  []store.AggregateSubmissionRow
}

// Preview assembles the exact submission for a finalized month WITHOUT sending
// or touching the ledger — the pure-local trust artifact. It works regardless
// of consent (nothing leaves the machine). An empty month resolves to the
// most-recently-finalized UTC month; a partial/future month is refused.
func (c *Collector) Preview(ctx context.Context, month string) (aggregate.Submission, error) {
	m, err := c.resolveMonth(month)
	if err != nil {
		return aggregate.Submission{}, err
	}
	sub, err := c.build(ctx, m, c.newID())
	if err != nil {
		return aggregate.Submission{}, fmt.Errorf("aggregatesvc.Preview: %w", err)
	}
	return sub, nil
}

// Status loads the current consent posture + submission ledger.
func (c *Collector) Status(ctx context.Context) (StatusReport, error) {
	receipt, err := c.store.LoadConsentReceipt(ctx)
	if err != nil {
		return StatusReport{}, fmt.Errorf("aggregatesvc.Status: %w", err)
	}
	live := c.live()
	states, err := c.store.ListAggregateStates(ctx)
	if err != nil {
		return StatusReport{}, fmt.Errorf("aggregatesvc.Status: %w", err)
	}
	return StatusReport{
		Live:    live,
		Status:  aggregate.CheckConsent(live, receipt),
		Receipt: receipt,
		States:  states,
	}, nil
}

// SubmitMonth runs the full gated lifecycle for one finalized month:
//
//	consent gate -> resolve month -> (reuse submission_id) -> build ->
//	persist attempt (before send) -> egress -> mark submitted/failed.
//
// It PRODUCES NOTHING when consent is absent: the gate is checked first and a
// non-ConsentValid status returns before the payload is ever built, with a
// wrapped ErrNotConsented so the CLI surfaces the exact remedy. --dry-run
// builds + gate-checks but sends nothing and leaves the ledger untouched.
func (c *Collector) SubmitMonth(ctx context.Context, month string, dryRun bool) (Result, error) {
	// (1) Consent gate FIRST — do not build (let alone send) if not consented.
	receipt, err := c.store.LoadConsentReceipt(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("aggregatesvc.SubmitMonth: %w", err)
	}
	live := c.live()
	status := aggregate.CheckConsent(live, receipt)
	gate, err := c.authorize(status)
	if err != nil {
		return Result{Status: status, Endpoint: live.Endpoint}, err
	}

	// (2) Resolve the target month (refuses a partial/future month).
	m, err := c.resolveMonth(month)
	if err != nil {
		return Result{Status: status, Endpoint: live.Endpoint}, err
	}

	// (3) Reuse a persisted submission_id on retry so a lost response cannot
	//     double-count (design §3.1/#14); short-circuit an already-submitted
	//     month.
	prior, err := c.store.LoadAggregateState(ctx, m)
	if err != nil {
		return Result{}, fmt.Errorf("aggregatesvc.SubmitMonth: %w", err)
	}
	submissionID := c.newID()
	attempts := 0
	if prior != nil {
		attempts = prior.Attempts
		if prior.SubmissionID != "" {
			submissionID = prior.SubmissionID
		}
		if prior.State == store.AggregateStateSubmitted && !dryRun {
			return Result{
				Month: m, Status: status, SubmissionID: prior.SubmissionID,
				Attempts: attempts, Endpoint: live.Endpoint, Skipped: "already submitted",
			}, nil
		}
	}

	// (4) Assemble the payload.
	sub, err := c.build(ctx, m, submissionID)
	if err != nil {
		return Result{Status: status, Endpoint: live.Endpoint}, fmt.Errorf("aggregatesvc.SubmitMonth: %w", err)
	}
	payloadJSON, err := json.Marshal(sub)
	if err != nil {
		return Result{}, fmt.Errorf("aggregatesvc.SubmitMonth: marshal: %w", err)
	}

	res := Result{
		Month: m, Status: status, SubmissionID: submissionID, Endpoint: live.Endpoint,
		Cells: len(sub.Cells), Bytes: len(payloadJSON), Attempts: attempts, Sub: sub,
	}

	if dryRun {
		res.DryRun = true
		return res, nil
	}

	// (5) Persist the attempt BEFORE the send (design §6.5). StartAttempt
	//     mints/reuses the id; a reused id means we must rebuild so the wire
	//     carries it.
	usedID, err := c.store.StartAggregateAttempt(ctx, m, submissionID, sha256Hex(payloadJSON), string(payloadJSON), aggregate.SchemaVersion, c.now())
	if err != nil {
		return Result{}, fmt.Errorf("aggregatesvc.SubmitMonth: %w", err)
	}
	if usedID != submissionID {
		sub, err = c.build(ctx, m, usedID)
		if err != nil {
			return Result{}, fmt.Errorf("aggregatesvc.SubmitMonth: rebuild: %w", err)
		}
		res.Sub = sub
		res.Cells = len(sub.Cells)
	}
	res.SubmissionID = usedID

	// (6) Egress through the hardened, Gate-guarded client.
	client, err := c.newClient(live.Endpoint)
	if err != nil {
		_ = c.store.MarkAggregateFailed(ctx, m, err.Error(), c.now())
		return res, fmt.Errorf("aggregatesvc.SubmitMonth: client: %w", err)
	}
	if err := client.Submit(ctx, gate, sub); err != nil {
		_ = c.store.MarkAggregateFailed(ctx, m, err.Error(), c.now())
		return res, fmt.Errorf("aggregatesvc.SubmitMonth: %w", err)
	}
	if err := c.store.MarkAggregateSubmitted(ctx, m, c.now()); err != nil {
		return res, fmt.Errorf("aggregatesvc.SubmitMonth: %w", err)
	}
	res.Sent = true
	return res, nil
}

// SubmitDue is the Phase-5 daemon hook (design §6.6): resolve the
// most-recently-finalized UTC month and submit it iff consent is valid and it
// is not already submitted. It is deliberately QUIET on the inert paths —
// disabled / not consented / already submitted return a Result{Skipped} with a
// nil error so a daemon tick logs nothing noisy and NOTHING is built or sent.
// Wiring this onto the `observer start` scheduler (with the randomized
// intra-window delay) is Phase 5 and intentionally NOT done here.
func (c *Collector) SubmitDue(ctx context.Context) (Result, error) {
	receipt, err := c.store.LoadConsentReceipt(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("aggregatesvc.SubmitDue: %w", err)
	}
	live := c.live()
	status := aggregate.CheckConsent(live, receipt)
	m := aggregate.FinalizedMonth(c.now())
	if status != aggregate.ConsentValid {
		return Result{Month: m, Status: status, Endpoint: live.Endpoint, Skipped: string(status)}, nil
	}
	return c.SubmitMonth(ctx, m, false)
}

// resolveMonth returns the finalized target month: an empty input resolves to
// the most-recently-finalized UTC month; a non-empty input must be a
// fully-elapsed month (the rail never submits a partial/future month).
func (c *Collector) resolveMonth(month string) (string, error) {
	now := c.now()
	if month == "" {
		return aggregate.FinalizedMonth(now), nil
	}
	if !aggregate.IsFinalizedMonth(month, now) {
		return "", fmt.Errorf("aggregatesvc: month %q is not a fully-elapsed UTC month; the rail never submits a partial month", month)
	}
	return month, nil
}

// defaultNewClient wraps aggregateclient.New into the Submitter shape.
func defaultNewClient(endpoint string) (Submitter, error) {
	client, err := aggregateclient.New(endpoint)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// randomID mints a random opaque submission_id (uuid4-class). NOT a machine
// identifier: minted per submission, reused only within a month's retry window.
func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("sub-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
