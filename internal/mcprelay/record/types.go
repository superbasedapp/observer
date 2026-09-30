// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package record

import (
	"context"
	"errors"
	"fmt"
)

// Kind discriminates the rows of the ONE node relay chain (R12.7 / R14.2):
// every kind draws its seq from the same AUTOINCREMENT id space and links into
// the same chain_prev/chain_hash chain.
type Kind string

// Record kinds. Every live enum of mcp_relay_record.record_kind lists all
// four (R14.2).
const (
	KindDecision      Kind = "decision"
	KindCompletion    Kind = "completion"
	KindGap           Kind = "gap"
	KindGapResolution Kind = "gap_resolution"
)

// Kinds returns every record kind in DDL order.
func Kinds() []Kind {
	return []Kind{KindDecision, KindCompletion, KindGap, KindGapResolution}
}

// EventKind is the MCP node event enum stamped on a decision row.
type EventKind string

// Event kinds (mcp_relay_record.event_kind).
const (
	EventCall      EventKind = "mcp_call"
	EventList      EventKind = "mcp_list"
	EventRead      EventKind = "mcp_read"
	EventPrompt    EventKind = "mcp_prompt"
	EventSubscribe EventKind = "mcp_subscribe"
	EventTask      EventKind = "mcp_task"
	EventDeny      EventKind = "mcp_deny"
)

// Decision is the relay's verdict on a decision row.
type Decision string

// Decisions (mcp_relay_record.decision).
const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
	DecisionAsk   Decision = "ask"
)

// ClientAttestation is how strongly the calling client was identified.
type ClientAttestation string

// Client attestation levels (mcp_relay_record.client_attestation).
const (
	AttestProcess    ClientAttestation = "process_attested"
	AttestIPCBound   ClientAttestation = "ipc_bound"
	AttestConfigured ClientAttestation = "configured"
	AttestClaimed    ClientAttestation = "claimed"
)

// CaptureLevel is the EFFECTIVE content-capture level of a decision or
// completion row (R14.2: NULL on gap / gap_resolution rows).
type CaptureLevel string

// Capture levels (mcp_relay_record.capture_level).
const (
	CaptureL0 CaptureLevel = "L0"
	CaptureL1 CaptureLevel = "L1"
	CaptureL2 CaptureLevel = "L2"
)

// CorrConfidence is how the correlation anchors (coding session / turn /
// action) were established (R10.7).
type CorrConfidence string

// Correlation confidences (mcp_relay_record.corr_confidence).
const (
	CorrExact    CorrConfidence = "exact"
	CorrInferred CorrConfidence = "inferred"
	CorrNone     CorrConfidence = "none"
)

// ScrubStatus is scrub.CaptureJSON's per-field status stored beside every
// L2 payload (R12.9).
type ScrubStatus string

// Scrub statuses (the four *_scrub_status columns).
const (
	ScrubStructured   ScrubStatus = "structured"
	ScrubTextFallback ScrubStatus = "text_fallback"
	ScrubRedacted     ScrubStatus = "redacted"
	ScrubTruncated    ScrubStatus = "truncated"
)

// Resolution is how a gap_resolution row resolves part of a gap (R13.4).
type Resolution string

// Resolutions (mcp_relay_record.resolution).
const (
	ResolutionLateArrival   Resolution = "late_arrival"
	ResolutionConfirmedLoss Resolution = "confirmed_loss"
)

// DefaultFamily is the policy family every relay record belongs to.
const DefaultFamily = "tools.mcp_access"

// Int returns a pointer to v, for the nullable integer columns of a Record.
func Int(v int64) *int64 { return &v }

// Record is one mcp_relay_record row - the node-local, append-only,
// hash-chained relay record (doc3 §3.2, R8.27.a / R12.7 / R14.2). Nullable
// integer columns are pointers (nil = NULL); nullable text columns are ""
// for NULL. Seq, ChainPrev and ChainHash are assigned by Store.Append.
//
// TS is UNIX SECONDS (the gateway chain's unit, internal/mcpgw/audit). The
// gap range columns (GapFrom / GapTo, and a gap_resolution's
// ResolvedRangeStart / ResolvedRangeEnd) are also unix seconds: they bound the
// pending-loss window (first_at .. last_at) of the local-append failures the
// gap accounts for - a failed append has no seq to range over.
type Record struct {
	Seq    int64
	Kind   Kind
	TS     int64
	Family string
	// DecisionSeq points a completion row at its decision row's seq.
	DecisionSeq *int64

	// Resolved targets (decision rows).
	VServer       string
	ServerRefHMAC string
	ToolRefHMAC   string
	Server        string // R10.6: PLAIN name, L2 enrolled teams/enterprise only
	Tool          string // PLAIN name, L2 only

	// Correlation anchors (decision rows).
	CallID          string
	TraceID         string
	CodingSessionID string
	TurnRef         string
	ActionRef       string
	CorrConfidence  CorrConfidence

	// Request / decision side (decision rows).
	Method              string
	EventKind           EventKind
	Decision            Decision
	ReasonCode          string
	ClientAttestation   ClientAttestation
	CredentialAssurance string
	CaptureLevel        CaptureLevel

	// Payloads, capture-gated by the L0/L2 CHECKs: excerpt at L1+, full
	// payloads at L2 only. Args ride the decision row; result / error /
	// elicitation ride the completion row.
	ArgsExcerpt            string
	ArgsFull               string
	ArgsScrubStatus        ScrubStatus
	ResultFull             string
	ResultScrubStatus      ScrubStatus
	ErrorFull              string
	ErrorScrubStatus       ScrubStatus
	ElicitationFull        string
	ElicitationScrubStatus ScrubStatus

	// Outcome (completion rows).
	ResultSizeBytes *int64 // R11.9: content-free, present at L0 too
	LatencyMS       *int64
	ResultStatus    string

	// Gap rows (R12.7 / R13.4).
	GapFrom   *int64
	GapTo     *int64
	LostCount *int64
	GapReason string

	// Gap-resolution rows (R13.4 / R14.3).
	ResolvesSeq        *int64
	ResolvedRangeStart *int64
	ResolvedRangeEnd   *int64
	Resolution         Resolution

	// Chain columns, assigned by Append: ChainPrev is the prior row's
	// ChainHash (Genesis for the first row); ChainHash = HashRecord(
	// Canonical(row), ChainPrev).
	ChainPrev []byte
	ChainHash []byte
}

// AppendResult is what Store.Append produced: the appended record with its
// seq and chain columns, plus the gap record it wrote FIRST (in the same
// transaction) when pending-loss state was outstanding (R13.5 step 3).
type AppendResult struct {
	Record Record
	Gap    *Record
}

// Head is the chain tail: the highest seq and its chain_hash. An empty chain
// reports Seq 0 and the node's Genesis hash.
type Head struct {
	Seq  int64
	Hash []byte
}

// Fault is the first verification failure a chain walk found.
type Fault struct {
	Seq    int64
	Reason string
}

// Error renders the fault.
func (f Fault) Error() string { return fmt.Sprintf("%v at seq %d: %s", ErrTamper, f.Seq, f.Reason) }

// Unwrap makes errors.Is(f, ErrTamper) true.
func (f Fault) Unwrap() error { return ErrTamper }

// VerifyResult summarises a chain walk from genesis.
type VerifyResult struct {
	// Records is the number of records verified before the walk stopped.
	Records int
	// HeadSeq / HeadHash are the last GOOD position.
	HeadSeq  int64
	HeadHash []byte
	// Fault is nil when the whole chain verified.
	Fault *Fault
}

// OK reports whether the walk found no fault.
func (r VerifyResult) OK() bool { return r.Fault == nil }

// PendingLoss is the durable twin of the relay's in-memory local-append
// failure counter (mcp_relay_state.pending_loss_*, R13.5 / R14.4). The relay
// folds its sidecar file into it at startup and after each failed append; the
// NEXT successful Append turns it into a gap record and zeroes it in the same
// transaction.
type PendingLoss struct {
	Count   int64
	FirstAt int64 // unix seconds
	LastAt  int64 // unix seconds
	Reason  string
	// CallIDs holds up to MaxPendingLossCallIDs attempted call ids, for the
	// gap row's diagnostic range.
	CallIDs []string
}

// MaxPendingLossCallIDs caps PendingLoss.CallIDs (doc3 §3.2: "up to 64").
const MaxPendingLossCallIDs = 64

// State is one mcp_relay_state row: the node's applied policy state for a
// family plus its pending-loss accounting.
type State struct {
	Family         string
	RunningVersion int64
	EffectiveHash  string
	Status         string
	Mode           string
	LastApplied    int64
	PendingLoss    PendingLoss
}

// LaunchSpec is one mcp_relay_launch_spec row (R8.18 / finding-28): the
// durable, crash-safe journal of an AI client's ORIGINAL MCP server launch,
// written BEFORE the relay rewrites the client's config entry and read back
// to restore it on disable / uninstall.
//
// OrigEnvRefs carries env KEY NAMES / secret references only - the journal
// never stores an upstream secret value.
type LaunchSpec struct {
	Client      string
	ConfigPath  string
	EntryKey    string
	OrigCommand string
	OrigArgs    []string
	OrigCwd     string
	OrigEnvRefs []string
	// ConfigGeneration is the CAS target: a concurrent rewrite bumps it, and
	// PutLaunchSpec refuses a stale expectation with ErrConflict.
	ConfigGeneration int64
	// BackupPath / BackupSHA256 name the owner-only durable backup file
	// holding the VERBATIM original config bytes and its digest (R8.28.i).
	BackupPath   string
	BackupSHA256 string
	AppliedAt    int64 // unix seconds
	// AppliedSHA256 is the SHA-256 of the config bytes the relay WROTE when
	// it applied this row (node migration 132, Sol P3+P4 finding 7 / R8.18
	// CAS). "" = NULL = a pre-132 row whose post-rewrite digest is unknown.
	// Every whole-file restore compares the config's CURRENT bytes against
	// it: a mismatch means the operator or the client edited the file after
	// the rewrite, and a whole-file restore would silently clobber that edit
	// - the restore then refuses and falls back to the format-aware reversal
	// of only the relay-owned entry.
	AppliedSHA256 string
	// VServer / RegistryServerID are the approved tools.mcp_access binding
	// (compiled node table vserver ID + registry server id) a stdio-wrap
	// row was projected under (node migration 133, Sol P3+P4 fold finding
	// 2): the stdio wrapper hands them to the local PDP as the call's
	// target. "" = NULL = a remote row (no binding) or a pre-133 row, which
	// the wrapper refuses to launch rather than guess a vserver.
	VServer          string
	RegistryServerID string
}

// Sentinel errors.
var (
	// ErrInvalid is a record or spec that fails Validate (wraps the detail).
	ErrInvalid = errors.New("mcprelay/record: invalid")
	// ErrNotFound is a missing row.
	ErrNotFound = errors.New("mcprelay/record: not found")
	// ErrConflict is a CAS failure (a launch spec's config generation moved).
	ErrConflict = errors.New("mcprelay/record: conflict")
	// ErrTamper is a chain verification fault.
	ErrTamper = errors.New("mcprelay/record: chain tamper")
	// ErrNoNodeKey is an Append on a store opened without a node key: the
	// genesis hash cannot be derived, so nothing may be chained.
	ErrNoNodeKey = errors.New("mcprelay/record: no node key")
)

// Store is the node-local relay store seam the relay (internal/mcprelay)
// writes through and the push composer (internal/store/mcprelaysummary.go)
// reads through. It is the ONE owner of the three mcp_relay_* tables; nothing
// else names them. *SQLStore is the production implementation.
type Store interface {
	// Append validates rec, links it to the chain tail (Genesis when empty)
	// and inserts it at tail+1. Outstanding PendingLoss for rec's family is
	// converted to a gap record FIRST, in the same transaction, and zeroed
	// (R13.5 step 3). A completion must point at a decision row; a
	// gap_resolution must point at a gap row and lie within its range
	// (R14.3) - either violation is ErrInvalid.
	Append(ctx context.Context, rec Record) (AppendResult, error)
	// Head returns the chain tail (Seq 0 + Genesis when empty).
	Head(ctx context.Context) (Head, error)
	// Get returns the record at seq, or ErrNotFound.
	Get(ctx context.Context, seq int64) (Record, error)
	// ReadAfter returns up to limit records with seq > after, seq ascending.
	// limit <= 0 means no limit.
	ReadAfter(ctx context.Context, after int64, limit int) ([]Record, error)
	// Verify walks the whole chain from Genesis, checking contiguous seqs,
	// chain_prev linkage and every chain_hash. A fault is reported in the
	// result, not as an error.
	Verify(ctx context.Context) (VerifyResult, error)

	// PendingLoss returns the family's pending-loss accounting (zero when the
	// family has no state row).
	PendingLoss(ctx context.Context, family string) (PendingLoss, error)
	// SetPendingLoss upserts the family's pending-loss accounting (the
	// sidecar fold). It leaves the policy columns of the state row untouched.
	SetPendingLoss(ctx context.Context, family string, p PendingLoss) error
	// State returns the family's state row (zero-valued + ErrNotFound when
	// absent).
	State(ctx context.Context, family string) (State, error)
	// PutState upserts the POLICY columns of the family's state row
	// (running_version / effective_hash / status / mode / last_applied),
	// leaving the pending-loss columns untouched.
	PutState(ctx context.Context, st State) error

	// PutLaunchSpec journals spec. expectedGeneration is the CAS
	// expectation: 0 requires that no row exists yet; otherwise the stored
	// config_generation must equal it. The stored generation becomes
	// spec.ConfigGeneration.
	PutLaunchSpec(ctx context.Context, spec LaunchSpec, expectedGeneration int64) error
	// GetLaunchSpec returns the journal row, or ErrNotFound.
	GetLaunchSpec(ctx context.Context, client, configPath, entryKey string) (LaunchSpec, error)
	// ListLaunchSpecs returns every journal row, ordered by key.
	ListLaunchSpecs(ctx context.Context) ([]LaunchSpec, error)
	// DeleteLaunchSpec removes the journal row after a verified restore.
	DeleteLaunchSpec(ctx context.Context, client, configPath, entryKey string) error
}

// Validate mirrors every CHECK constraint of mcp_relay_record (doc3 §3.2):
// the closed enums, the L0/L2 payload gates and the exhaustive per-kind
// required/forbidden column sets (R14.2 / R15(a)). The returned error wraps
// ErrInvalid and names the offending column.
func (r Record) Validate() error {
	if r.TS <= 0 {
		return fmt.Errorf("%w: ts must be positive", ErrInvalid)
	}
	spec, ok := kindSpecs[r.Kind]
	if !ok {
		return fmt.Errorf("%w: record_kind %q", ErrInvalid, r.Kind)
	}
	for _, e := range enumChecks {
		if v := e.get(&r); v != "" && !e.allowed[v] {
			return fmt.Errorf("%w: %s %q", ErrInvalid, e.column, v)
		}
	}
	// L0/L2 payload gates (R13.6): L0 carries no payload at all; only L2
	// carries the four full payloads.
	if r.CaptureLevel == CaptureL0 && (r.ArgsExcerpt != "" || r.ArgsFull != "" || r.ResultFull != "" || r.ErrorFull != "" || r.ElicitationFull != "") {
		return fmt.Errorf("%w: capture_level L0 carries a payload", ErrInvalid)
	}
	if r.CaptureLevel != CaptureL2 && (r.ArgsFull != "" || r.ResultFull != "" || r.ErrorFull != "" || r.ElicitationFull != "") {
		return fmt.Errorf("%w: full payload below capture_level L2", ErrInvalid)
	}
	set := map[string]bool{}
	for _, c := range columns {
		set[c.name] = c.isSet(&r)
	}
	for _, name := range spec.required {
		if !set[name] {
			return fmt.Errorf("%w: %s row requires %s", ErrInvalid, r.Kind, name)
		}
	}
	for _, name := range spec.forbidden {
		if set[name] {
			return fmt.Errorf("%w: %s row must not carry %s", ErrInvalid, r.Kind, name)
		}
	}
	if r.Kind == KindGapResolution && *r.ResolvedRangeStart > *r.ResolvedRangeEnd {
		return fmt.Errorf("%w: resolved_range_start > resolved_range_end", ErrInvalid)
	}
	return nil
}

// Validate mirrors the launch-spec NOT NULL constraints.
func (l LaunchSpec) Validate() error {
	for _, f := range []struct{ name, v string }{
		{"client", l.Client},
		{"config_path", l.ConfigPath},
		{"entry_key", l.EntryKey},
		{"orig_command", l.OrigCommand},
		{"backup_path", l.BackupPath},
		{"backup_sha256", l.BackupSHA256},
	} {
		if f.v == "" {
			return fmt.Errorf("%w: launch spec requires %s", ErrInvalid, f.name)
		}
	}
	if l.AppliedAt <= 0 {
		return fmt.Errorf("%w: launch spec requires applied_at", ErrInvalid)
	}
	return nil
}

// column is one nullable column of mcp_relay_record with its set-ness
// predicate; the names are the DDL column names so the per-kind tables below
// read like the CHECKs they mirror.
type column struct {
	name  string
	isSet func(*Record) bool
}

func strCol(name string, get func(*Record) string) column {
	return column{name, func(r *Record) bool { return get(r) != "" }}
}

func intCol(name string, get func(*Record) *int64) column {
	return column{name, func(r *Record) bool { return get(r) != nil }}
}

// columns lists every nullable column in DDL order.
var columns = []column{
	intCol("decision_seq", func(r *Record) *int64 { return r.DecisionSeq }),
	strCol("vserver", func(r *Record) string { return r.VServer }),
	strCol("server_ref_hmac", func(r *Record) string { return r.ServerRefHMAC }),
	strCol("tool_ref_hmac", func(r *Record) string { return r.ToolRefHMAC }),
	strCol("server", func(r *Record) string { return r.Server }),
	strCol("tool", func(r *Record) string { return r.Tool }),
	strCol("call_id", func(r *Record) string { return r.CallID }),
	strCol("trace_id", func(r *Record) string { return r.TraceID }),
	strCol("coding_session_id", func(r *Record) string { return r.CodingSessionID }),
	strCol("turn_ref", func(r *Record) string { return r.TurnRef }),
	strCol("action_ref", func(r *Record) string { return r.ActionRef }),
	strCol("corr_confidence", func(r *Record) string { return string(r.CorrConfidence) }),
	strCol("method", func(r *Record) string { return r.Method }),
	strCol("event_kind", func(r *Record) string { return string(r.EventKind) }),
	strCol("decision", func(r *Record) string { return string(r.Decision) }),
	strCol("reason_code", func(r *Record) string { return r.ReasonCode }),
	strCol("client_attestation", func(r *Record) string { return string(r.ClientAttestation) }),
	strCol("credential_assurance", func(r *Record) string { return r.CredentialAssurance }),
	strCol("capture_level", func(r *Record) string { return string(r.CaptureLevel) }),
	strCol("args_excerpt", func(r *Record) string { return r.ArgsExcerpt }),
	strCol("args_full", func(r *Record) string { return r.ArgsFull }),
	strCol("args_scrub_status", func(r *Record) string { return string(r.ArgsScrubStatus) }),
	strCol("result_full", func(r *Record) string { return r.ResultFull }),
	strCol("result_scrub_status", func(r *Record) string { return string(r.ResultScrubStatus) }),
	strCol("error_full", func(r *Record) string { return r.ErrorFull }),
	strCol("error_scrub_status", func(r *Record) string { return string(r.ErrorScrubStatus) }),
	strCol("elicitation_full", func(r *Record) string { return r.ElicitationFull }),
	strCol("elicitation_scrub_status", func(r *Record) string { return string(r.ElicitationScrubStatus) }),
	intCol("result_size_bytes", func(r *Record) *int64 { return r.ResultSizeBytes }),
	intCol("latency_ms", func(r *Record) *int64 { return r.LatencyMS }),
	strCol("result_status", func(r *Record) string { return r.ResultStatus }),
	intCol("gap_from", func(r *Record) *int64 { return r.GapFrom }),
	intCol("gap_to", func(r *Record) *int64 { return r.GapTo }),
	intCol("lost_count", func(r *Record) *int64 { return r.LostCount }),
	strCol("gap_reason", func(r *Record) string { return r.GapReason }),
	intCol("resolves_seq", func(r *Record) *int64 { return r.ResolvesSeq }),
	intCol("resolved_range_start", func(r *Record) *int64 { return r.ResolvedRangeStart }),
	intCol("resolved_range_end", func(r *Record) *int64 { return r.ResolvedRangeEnd }),
	strCol("resolution", func(r *Record) string { return string(r.Resolution) }),
}

// Column groups, named as the DDL comments name them.
var (
	completionOnly = []string{
		"result_full", "result_scrub_status", "error_full", "error_scrub_status",
		"elicitation_full", "elicitation_scrub_status", "result_size_bytes", "latency_ms", "result_status",
	}
	gapOnly           = []string{"gap_from", "gap_to", "lost_count", "gap_reason"}
	gapResolutionOnly = []string{"resolves_seq", "resolved_range_start", "resolved_range_end", "resolution"}
	decisionOnly      = []string{
		"corr_confidence", "vserver", "server_ref_hmac", "tool_ref_hmac", "server", "tool",
		"method", "event_kind", "decision", "reason_code", "client_attestation", "credential_assurance",
		"coding_session_id", "turn_ref", "action_ref", "args_excerpt", "args_full", "args_scrub_status",
	}
	captureAndCorrelation = []string{
		"capture_level", "corr_confidence", "decision_seq", "vserver", "server_ref_hmac",
		"tool_ref_hmac", "server", "tool", "call_id", "trace_id", "coding_session_id", "turn_ref", "action_ref",
		"method", "event_kind", "decision", "reason_code", "client_attestation", "credential_assurance",
		"args_excerpt", "args_full", "args_scrub_status", "result_full", "result_scrub_status", "error_full",
		"error_scrub_status", "elicitation_full", "elicitation_scrub_status", "result_size_bytes", "latency_ms",
		"result_status",
	}
)

// kindSpec is one row of the per-kind CHECK table (R15(a) / R13.4 / R14.2).
type kindSpec struct {
	required  []string
	forbidden []string
}

func concat(parts ...[]string) []string {
	var out []string
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// kindSpecs mirrors the four per-kind CHECKs of mcp_relay_record exactly.
var kindSpecs = map[Kind]kindSpec{
	KindDecision: {
		required:  []string{"capture_level", "corr_confidence", "call_id", "event_kind", "decision"},
		forbidden: concat([]string{"decision_seq"}, completionOnly, gapOnly, gapResolutionOnly),
	},
	KindCompletion: {
		required:  []string{"capture_level", "call_id", "decision_seq", "result_status"},
		forbidden: concat(decisionOnly, gapOnly, gapResolutionOnly),
	},
	KindGap: {
		required:  gapOnly,
		forbidden: concat(gapResolutionOnly, captureAndCorrelation),
	},
	KindGapResolution: {
		required:  gapResolutionOnly,
		forbidden: concat(gapOnly, captureAndCorrelation),
	},
}

// enumCheck is one closed-vocabulary column.
type enumCheck struct {
	column  string
	get     func(*Record) string
	allowed map[string]bool
}

func allow(vs ...string) map[string]bool {
	m := make(map[string]bool, len(vs))
	for _, v := range vs {
		m[v] = true
	}
	return m
}

var scrubStatuses = allow(string(ScrubStructured), string(ScrubTextFallback), string(ScrubRedacted), string(ScrubTruncated))

// enumChecks mirrors every `CHECK(col IS NULL OR col IN (...))` of the DDL.
var enumChecks = []enumCheck{
	{"corr_confidence", func(r *Record) string { return string(r.CorrConfidence) }, allow(string(CorrExact), string(CorrInferred), string(CorrNone))},
	{"event_kind", func(r *Record) string { return string(r.EventKind) }, allow(string(EventCall), string(EventList), string(EventRead), string(EventPrompt), string(EventSubscribe), string(EventTask), string(EventDeny))},
	{"decision", func(r *Record) string { return string(r.Decision) }, allow(string(DecisionAllow), string(DecisionDeny), string(DecisionAsk))},
	{"client_attestation", func(r *Record) string { return string(r.ClientAttestation) }, allow(string(AttestProcess), string(AttestIPCBound), string(AttestConfigured), string(AttestClaimed))},
	{"capture_level", func(r *Record) string { return string(r.CaptureLevel) }, allow(string(CaptureL0), string(CaptureL1), string(CaptureL2))},
	{"args_scrub_status", func(r *Record) string { return string(r.ArgsScrubStatus) }, scrubStatuses},
	{"result_scrub_status", func(r *Record) string { return string(r.ResultScrubStatus) }, scrubStatuses},
	{"error_scrub_status", func(r *Record) string { return string(r.ErrorScrubStatus) }, scrubStatuses},
	{"elicitation_scrub_status", func(r *Record) string { return string(r.ElicitationScrubStatus) }, scrubStatuses},
	{"resolution", func(r *Record) string { return string(r.Resolution) }, allow(string(ResolutionLateArrival), string(ResolutionConfirmedLoss))},
}
