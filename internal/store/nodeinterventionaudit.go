package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// NodeProcessControlEventKind is the distinct guard-event kind used for
// node-local process-control outcomes. It deliberately does not model an API
// request, proxy turn, or watcher action.
const NodeProcessControlEventKind = "node_process_control"

const (
	nodeProcessControlSource   = "node_intervention"
	nodeProcessControlCategory = "process_control"
	nodeProcessControlSeverity = "high"
)

// NodeProcessControlAudit is the store-shaped input for one native process
// control observation. It contains only stable process identity and bounded
// policy/result metadata: callers must not put argv, environment, executable
// paths, credentials, or raw errors in this value.
//
// The process identity fields are persisted in the bounded structured reason
// metadata and also contribute to TargetHash. SessionID is copied only when a
// caller already has a real session correlation; this helper never invents one.
type NodeProcessControlAudit struct {
	// TS defaults to the current UTC time when zero.
	TS time.Time
	// Surface identifies the installed intervention surface.
	Surface string
	// Tool is the adapter/vendor tool name.
	Tool string
	// SessionID is an existing source session id, or empty when none is known.
	SessionID string

	// Stable process identity observed by the controller.
	PID              int
	UID              int
	BootID           string
	StartTicks       int64
	ExecutableDevice uint64
	ExecutableInode  uint64

	// RuleID and Reason identify the policy result. Reason is treated as a
	// bounded policy explanation, never as a place for an OS error string.
	RuleID string
	Reason string
	// Status is a stable outcome such as terminated, killed, already_exited,
	// fence_rejected, or termination_unverified.
	Status string

	// TermAttempted and KillAttempted mean the corresponding OS-operation
	// callback was invoked. They do not claim that a signal was delivered.
	TermAttempted bool
	KillAttempted bool
	// Observed means the process-control primitive observed process exit.
	// It is separate from Stopped because an already-exited process is
	// observed without being stopped by this operation.
	Observed        bool
	Stopped         bool
	AlreadyExited   bool
	ControlVerified bool
	ErrorPresent    bool

	// These are metadata fingerprints, never raw authority or policy bodies.
	// Non-hash input is defensively hashed before persistence.
	AuthorityFingerprint string
	BudgetFingerprint    string
	PolicyRevision       uint64
	MetadataHash         string

	// PricingDocument* records the pricing evidence used by a measured USD
	// decision. The fingerprint is canonicalized and hashed before it enters
	// reason metadata; the durable audit never stores a pricing document or
	// other raw policy body.
	PricingDocumentRequired    bool
	PricingDocumentKnown       bool
	PricingDocumentPresent     bool
	PricingDocumentFingerprint string
}

type nodeProcessControlReasonMetadata struct {
	Version                    int    `json:"version"`
	Surface                    string `json:"surface"`
	Tool                       string `json:"tool"`
	SessionID                  string `json:"session_id"`
	PID                        int    `json:"pid"`
	UID                        int    `json:"uid"`
	BootID                     string `json:"boot_id"`
	StartTicks                 int64  `json:"start_ticks"`
	ExecutableDevice           uint64 `json:"executable_device"`
	ExecutableInode            uint64 `json:"executable_inode"`
	RuleID                     string `json:"rule_id"`
	Reason                     string `json:"reason"`
	AuthorityFingerprint       string `json:"authority_fingerprint,omitempty"`
	BudgetFingerprint          string `json:"budget_fingerprint,omitempty"`
	PolicyRevision             uint64 `json:"policy_revision,omitempty"`
	MetadataHash               string `json:"metadata_hash,omitempty"`
	PricingDocumentRequired    bool   `json:"pricing_document_required"`
	PricingDocumentKnown       bool   `json:"pricing_document_known"`
	PricingDocumentPresent     bool   `json:"pricing_document_present"`
	PricingDocumentFingerprint string `json:"pricing_document_fingerprint,omitempty"`
}

type nodeProcessControlOutcomeMetadata struct {
	Version         int    `json:"version"`
	Status          string `json:"status"`
	TermAttempted   bool   `json:"term_attempted"`
	KillAttempted   bool   `json:"kill_attempted"`
	Stopped         bool   `json:"stopped"`
	AlreadyExited   bool   `json:"already_exited"`
	Observed        bool   `json:"observed"`
	ControlVerified bool   `json:"control_verified"`
	ErrorPresent    bool   `json:"error_present"`
}

// InsertNodeProcessControlAudit records one process-control observation in
// the existing hash-chained guard_events owner. Enforced is derived solely
// from Stopped, so an attempted, verified, or merely reported signal cannot
// be presented as enforcement without observed process exit.
func (s *Store) InsertNodeProcessControlAudit(ctx context.Context, audit NodeProcessControlAudit) error {
	if s == nil || s.db == nil {
		return errors.New("store.InsertNodeProcessControlAudit: store unavailable")
	}
	if ctx == nil {
		return errors.New("store.InsertNodeProcessControlAudit: nil context")
	}

	reason, err := marshalNodeProcessControlReason(audit)
	if err != nil {
		return fmt.Errorf("store.InsertNodeProcessControlAudit: reason metadata: %w", err)
	}
	outcome, err := marshalNodeProcessControlOutcome(audit)
	if err != nil {
		return fmt.Errorf("store.InsertNodeProcessControlAudit: outcome metadata: %w", err)
	}
	ts := audit.TS
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	status := nodeProcessControlStatus(audit.Status)
	ruleID := boundedNodeControlText(audit.RuleID, 128)
	if ruleID == "" {
		ruleID = NodeProcessControlEventKind
	}
	row := GuardEventRow{
		TS:            ts.UTC(),
		SessionID:     boundedNodeControlText(audit.SessionID, 256),
		Tool:          boundedNodeControlText(audit.Tool, 128),
		EventKind:     NodeProcessControlEventKind,
		RuleID:        ruleID,
		Category:      nodeProcessControlCategory,
		Severity:      nodeProcessControlSeverity,
		Decision:      status,
		Enforced:      audit.Stopped,
		Source:        nodeProcessControlSource,
		Reason:        reason,
		TargetHash:    nodeProcessControlTargetHash(audit),
		TargetExcerpt: outcome,
	}
	if _, err := s.InsertGuardEvents(ctx, []GuardEventRow{row}); err != nil {
		return fmt.Errorf("store.InsertNodeProcessControlAudit: %w", err)
	}
	return nil
}

func marshalNodeProcessControlReason(audit NodeProcessControlAudit) (string, error) {
	metadata := nodeProcessControlReasonMetadata{
		Version:                    1,
		Surface:                    boundedNodeControlText(audit.Surface, 96),
		Tool:                       boundedNodeControlText(audit.Tool, 128),
		SessionID:                  boundedNodeControlText(audit.SessionID, 256),
		PID:                        audit.PID,
		UID:                        audit.UID,
		BootID:                     boundedNodeControlText(audit.BootID, 96),
		StartTicks:                 audit.StartTicks,
		ExecutableDevice:           audit.ExecutableDevice,
		ExecutableInode:            audit.ExecutableInode,
		RuleID:                     boundedNodeControlText(audit.RuleID, 128),
		Reason:                     boundedNodeControlText(audit.Reason, 256),
		AuthorityFingerprint:       canonicalNodeControlHash(audit.AuthorityFingerprint),
		BudgetFingerprint:          canonicalNodeControlHash(audit.BudgetFingerprint),
		PolicyRevision:             audit.PolicyRevision,
		MetadataHash:               canonicalNodeControlHash(audit.MetadataHash),
		PricingDocumentRequired:    audit.PricingDocumentRequired,
		PricingDocumentKnown:       audit.PricingDocumentKnown,
		PricingDocumentPresent:     audit.PricingDocumentPresent,
		PricingDocumentFingerprint: canonicalNodeControlHash(audit.PricingDocumentFingerprint),
	}
	for {
		encoded, err := json.Marshal(metadata)
		if err != nil {
			return "", err
		}
		// InsertGuardEvents bounds the reason before hashing. Keep this
		// structured payload under that byte limit here so the downstream
		// seam never cuts a valid JSON document into invalid metadata.
		if len(encoded) <= guardMaxReasonRunes {
			return string(encoded), nil
		}
		switch {
		case metadata.Reason != "":
			metadata.Reason = trimNodeControlString(metadata.Reason)
		case metadata.SessionID != "":
			metadata.SessionID = trimNodeControlString(metadata.SessionID)
		case metadata.Surface != "":
			metadata.Surface = trimNodeControlString(metadata.Surface)
		case metadata.Tool != "":
			metadata.Tool = trimNodeControlString(metadata.Tool)
		case metadata.RuleID != "":
			metadata.RuleID = trimNodeControlString(metadata.RuleID)
		case metadata.BootID != "":
			metadata.BootID = trimNodeControlString(metadata.BootID)
		default:
			return "", errors.New("node process control reason metadata exceeds bound")
		}
	}
}

func marshalNodeProcessControlOutcome(audit NodeProcessControlAudit) (string, error) {
	metadata := nodeProcessControlOutcomeMetadata{
		Version:         1,
		Status:          nodeProcessControlStatus(audit.Status),
		TermAttempted:   audit.TermAttempted,
		KillAttempted:   audit.KillAttempted,
		Stopped:         audit.Stopped,
		AlreadyExited:   audit.AlreadyExited,
		Observed:        audit.Observed || audit.Stopped || audit.AlreadyExited,
		ControlVerified: audit.ControlVerified,
		ErrorPresent:    audit.ErrorPresent,
	}
	for {
		encoded, err := json.Marshal(metadata)
		if err != nil {
			return "", err
		}
		if len(encoded) <= guardMaxExcerptRunes {
			return string(encoded), nil
		}
		if metadata.Status == "" {
			return "", errors.New("node process control outcome metadata exceeds bound")
		}
		metadata.Status = trimNodeControlString(metadata.Status)
	}
}

func nodeProcessControlTargetHash(audit NodeProcessControlAudit) string {
	canonical := strings.Join([]string{
		"node-process-control/v1",
		boundedNodeControlText(audit.BootID, 96),
		strconv.Itoa(audit.PID),
		strconv.Itoa(audit.UID),
		strconv.FormatInt(audit.StartTicks, 10),
		strconv.FormatUint(audit.ExecutableDevice, 10),
		strconv.FormatUint(audit.ExecutableInode, 10),
	}, "\x1f")
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

func canonicalNodeControlHash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "sha256:") {
		value = strings.TrimPrefix(value, "sha256:")
	}
	if decoded, err := hex.DecodeString(value); err == nil && len(decoded) == sha256.Size {
		return strings.ToLower(value)
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// nodeProcessControlStatus accepts only a compact stable classification. A
// caller can still record that an operation failed through ErrorPresent, but
// an OS error sentence, path, or credential cannot become an audit status.
func nodeProcessControlStatus(value string) string {
	value = strings.ToLower(boundedNodeControlText(value, 64))
	if value == "" {
		return "unknown"
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' && r != '-' {
			return "unknown"
		}
	}
	return value
}

func trimNodeControlString(value string) string {
	runes := []rune(value)
	if len(runes) == 0 {
		return ""
	}
	return string(runes[:len(runes)-1])
}

func boundedNodeControlText(value string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	value = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value))
	runes := []rune(value)
	if len(runes) > maxRunes {
		return string(runes[:maxRunes])
	}
	return value
}
