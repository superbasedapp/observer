package update

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// backoff.go is the DURABLE per-target apply backoff (FR-SEC-12).
//
// An apply that fails deterministically fails the same way on the next tick:
// the same archive, the same signature, the same probe, the same supervisor.
// Re-running it every auto-apply interval is not a retry, it is a loop, and
// for a failed handshake (ErrorHealthcheck) each lap drains the proxy, swaps
// the binary, rolls it back and restarts the daemon. The memory of that
// failure has to outlive the process, because a failed hand-over ends with
// the old daemon exiting: an in-process counter restarts at zero every time.
//
// The record is keyed on the TARGET (its version under NormalizeVersion and
// the artifact's archive sha256): re-signing the same manifest for freshness
// keeps the backoff, while a different release or a corrected artifact for
// the same version is a new question and is not held. An operator's own
// `observer update apply` clears it (cmd/observer).

// BackoffAction is what one apply outcome does to the backoff.
type BackoffAction int

const (
	// BackoffKeep leaves the record as it is: a transient failure (a fetch,
	// a busy drain, a closed window) or a defer says nothing about the target.
	BackoffKeep BackoffAction = iota
	// BackoffAdvance counts one more deterministic failure of the target.
	BackoffAdvance
	// BackoffClear forgets the record: the target applied.
	BackoffClear
)

// deterministicFailures are the error classes that give the same answer on
// the next tick for the same target on the same node. ErrorHealthcheck is
// the FR-SEC-12 row: a failed self-check (the hand-over interlock included)
// or a handshake timeout repeats with the same binary. Download, drain and
// window are absent on purpose: a fetch that failed or a busy node is a
// transient condition the plain cadence answers.
var deterministicFailures = map[ErrorClass]bool{
	ErrorHash:        true,
	ErrorSignature:   true,
	ErrorProbe:       true,
	ErrorSwap:        true,
	ErrorPermission:  true,
	ErrorHealthcheck: true,
}

// BackoffStep is the table from one apply outcome to its BackoffAction.
func BackoffStep(applied bool, class ErrorClass) BackoffAction {
	switch {
	case applied:
		return BackoffClear
	case deterministicFailures[class]:
		return BackoffAdvance
	default:
		return BackoffKeep
	}
}

// BackoffKey names the target a backoff is about.
type BackoffKey struct {
	// Target is the manifest's version; compared under NormalizeVersion.
	Target string
	// ArtifactSHA256 is the selected artifact's archive hash.
	ArtifactSHA256 string
}

// ApplyBackoff is the durable record. The zero value holds nothing.
type ApplyBackoff struct {
	Target          string     `json:"target"`
	ArtifactSHA256  string     `json:"artifact_sha256,omitempty"`
	ManifestVersion int64      `json:"manifest_version,omitempty"`
	Failures        int        `json:"failures"`
	ErrorClass      ErrorClass `json:"error_class"`
	// Refusal is the hand-over interlock's token when the failure was one
	// (service.HandoverRefusal), so a caller can see the cause has gone
	// (the operator ran `observer service upgrade` and restarted) and stop
	// holding the target early.
	Refusal     string    `json:"refusal,omitempty"`
	NextAttempt time.Time `json:"next_attempt"`
}

// Matches reports whether the record is about key's target.
func (b ApplyBackoff) Matches(key BackoffKey) bool {
	return b.Failures > 0 && SameVersion(b.Target, key.Target) &&
		strings.EqualFold(strings.TrimSpace(b.ArtifactSHA256), strings.TrimSpace(key.ArtifactSHA256))
}

// Holds reports whether an automatic apply of key's target must wait at now.
func (b ApplyBackoff) Holds(key BackoffKey, now time.Time) bool {
	return b.Matches(key) && now.Before(b.NextAttempt)
}

// NextApplyBackoff counts one more deterministic failure of key's target at
// now. The wait is base << failures, capped at ceiling (an operator who fixed
// the cause must not wait a day for the node to notice); a record about
// another target starts the count again.
func NextApplyBackoff(prev ApplyBackoff, key BackoffKey, manifestVersion int64, class ErrorClass, refusal string, now time.Time, base, ceiling time.Duration) ApplyBackoff {
	failures := 1
	if prev.Matches(key) {
		failures = prev.Failures + 1
	}
	wait := ceiling
	if failures < 62 {
		if w := base << failures; w > 0 && w < ceiling {
			wait = w
		}
	}
	return ApplyBackoff{
		Target: strings.TrimSpace(key.Target), ArtifactSHA256: strings.TrimSpace(key.ArtifactSHA256),
		ManifestVersion: manifestVersion, Failures: failures, ErrorClass: class,
		Refusal: strings.TrimSpace(refusal), NextAttempt: now.Add(wait).UTC(),
	}
}

// EncodeApplyBackoff renders the record for storage; the zero value encodes
// as "" (no record).
func EncodeApplyBackoff(b ApplyBackoff) (string, error) {
	if b.Failures <= 0 {
		return "", nil
	}
	js, err := json.Marshal(b)
	if err != nil {
		return "", fmt.Errorf("update.EncodeApplyBackoff: %w", err)
	}
	return string(js), nil
}

// DecodeApplyBackoff reads a stored record; "" is the zero value.
func DecodeApplyBackoff(js string) (ApplyBackoff, error) {
	if strings.TrimSpace(js) == "" {
		return ApplyBackoff{}, nil
	}
	var b ApplyBackoff
	if err := json.Unmarshal([]byte(js), &b); err != nil {
		return ApplyBackoff{}, fmt.Errorf("update.DecodeApplyBackoff: %w", err)
	}
	b.NextAttempt = b.NextAttempt.UTC()
	return b, nil
}
