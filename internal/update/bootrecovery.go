package update

import (
	"encoding/json"
	"fmt"
	"strings"
)

// bootrecovery.go decides how a daemon that starts while its state says
// `applying` settles it, with no parent watching (cmd/observer RecoverAtBoot).
//
// Two shapes reach it. A kill or a host reboot after the old parent exited:
// the running binary IS the target or it is not, and that settles it at once.
// And the launchd hand-over (SVC-3 option b): the parent stopped the
// self-checked child and exited non-zero, and launchd started the new binary
// itself. Then the parent left a SupervisorRestart record, and the new binary
// settles `applied` only after it has stayed up; each boot counts an
// attempt, and a binary that keeps failing to come up is replaced by the
// previous one after MaxSupervisorRestartBoots boots.

// MaxSupervisorRestartBoots is how many boots of the new binary, started by
// the supervisor after a hand-over, may fail to stay up before the previous
// binary is restored.
const MaxSupervisorRestartBoots = 3

// BootRecovery is the closed vocabulary of RecoverAtBoot's actions.
type BootRecovery string

const (
	// BootNothing: the state is not `applying`.
	BootNothing BootRecovery = "nothing"
	// BootSettleFailed: the running binary is not the target; the swap did
	// not happen or was already undone.
	BootSettleFailed BootRecovery = "settle_failed"
	// BootSettleApplied: the running binary is the target and the apply only
	// lost its witness.
	BootSettleApplied BootRecovery = "settle_applied"
	// BootSettleAppliedWhenHealthy: the supervisor started the target after
	// a hand-over; settle applied once this boot has stayed up.
	BootSettleAppliedWhenHealthy BootRecovery = "settle_applied_when_healthy"
	// BootRestorePrevious: the target failed to stay up too many times;
	// restore the previous binary and exit for the supervisor to start it.
	BootRestorePrevious BootRecovery = "restore_previous"
)

// BootRecoveryInput is the resolved facts.
type BootRecoveryInput struct {
	// Applying reports state `applying`.
	Applying bool
	// RunningIsTarget reports that this binary is the apply's target.
	RunningIsTarget bool
	// AwaitingRestart reports a SupervisorRestart record for the target.
	AwaitingRestart bool
	// Attempts counts the boots under that record, this one included.
	Attempts int
}

// bootRecoveryRow is one rule.
type bootRecoveryRow struct {
	action  BootRecovery
	applies func(BootRecoveryInput) bool
}

// bootRecoveryRows is walked top-down; the last row always matches.
var bootRecoveryRows = []bootRecoveryRow{
	{BootNothing, func(in BootRecoveryInput) bool { return !in.Applying }},
	{BootSettleFailed, func(in BootRecoveryInput) bool { return !in.RunningIsTarget }},
	{BootSettleApplied, func(in BootRecoveryInput) bool { return !in.AwaitingRestart }},
	{BootRestorePrevious, func(in BootRecoveryInput) bool { return in.Attempts > MaxSupervisorRestartBoots }},
	{BootSettleAppliedWhenHealthy, func(BootRecoveryInput) bool { return true }},
}

// DecideBootRecovery walks the table.
func DecideBootRecovery(in BootRecoveryInput) BootRecovery {
	for _, r := range bootRecoveryRows {
		if r.applies(in) {
			return r.action
		}
	}
	return BootNothing
}

// SupervisorRestart is the record a launchd hand-over leaves for the new
// binary's boots. The zero value is no record.
type SupervisorRestart struct {
	Target   string `json:"target"`
	Attempts int    `json:"attempts"`
}

// Matches reports whether the record is about target.
func (r SupervisorRestart) Matches(target string) bool {
	return strings.TrimSpace(r.Target) != "" && SameVersion(r.Target, target)
}

// EncodeSupervisorRestart renders the record; the zero value is "".
func EncodeSupervisorRestart(r SupervisorRestart) (string, error) {
	if strings.TrimSpace(r.Target) == "" {
		return "", nil
	}
	js, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("update.EncodeSupervisorRestart: %w", err)
	}
	return string(js), nil
}

// DecodeSupervisorRestart reads a stored record; "" is the zero value.
func DecodeSupervisorRestart(js string) (SupervisorRestart, error) {
	if strings.TrimSpace(js) == "" {
		return SupervisorRestart{}, nil
	}
	var r SupervisorRestart
	if err := json.Unmarshal([]byte(js), &r); err != nil {
		return SupervisorRestart{}, fmt.Errorf("update.DecodeSupervisorRestart: %w", err)
	}
	return r, nil
}
