package planechoice

import (
	"strings"
)

// ReceiverState is the local OTLP receiver's recorded bind state (the
// daemon's otlp-receiver.json record).
type ReceiverState string

// The receiver states.
const (
	ReceiverListening  ReceiverState = "listening"
	ReceiverBindFailed ReceiverState = "bind_failed"
	// ReceiverNotRunning: no receiver is open (AI Apps and vendor ingest
	// both off).
	ReceiverNotRunning ReceiverState = "not_running"
	// ReceiverNoAnswer: the enable waited for the bind and got no answer.
	ReceiverNoAnswer ReceiverState = "no_answer"
	// ReceiverUnknown: this process has no receiver facts (no daemon seam).
	ReceiverUnknown ReceiverState = "unknown"
)

// Receiver is the receiver's status as the surfaces show it.
type Receiver struct {
	State    ReceiverState `json:"state"`
	GRPCAddr string        `json:"grpc_addr,omitempty"`
	HTTPAddr string        `json:"http_addr,omitempty"`
	Error    string        `json:"error,omitempty"`
	At       string        `json:"at,omitempty"`
}

// EnableFacts is everything one enable attempt learned, in order: the
// build, the component, the config writes, the receiver.
type EnableFacts struct {
	// InBuild: app observability is compiled into this binary.
	InBuild bool
	// Component is the obs component's state before the attempt.
	Component ComponentState
	// Editions are the editions that include AI Apps (for the refusal).
	Editions []string
	// Refused is why the config change was refused (an organization pin,
	// an unreadable policy); "" when it was not.
	Refused string
	// WriteError is a config write or verification failure.
	WriteError string
	// Receiver is the receiver's state after the attempt.
	Receiver Receiver
	// Pending names features configured on that start only at the next
	// start (admission, alerts, organization share tiers).
	Pending []string
}

// EnableOutcome is the outcome code.
type EnableOutcome string

// The outcomes.
const (
	OutcomeOn           EnableOutcome = "on"
	OutcomeNotInBuild   EnableOutcome = "not_in_build"
	OutcomeBlocked      EnableOutcome = "blocked"
	OutcomeRefused      EnableOutcome = "refused"
	OutcomeConfigFailed EnableOutcome = "config_failed"
	OutcomeBindFailed   EnableOutcome = "bind_failed"
	OutcomeNoAnswer     EnableOutcome = "receiver_no_answer"
)

// EnableReport is what the enable seam answers: the dashboard button, the
// CLI and the VS Code action all print it.
type EnableReport struct {
	Outcome EnableOutcome `json:"outcome"`
	// OK: AI Apps is on and the receiver listens. Never true while the
	// receiver waits or failed (plan 3.5: it never says "AI Apps is on"
	// and then waits).
	OK bool `json:"ok"`
	// Rule names the enableRules row.
	Rule    string `json:"rule"`
	Message string `json:"message"`
	// Fix is the one next step, "" when there is none.
	Fix      string   `json:"fix,omitempty"`
	Receiver Receiver `json:"receiver"`
	// Pending is copied from the facts.
	Pending []string `json:"pending_next_start,omitempty"`
}

// enableRules classifies one attempt, walked top-down.
var enableRules = []struct {
	name    string
	when    func(EnableFacts) bool
	outcome EnableOutcome
	message func(EnableFacts) (msg, fix string)
}{
	{
		name:    "not in this build",
		when:    func(f EnableFacts) bool { return !f.InBuild || f.Component == ComponentAbsent },
		outcome: OutcomeNotInBuild,
		message: func(f EnableFacts) (string, string) {
			eds := "developer and full"
			if len(f.Editions) > 0 {
				eds = strings.Join(f.Editions, " and ")
			}
			return "This edition does not include AI Apps. The " + eds + " editions have it.",
				"Reinstall with `install.sh --edition developer` (Windows: the install.ps1 -Edition developer option)."
		},
	},
	{
		name:    "blocked on this machine",
		when:    func(f EnableFacts) bool { return f.Component == ComponentBlocked },
		outcome: OutcomeBlocked,
		message: func(EnableFacts) (string, string) {
			return "AI Apps is blocked on this machine by a rule or your organization.",
				"See Settings > Components for who blocked it."
		},
	},
	{
		name:    "the config change was refused",
		when:    func(f EnableFacts) bool { return f.Refused != "" },
		outcome: OutcomeRefused,
		message: func(f EnableFacts) (string, string) {
			return "AI Apps was not turned on: " + f.Refused, ""
		},
	},
	{
		name:    "the config change failed",
		when:    func(f EnableFacts) bool { return f.WriteError != "" },
		outcome: OutcomeConfigFailed,
		message: func(f EnableFacts) (string, string) {
			return "AI Apps was not turned on: the config change failed: " + f.WriteError, ""
		},
	},
	{
		name:    "the receiver could not bind",
		when:    func(f EnableFacts) bool { return f.Receiver.State == ReceiverBindFailed },
		outcome: OutcomeBindFailed,
		message: func(f EnableFacts) (string, string) {
			addr := f.Receiver.HTTPAddr
			if addr == "" {
				addr = f.Receiver.GRPCAddr
			}
			return "AI Apps is set to on, but the receiver could not listen on " + addr + ": " + f.Receiver.Error,
				"Another program holds the port (a collector or Jaeger is common). Stop it, or move the receiver with [ingest.otel] http_addr / grpc_addr, then turn AI Apps on again."
		},
	},
	{
		name:    "the receiver did not answer",
		when:    func(f EnableFacts) bool { return f.Receiver.State != ReceiverListening },
		outcome: OutcomeNoAnswer,
		message: func(EnableFacts) (string, string) {
			return "AI Apps is set to on, but the receiver did not report that it is listening.",
				"Run `observer doctor` (the otlp.receiver row), or restart `observer start`."
		},
	},
	{
		name:    "on and listening",
		when:    func(EnableFacts) bool { return true },
		outcome: OutcomeOn,
		message: func(f EnableFacts) (string, string) {
			return "AI Apps is on. Receiver: listening on " + f.Receiver.HTTPAddr + ".", ""
		},
	},
}

// ClassifyEnable walks enableRules.
func ClassifyEnable(f EnableFacts) EnableReport {
	for _, r := range enableRules {
		if !r.when(f) {
			continue
		}
		msg, fix := r.message(f)
		return EnableReport{
			Outcome: r.outcome, OK: r.outcome == OutcomeOn, Rule: r.name,
			Message: msg, Fix: fix, Receiver: f.Receiver, Pending: f.Pending,
		}
	}
	return EnableReport{Outcome: OutcomeNoAnswer, Receiver: f.Receiver}
}
