package cloudsession

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// otelloop.go plans the in-sandbox LOOPBACK OTLP receiver (cloud-agents lane
// CA-C7, part 2). Rail S already runs Observer inside the vendor's VM; with
// this option the committed hooks also start a short-lived OTLP/HTTP receiver
// on a loopback address there, and the agent's own OpenTelemetry export
// (configured on the cloud ENVIRONMENT, not in the repository) points at it.
// The receiver writes into the sandbox's own Observer database, the same one
// the flush hooks ship, so its rows travel inside the existing push envelope:
// no second wire, no credential (a loopback receiver needs none), and no
// network allowlist entry (the VM's NO_PROXY covers 127.0.0.1).
//
// It is OPT-IN (`observer cloud-session init --otel-loopback`), Claude Code
// only, and adds nothing the agent's transcript does not already carry for
// its main conversation: what it adds is the per-request record (the
// Anthropic request id, the vendor's own cost figure, the duration) and the
// requests the transcript never logs (side calls such as title generation).
// The transcript stays the token owner (decision CA-D12); the export's turns
// fold against it in internal/sessionmsg exactly as on a laptop.

// DefaultOTelLoopbackAddr is the receiver's default bind: the OTLP/HTTP
// default port on IPv4 loopback, the address an exporter with no endpoint
// configured would already try.
const DefaultOTelLoopbackAddr = "127.0.0.1:4318"

// OTelLoopbackHookTimeoutSeconds bounds the ensure hook: it probes the port
// and, when nothing answers, starts the receiver and waits briefly for it.
const OTelLoopbackHookTimeoutSeconds = 15

// OTelLoopbackSpec is one row of the loopback table: what an agent's
// export needs to reach an in-sandbox receiver.
type OTelLoopbackSpec struct {
	// Agent is the agent id.
	Agent string
	// Events are the vendor hook events that ensure the receiver runs:
	// session start, and the prompt event as a cheap re-check after a
	// resumed sandbox (processes do not survive a resume; files do).
	Events []string
	// Env are the environment variables to add to the cloud environment,
	// in order, with the endpoint filled in by Env(addr). None is a secret.
	env func(endpoint string) [][2]string
	// Grounding records what was verified live and what was not.
	Grounding string
}

// Env returns the cloud-environment variables for a receiver on addr.
func (s OTelLoopbackSpec) Env(addr string) [][2]string {
	return s.env("http://" + addr)
}

// otelLoopbackSpecs is THE loopback table. An agent absent from it has no
// loopback route (init refuses the flag for it).
var otelLoopbackSpecs = []OTelLoopbackSpec{
	{
		Agent:  "claude-code",
		Events: []string{"SessionStart", "UserPromptSubmit"},
		env: func(endpoint string) [][2]string {
			return [][2]string{
				{"CLAUDE_CODE_ENABLE_TELEMETRY", "1"},
				{"OTEL_LOGS_EXPORTER", "otlp"},
				{"OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf"},
				{"OTEL_EXPORTER_OTLP_ENDPOINT", endpoint},
			}
		},
		Grounding: "Live-checked 2026-11-01 (lane CA-C7, Claude Code 2.1.316, inside a Claude Code cloud VM): a receiver started detached from a SessionStart hook outlived the hook and the session process, and a `claude -p` run exporting http/protobuf to 127.0.0.1 landed its api_request turns and the vendor_cloud stamp in the sandbox database. Not observed: the MAIN session process exporting with these variables set on a cloud environment (the variables are read at process start, so only a new session can show it).",
	},
}

// OTelLoopbackFor returns agentID's loopback row.
func OTelLoopbackFor(agentID string) (OTelLoopbackSpec, error) {
	for _, s := range otelLoopbackSpecs {
		if s.Agent == agentID {
			return s, nil
		}
	}
	return OTelLoopbackSpec{}, fmt.Errorf("cloudsession: agent %q has no loopback OpenTelemetry route (supported: %s)", agentID, strings.Join(otelLoopbackAgents(), ", "))
}

func otelLoopbackAgents() []string {
	out := make([]string, 0, len(otelLoopbackSpecs))
	for _, s := range otelLoopbackSpecs {
		out = append(out, s.Agent)
	}
	return out
}

// ErrOTelLoopbackAddr is returned for an address that is not a loopback IP
// literal with a port.
var ErrOTelLoopbackAddr = errors.New("cloudsession: the loopback receiver address must be a loopback IP literal and a port (127.0.0.1:4318, [::1]:4318)")

// ValidOTelLoopbackAddr checks addr: a loopback IP LITERAL (never a name,
// which a resolver could point elsewhere) and a port in 1..65535. It returns
// the canonical host:port.
func ValidOTelLoopbackAddr(addr string) (string, error) {
	ap, err := netip.ParseAddrPort(strings.TrimSpace(addr))
	if err != nil || !ap.Addr().IsLoopback() || ap.Port() == 0 || ap.Addr().Zone() != "" {
		return "", ErrOTelLoopbackAddr
	}
	return ap.String(), nil
}

// otelLoopbackCommand renders the committed ensure hook: like every other
// committed hook it runs only inside the agent's cloud sandbox and only when
// the setup step installed observer, and otherwise succeeds silently.
func otelLoopbackCommand(a Agent, opts PlanOptions, addr string) string {
	bin := shellQuote(opts.installDir() + "/observer")
	argv := []string{"cloud-session", "otel-receiver", "ensure", "--agent", a.ID, "--addr", addr}
	quoted := make([]string, len(argv))
	for i, s := range argv {
		quoted[i] = shellQuote(s)
	}
	return fmt.Sprintf("%s && [ -x %s ] && exec %s %s; exit 0 %s",
		markerGate(a), bin, bin, strings.Join(quoted, " "), OwnerTag)
}

// AddOTelLoopback extends an init plan for plan.Agent with the loopback
// receiver: one owned ensure entry per row event appended to the agent's
// settings file, and the cloud-environment variables as a manual step. The
// entries end with OwnerTag, so `remove` takes them out with the rest, and a
// later init without the option drops them (init strips every owned entry
// before adding its own). addr "" takes DefaultOTelLoopbackAddr.
func AddOTelLoopback(plan RepoPlan, opts PlanOptions, addr string) (RepoPlan, error) {
	spec, err := OTelLoopbackFor(plan.Agent.ID)
	if err != nil {
		return plan, err
	}
	if addr == "" {
		addr = DefaultOTelLoopbackAddr
	}
	addr, err = ValidOTelLoopbackAddr(addr)
	if err != nil {
		return plan, err
	}
	idx := -1
	for i, c := range plan.Changes {
		if c.Path == ClaudeSettingsPath && !c.Delete {
			idx = i
			break
		}
	}
	if idx < 0 {
		return plan, fmt.Errorf("cloudsession: the %s plan writes no %s to add the receiver hook to", plan.Agent.ID, ClaudeSettingsPath)
	}
	doc, err := loadJSONDoc(plan.Changes[idx].After)
	if err != nil || doc.root.kind != jObject {
		return plan, fmt.Errorf("cloudsession: the planned %s is not a JSON object", ClaudeSettingsPath)
	}
	hooks, err := childObject(doc.root, "hooks")
	if err != nil {
		return plan, err
	}
	cmd := otelLoopbackCommand(plan.Agent, opts, addr)
	for _, event := range spec.Events {
		arr, err := childArray(hooks, event)
		if err != nil {
			return plan, err
		}
		inner := &jnode{kind: jArray, items: []*jnode{commandEntry("command", cmd, "timeout", OTelLoopbackHookTimeoutSeconds)}}
		arr.items = append(arr.items, jObj("hooks", inner))
	}
	out := plan
	out.Changes = append([]FileChange(nil), plan.Changes...)
	out.Changes[idx].After = doc.render()
	lines := make([]string, 0, 4)
	for _, kv := range spec.Env(addr) {
		lines = append(lines, kv[0]+"="+kv[1])
	}
	out.Manual = append(append([]string(nil), plan.Manual...),
		"In the Claude Code cloud environment's settings, add these environment variables (none is a secret; they point the session's own telemetry at the receiver the hooks start inside the VM): "+strings.Join(lines, " "),
		"No network allowlist entry is needed for the receiver: it is on "+addr+" inside the VM, which the sandbox's NO_PROXY already covers. Do not also point OTEL_EXPORTER_OTLP_ENDPOINT at a remote receiver: one endpoint per environment.",
	)
	return out, nil
}
