package settingsgate

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/configschema"
)

// Verdict is what an agent's write of one key may do.
type Verdict string

const (
	// Apply: an ordinary key; the agent's write is applied directly.
	Apply Verdict = "apply"
	// Propose: a security-sensitive key; the write becomes a proposal the
	// user approves (never applied by the agent).
	Propose Verdict = "propose"
	// Refuse: a credential, a key another surface owns, a whole table, or an
	// unknown key; nothing is written or proposed.
	Refuse Verdict = "refuse"
)

// Category names why a key needs the user's approval, in the D19 words.
type Category string

// The D19 categories.
const (
	CategoryNone        Category = ""
	CategoryGuard       Category = "guard"
	CategoryCapture     Category = "capture_content"
	CategorySharing     Category = "sharing"
	CategoryEgress      Category = "egress"
	CategoryAdmission   Category = "admission_mode"
	CategoryBudget      Category = "budget"
	CategoryDestination Category = "destination_online"
	CategorySensitive   Category = "sensitive"
)

// Decision is the gate's answer for one key and value.
type Decision struct {
	Verdict  Verdict
	Category Category
	// Reason is one plain sentence for the agent and the user.
	Reason string
	// Leaf is the resolved schema leaf (zero when the key is unknown).
	Leaf configschema.Leaf
}

// approvalPrefix is one D19 security-sensitive key family.
type approvalPrefix struct {
	prefix   string
	category Category
	reason   string
}

// approvalPrefixes are the key families an agent may never change directly.
// The first four are the guard's own self-lowering sections (R-165: an agent
// may not lower the guard, the security module, launch limits or the gate
// hooks). Order matters only for which reason is shown.
var approvalPrefixes = []approvalPrefix{
	{"guard.budget", CategoryBudget, "it changes your own spending limits"},
	{"guard", CategoryGuard, "it changes what the guard allows an agent to do"},
	{"security", CategoryGuard, "it changes the code security checks"},
	{"terminal.launch", CategoryGuard, "it changes what an agent-started launch may start"},
	{"observer.hooks", CategoryGuard, "it changes the gate hooks that let the guard judge agent actions"},
	{"org_client.share", CategorySharing, "it changes what this machine shares with your organization"},
	{"aggregate_share", CategorySharing, "it changes what this machine shares off the machine"},
	{"observability.store_content", CategoryCapture, "it changes whether an app's prompt and response bodies are kept"},
	{"observer.process.network.capture_bodies", CategoryCapture, "it changes whether network bodies are captured"},
	{"observability.egress", CategoryEgress, "it changes where an app's model requests are routed"},
	{"observability.judge", CategoryEgress, "it changes where an app's content is sent to be judged"},
	{"observability.admission.judge", CategoryEgress, "it changes where an app's content is sent to be judged"},
	{"observability.eval.judge_base_url", CategoryEgress, "it changes where an app's content is sent to be judged"},
	{"observability.admission.budget", CategoryBudget, "it changes an app's end-user spending limits"},
	{"observability.admission.enabled", CategoryAdmission, "it changes whether an app's requests are checked before they run"},
	{"observability.admission.mode", CategoryAdmission, "it changes whether admission only reports or also blocks"},
	{"observability.admission.strict", CategoryAdmission, "it changes how strictly admission blocks"},
	{"observability.admission.on_judge_error", CategoryAdmission, "it changes what admission does when its judge fails"},
	// The rest of the admission block as one family (review finding R-B07):
	// its scope, prefilter and secret_remote_judge decide what admission
	// checks and where content is sent. The rows above only give the more
	// specific reason.
	{"observability.admission", CategoryAdmission, "it changes what admission checks and where an app's content is sent to be checked"},
	{"observability.enabled", CategoryAdmission, "it turns app observability, and with it admission, on or off"},
	{"observability.sdk", CategoryDestination, "it sends an app's data off this machine"},
	// Review E-24 (ruling D29): ordinary-looking keys that change egress or
	// safety. The sample rate and scorers decide how much of an app's
	// content goes to the judge, and the judge model which model reads it.
	{"observability.eval.online_sample_rate", CategoryEgress, "it changes how much of an app's content is sent to be judged"},
	{"observability.eval.online_scorers", CategoryEgress, "it changes which checks read an app's content, a judge among them"},
	{"observability.eval.judge_model", CategoryEgress, "it changes which model an app's content is sent to be judged by"},
	{"observability.proxy_turn_traces", CategoryCapture, "it changes whether model calls on an app's upstream lane are recorded as AI Apps traces"},
	{"observability.alerts.enabled", CategorySensitive, "it changes whether AI Apps alerts reach you"},
	{"observer.db_path", CategorySensitive, "it changes where this machine keeps its records, and which records every surface reads"},
}

// rule is one row of the gate table.
type rule struct {
	name  string
	match func(c configschema.KeyCheck, value string) bool
	// decide builds the decision for a matching row.
	decide func(c configschema.KeyCheck, value string) Decision
}

func refuse(reason string) func(configschema.KeyCheck, string) Decision {
	return func(c configschema.KeyCheck, _ string) Decision {
		return Decision{Verdict: Refuse, Reason: reason, Leaf: c.Leaf}
	}
}

// rules is the D19 table, walked top-down; the first match wins.
var rules = []rule{
	{
		name:  "unknown key",
		match: func(c configschema.KeyCheck, _ string) bool { return !c.Found },
		decide: func(c configschema.KeyCheck, _ string) Decision {
			return Decision{Verdict: Refuse, Reason: "unknown config key " + c.Key}
		},
	},
	{
		name:   "a credential",
		match:  func(c configschema.KeyCheck, _ string) bool { return c.Verdict == configschema.KeySecret },
		decide: refuse("it holds a credential, which is never written by an agent or read back"),
	},
	{
		name: "owned by another surface, or a whole table",
		match: func(c configschema.KeyCheck, _ string) bool {
			return c.Verdict == configschema.KeyOwnerElsewhere
		},
		decide: func(c configschema.KeyCheck, _ string) Decision {
			msg := c.Message
			if msg == "" {
				msg = "another surface owns it"
			}
			return Decision{Verdict: Refuse, Reason: "it is read-only here: " + msg, Leaf: c.Leaf}
		},
	},
	{
		name: "refused by the schema (governance, hidden, deprecated)",
		match: func(c configschema.KeyCheck, _ string) bool {
			return c.Verdict != configschema.KeyOK
		},
		decide: func(c configschema.KeyCheck, _ string) Decision {
			return Decision{Verdict: Refuse, Reason: c.Message, Leaf: c.Leaf}
		},
	},
	{
		// D19 names destination `online`: only the literal local keeps data
		// on this machine. The default ("") is not it: a signed-in machine
		// resolves an unset destination to both (D18), so clearing it is a
		// proposal like online (review finding R-B02).
		name: "an SDK destination that keeps data on this machine",
		match: func(c configschema.KeyCheck, value string) bool {
			return c.Leaf.Path == "observability.sdk.destination" && config.SDKDestinationKeepsLocal(value)
		},
		decide: func(c configschema.KeyCheck, _ string) Decision {
			return Decision{Verdict: Apply, Reason: "it keeps an app's data on this machine", Leaf: c.Leaf}
		},
	},
	{
		name: "a D19 security-sensitive family",
		match: func(c configschema.KeyCheck, _ string) bool {
			_, ok := approvalFor(c.Leaf.Path)
			return ok
		},
		decide: func(c configschema.KeyCheck, _ string) Decision {
			p, _ := approvalFor(c.Leaf.Path)
			return Decision{Verdict: Propose, Category: p.category, Reason: p.reason, Leaf: c.Leaf}
		},
	},
	{
		name:  "a sensitive leaf in the schema",
		match: func(c configschema.KeyCheck, _ string) bool { return c.NeedsConfirm },
		decide: func(c configschema.KeyCheck, _ string) Decision {
			return Decision{Verdict: Propose, Category: CategorySensitive, Reason: "it changes what superbased captures, shares or exposes", Leaf: c.Leaf}
		},
	},
	{
		name:  "ordinary",
		match: func(configschema.KeyCheck, string) bool { return true },
		decide: func(c configschema.KeyCheck, _ string) Decision {
			return Decision{Verdict: Apply, Reason: "an ordinary setting", Leaf: c.Leaf}
		},
	},
}

// approvalFor returns the approval family of a dotted key.
func approvalFor(path string) (approvalPrefix, bool) {
	for _, p := range approvalPrefixes {
		if path == p.prefix || strings.HasPrefix(path, p.prefix+".") {
			return p, true
		}
	}
	return approvalPrefix{}, false
}

// Decide classifies an agent's write of key = value (value as typed, the
// `observer config set` spelling). gov is the machine's governance posture
// (nil when ungoverned), so a key the organization pinned or hid is refused
// here exactly as on the CLI.
func Decide(key, value string, gov configschema.KeyGovernance) Decision {
	c := configschema.CheckKey(key, gov)
	if c.Found && c.Leaf.Path != key {
		// A map entry under a leaf (a.b.<id>): judge it by its leaf.
		c.Key = key
	}
	for _, r := range rules {
		if r.match(c, value) {
			return r.decide(c, value)
		}
	}
	return Decision{Verdict: Refuse, Reason: "could not classify " + key}
}

// Prefixes returns the D19 approval families' key prefixes, in table order,
// for the parity and R-165 drift tests.
func Prefixes() []string {
	out := make([]string, len(approvalPrefixes))
	for i, p := range approvalPrefixes {
		out[i] = p.prefix
	}
	return out
}
