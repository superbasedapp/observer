package planechoice

import (
	"strings"
)

// ShareTier is one [org_client.share.obs] opt-in tier (T1 to T8,
// docs/deployment-models.md): a kind of AI Apps data an enrolled machine
// sends to its organization.
type ShareTier struct {
	// Key is the config leaf under [org_client.share.obs].
	Key string
	// Label is how the consent sentence names it.
	Label string
}

// ShareTiers is the closed tier table, in the order the sentence lists
// them. A key not in it is dropped (never shown raw).
var ShareTiers = []ShareTier{
	{Key: "summary", Label: "summaries"},
	{Key: "traces", Label: "trace structure"},
	{Key: "content", Label: "span content"},
	{Key: "eval_summary", Label: "eval summaries"},
	{Key: "admission", Label: "admission verdicts"},
	{Key: "eval_items", Label: "eval scores"},
	{Key: "egress", Label: "egress decisions"},
}

// ConsentFacts is what the consent sentence reads.
type ConsentFacts struct {
	// Enrolled: the machine is enrolled in an organization and its push
	// rail is on.
	Enrolled bool
	// Org is the organization's display name ("" reads "your organization").
	Org string
	// Tiers are the [org_client.share.obs] keys in force (after the
	// organization's own lowering or raise), in any order.
	Tiers []string
	// AllowNonLoopback: [ingest.otel] allow_non_loopback is set.
	AllowNonLoopback bool
}

// Consent is the built sentence and the facts behind it.
type Consent struct {
	// Row names the consentRules row that built it.
	Row string `json:"row"`
	// Sentence is the one line every surface shows (card, CLI, docs, "What
	// changes").
	Sentence string `json:"sentence"`
	// Shared: AI Apps data also leaves this machine for the organization.
	Shared bool   `json:"shared"`
	Org    string `json:"org,omitempty"`
	// Tiers are the labels named in the sentence.
	Tiers []string `json:"tiers,omitempty"`
	// LoopbackOnly: the receiver accepts only this machine, so the address
	// is shown with ReceiverNote.
	LoopbackOnly bool   `json:"loopback_only"`
	ReceiverNote string `json:"receiver_note,omitempty"`
}

// tierLabels returns the labels of the known keys in t, in table order.
func tierLabels(t []string) []string {
	on := map[string]bool{}
	for _, k := range t {
		on[strings.TrimSpace(k)] = true
	}
	var out []string
	for _, st := range ShareTiers {
		if on[st.Key] {
			out = append(out, st.Label)
		}
	}
	return out
}

// consentRules is the two-row sentence builder (plan 3.5, review P-05),
// walked top-down.
var consentRules = []struct {
	name  string
	when  func(f ConsentFacts, labels []string) bool
	build func(f ConsentFacts, labels []string) Consent
}{
	{
		name: "not enrolled, or no AI Apps share tier on",
		when: func(f ConsentFacts, labels []string) bool { return !f.Enrolled || len(labels) == 0 },
		build: func(ConsentFacts, []string) Consent {
			return Consent{Sentence: "Stays on this machine."}
		},
	},
	{
		name: "enrolled with a share tier on",
		when: func(ConsentFacts, []string) bool { return true },
		build: func(f ConsentFacts, labels []string) Consent {
			org := strings.TrimSpace(f.Org)
			if org == "" {
				org = "your organization"
			}
			return Consent{
				Sentence: "Also sent to " + org + " (" + strings.Join(labels, ", ") + ").",
				Shared:   true, Org: org, Tiers: labels,
			}
		},
	},
}

// BuildConsent builds the consent sentence.
func BuildConsent(f ConsentFacts) Consent {
	labels := tierLabels(f.Tiers)
	var c Consent
	for _, r := range consentRules {
		if r.when(f, labels) {
			c = r.build(f, labels)
			c.Row = r.name
			break
		}
	}
	c.LoopbackOnly = !f.AllowNonLoopback
	if c.LoopbackOnly {
		c.ReceiverNote = "(this machine only)"
	}
	return c
}
