package main

import (
	"fmt"
	"io"
	"net/url"
	"strings"
)

// admission_judge.go is the "judge in effect" (hosted AI gateway plan
// section 4 item 3, lane L7 node and CLI): which judge decides an AI Apps
// admission check on this machine, where its configuration comes from, and
// what is wrong with it. Users blur the machine judge, the org relay and the
// org's own judge; this answers it from config alone (the plan's "the node
// judge-in-effect API reads config only"). The resolver lives at the obs
// wiring point (obsAdmissionJudgeInEffect, obs_wire.go; a stub when the
// build has no AI Apps admission). Served as GET /api/obs/admission/judge
// (S5) and printed by `observer obs admission status`.

// The judge kinds.
const (
	// judgeKindMachine is a judge this machine calls itself.
	judgeKindMachine = "machine"
	// judgeKindOrg is the organization's admission judge, reached through
	// the org relay (use_org_relay), or the org deciding admit() itself.
	judgeKindOrg = "org"
	// judgeKindNone: no judge runs; judged criteria degrade to the
	// deterministic layers.
	judgeKindNone = "none"
)

// admissionJudgeEffect is the judge in effect on this machine.
type admissionJudgeEffect struct {
	// AdmissionEnabled is [observability.admission] enabled (and
	// [observability] on). With it off no machine check runs at all.
	AdmissionEnabled bool `json:"admission_enabled"`
	// Judge is judgeKindMachine, judgeKindOrg or judgeKindNone for a check
	// this machine runs: an app lane call and an admit() sent to the machine.
	Judge string `json:"judge"`
	// Hosting is the judge's hosting label (org_relay, local, provider,
	// aggregator, private, off).
	Hosting string `json:"hosting"`
	// Model is the machine judge's model ("" for the org relay).
	Model string `json:"model"`
	// Endpoint is the machine judge's host (never a path, a query or a key).
	Endpoint string `json:"endpoint"`
	// Source is the config key that decided the judge.
	Source string `json:"source"`
	// Enrolled is true when this machine is enrolled with an organization
	// ([org_client] enabled with a server), so the org relay can work and
	// `observer obs admission setup` offers the org's judge.
	Enrolled bool `json:"enrolled"`
	// SDKDestination is where the SDKs send admit() by default
	// ([observability.sdk] destination; "" is the default).
	SDKDestination string `json:"sdk_destination"`
	// SDKJudge says which judge decides an SDK admit() under that
	// destination (the org decides one sent to it).
	SDKJudge string `json:"sdk_judge"`
	// Summary is one plain sentence for the CLI and the dashboard card.
	Summary string `json:"summary"`
	// Warnings name configuration that does not do what it looks like.
	Warnings []string `json:"warnings"`
}

// judgeEndpointHost returns the host of a judge base URL ("" when none).
func judgeEndpointHost(base string) string {
	if strings.TrimSpace(base) == "" {
		return ""
	}
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	return u.Host
}

// printAdmissionJudgeEffect prints the judge in effect for the CLI.
func printAdmissionJudgeEffect(out io.Writer, e admissionJudgeEffect) {
	fmt.Fprintf(out, "judge in effect: %s\n", e.Summary)
	if e.Source != "" {
		fmt.Fprintf(out, "judge source:    %s\n", e.Source)
	}
	fmt.Fprintf(out, "sdk admit():     %s\n", e.SDKJudge)
	for _, w := range e.Warnings {
		fmt.Fprintf(out, "judge warning:   %s\n", w)
	}
}
