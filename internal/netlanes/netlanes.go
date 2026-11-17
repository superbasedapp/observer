package netlanes

import "strings"

// Default says whether a lane runs on a default install.
type Default string

// The closed set of defaults.
const (
	// DefaultOn runs on a default install with no action from you.
	DefaultOn Default = "on"
	// DefaultYourTraffic carries only requests your own AI tool makes.
	DefaultYourTraffic Default = "your tool's traffic"
	// DefaultAfterAccept runs only after a one-time accept you give.
	DefaultAfterAccept Default = "after you accept"
	// DefaultWhenYouAct runs only when you run a command or click.
	DefaultWhenYouAct Default = "when you ask"
	// DefaultOff is off until you turn it on.
	DefaultOff Default = "off"
)

// Lane is one user-facing network lane.
type Lane struct {
	// ID is stable; the README and tests refer to it.
	ID string
	// Name is the short name people see.
	Name string
	// Sends is what leaves the machine.
	Sends string
	// To is where it goes.
	To string
	// When is what starts it.
	When string
	// Default is whether it runs on a default install.
	Default Default
	// TurnOff is how to stop it.
	TurnOff string
	// EgressIDs are the developer lane rows (tests/invariant/
	// egress_lanes_test.go) this lane covers.
	EgressIDs []string
}

// Lanes is the list, in the order people read it: what runs by default
// first, then what you start, then what you turn on.
var Lanes = []Lane{
	{
		ID: "proxy", Name: "AI tool traffic through the proxy",
		Sends:   "your AI tool's own requests, unchanged, with the key the tool already sent",
		To:      "the provider the tool already uses (Anthropic, OpenAI, Google and the like)",
		When:    "an AI tool is routed through the local proxy",
		Default: DefaultYourTraffic,
		TurnOff: "point the tool back at its provider (`observer uninstall` removes the routes Observer wrote)",
		EgressIDs: []string{
			"proxy.upstream", "winrelay",
		},
	},
	{
		ID: "tls-prewarm", Name: "TLS pre-warm",
		Sends:     "bare HEAD requests, no data",
		To:        "the hosts in `[proxy] prewarm_targets` (chatgpt.com and api.openai.com by default)",
		When:      "each time the proxy starts",
		Default:   DefaultOn,
		TurnOff:   "`[proxy] prewarm_targets = []`",
		EgressIDs: []string{"proxy.upstream"},
	},
	{
		ID: "pricing-feed", Name: "Model price list",
		Sends:     "a plain download request; nothing about you or your sessions",
		To:        "superbased.app (the signed public price table)",
		When:      "when Observer starts, then daily, on a machine not connected to a team",
		Default:   DefaultOn,
		TurnOff:   "`[pricing.feed] enabled = false`",
		EgressIDs: []string{"pricing.feed", "pricing.feed.gate"},
	},
	{
		ID: "package-lists", Name: "Package list downloads",
		Sends:     "plain download requests for public files; no package is named",
		To:        "superbased.app (the signed package index)",
		When:      "every 6 hours while package checks are on",
		Default:   DefaultOn,
		TurnOff:   "`[security.deps] index_download = false`",
		EgressIDs: []string{"security.online"},
	},
	{
		ID: "package-checks", Name: "Online package checks",
		Sends:     "the ecosystem, public package name and version of a package an agent installs; never a private package name",
		To:        "api.osv.dev and the public package registries",
		When:      "an agent installs a package, after you accept the one-time notice",
		Default:   DefaultAfterAccept,
		TurnOff:   "`[security.deps] online = false`",
		EgressIDs: []string{"security.online"},
	},
	{
		ID: "osv-database", Name: "Vulnerability database (OSV)",
		Sends:     "plain download requests; only ecosystem and release names, nothing about a project",
		To:        "superbased.app (signed mirror), falling back to the OSV bucket; api.osv.dev for an online scan you ask for",
		When:      "after your one-time accept, refreshed every 6 hours",
		Default:   DefaultAfterAccept,
		TurnOff:   "do not accept it, or `[security.deps] db_source = \"import\"`",
		EgressIDs: []string{"security.scan.osv.db", "security.scan.scalibr"},
	},
	{
		ID: "package-lookup", Name: "Package lookup",
		Sends:     "requests for advisory shards chosen by a short hash of each package name; never a name, version, path or code",
		To:        "shards.superbased.app",
		When:      "a dependency scan, with lookup mode remote or both and your consent",
		Default:   DefaultOff,
		TurnOff:   "`observer security lookup mode local`",
		EgressIDs: []string{"security.scan.osv.shards"},
	},
	{
		ID: "scanner-downloads", Name: "Scanner downloads",
		Sends:     "plain download requests for pinned releases and databases; nothing about a project",
		To:        "github.com, ghcr.io and superbased.app",
		When:      "you turn on an extra scanner (Opengrep, Trivy) and accept its download",
		Default:   DefaultOff,
		TurnOff:   "leave the scanner off",
		EgressIDs: []string{"security.scan.opengrep.net", "security.scan.trivy.net", "security.scan.trivy.db"},
	},
	{
		ID: "sign-in", Name: "Sign-in and AI summaries",
		Sends:     "your sign-in and this machine's public key; for AI summaries, only what you preview and approve",
		To:        "cloud.superbased.app",
		When:      "you sign in (`observer connect`), and each AI summary you turn on",
		Default:   DefaultWhenYouAct,
		TurnOff:   "`observer cloud logout`",
		EgressIDs: []string{"cloud.client", "cloud.gateway"},
	},
	{
		ID: "community", Name: "Community benchmarks",
		Sends:     "a coarse contribution you preview and approve",
		To:        "cloud.superbased.app",
		When:      "you join community benchmarks",
		Default:   DefaultOff,
		TurnOff:   "leave community benchmarks",
		EgressIDs: []string{"cloud.client", "cloud.gateway"},
	},
	{
		ID: "connect-push", Name: "Connect: personal dashboard or team",
		Sends:     "activity from after you connected: a summary for a personal dashboard; full detail (prompts, responses, file paths) for a team, readable by its admins",
		To:        "your personal dashboard or your team's server",
		When:      "this machine is connected",
		Default:   DefaultOff,
		TurnOff:   "`observer disconnect`",
		EgressIDs: []string{"org.client", "org.client.gen", "selfobs.export"},
	},
	{
		ID: "plans-limits", Name: "Plans and limits",
		Sends:     "your account's usage request, with the key you added",
		To:        "the plan provider you added (its own usage endpoint)",
		When:      "you add a plan account",
		Default:   DefaultOff,
		TurnOff:   "`observer plans remove`",
		EgressIDs: []string{"plans.limits"},
	},
	{
		ID: "sandboxes", Name: "Sandboxed and hosted terminals",
		Sends:     "what you run in the sandbox, to the sandbox you chose",
		To:        "the sandbox provider you chose (E2B, Modal, Vercel, Docker, Daytona, InstaBox, your team's OpenShell) or the internet from a local sandbox",
		When:      "you launch a sandboxed terminal",
		Default:   DefaultWhenYouAct,
		TurnOff:   "do not launch one",
		EgressIDs: []string{"sandbox.remote.e2b", "sandbox.remote.modal", "sandbox.remote.vercel", "sandbox.remote.openshell-org", "sandbox.remote.docker", "sandbox.remote.daytona", "sandbox.remote.instabox", "sandbox.egress", "sandbox.setup.net"},
	},
	{
		ID: "cloud-agents", Name: "Cloud agents",
		Sends:     "requests to the cloud agent accounts you linked, with their own keys",
		To:        "the vendors you linked (OpenAI Codex Cloud, GitHub, Cursor, Devin and others)",
		When:      "you link a cloud agent account",
		Default:   DefaultOff,
		TurnOff:   "unlink the account",
		EgressIDs: []string{"cloud.agents", "cloud.session"},
	},
	{
		ID: "code-host", Name: "Code host",
		Sends:     "requests to the code host you connected",
		To:        "the GitHub API and your repositories' remotes",
		When:      "you connect a code host",
		Default:   DefaultOff,
		TurnOff:   "disconnect the code host",
		EgressIDs: []string{"delivery"},
	},
	{
		ID: "ci-checks", Name: "Security checks in CI",
		Sends:     "commit ids and result uploads from a CI job, to your team's server",
		To:        "your team's server",
		When:      "a CI job runs `observer security verify fetch`",
		Default:   DefaultWhenYouAct,
		TurnOff:   "remove the CI step",
		EgressIDs: []string{"security.ci.fetch"},
	},
	{
		ID: "summarize", Name: "observer summarize",
		Sends:     "the session you ask to summarize",
		To:        "the Anthropic API, with your own key",
		When:      "you run `observer summarize`",
		Default:   DefaultWhenYouAct,
		TurnOff:   "do not run it",
		EgressIDs: []string{"summary"},
	},
	{
		ID: "rolling-summary", Name: "Rolling conversation summaries",
		Sends:     "older turns of a long conversation, to be summarized",
		To:        "the provider your tool uses, with the key its request carried",
		When:      "a routed conversation passes the size you set",
		Default:   DefaultOff,
		TurnOff:   "`[compression.conversation.rolling] enabled = false`",
		EgressIDs: []string{"proxy.summary"},
	},
	{
		ID: "judge", Name: "LLM judge",
		Sends:     "the text to be judged, with secrets removed when the judge is not on this machine",
		To:        "the judge endpoint you configured (local or remote)",
		When:      "you configure a judge",
		Default:   DefaultOff,
		TurnOff:   "remove the judge endpoint",
		EgressIDs: []string{"judge", "llm.wire"},
	},
	{
		ID: "guard-cloud", Name: "Guard alerts and lookups",
		Sends:     "a short event summary with secrets removed, or a public package name",
		To:        "the webhooks, judge and registry you configured",
		When:      "you turn on `[guard.cloud]`",
		Default:   DefaultOff,
		TurnOff:   "`[guard.cloud] enabled = false`",
		EgressIDs: []string{"guard.cloud"},
	},
	{
		ID: "alerts", Name: "Alert webhooks, email and notifications",
		Sends:     "the alert or digest you set up",
		To:        "the webhook, mail server or notification service you configured",
		When:      "you configure alerts, a digest or terminal notifications",
		Default:   DefaultOff,
		TurnOff:   "remove the alert, `[email]` or `[remote.notify]` setting",
		EgressIDs: []string{"email", "cmd.observer"},
	},
	{
		ID: "otel-export", Name: "OpenTelemetry export",
		Sends:     "turn-level spans",
		To:        "the OTLP collector you configured",
		When:      "you turn on `[exporter.otel]`",
		Default:   DefaultOff,
		TurnOff:   "`[exporter.otel] enabled = false`",
		EgressIDs: []string{"otel.export"},
	},
	{
		ID: "aggregate", Name: "Aggregate usage share",
		Sends:     "a coarse monthly usage total you preview and approve",
		To:        "the collector you configured",
		When:      "you turn it on and approve the preview",
		Default:   DefaultOff,
		TurnOff:   "`[aggregate_share] enabled = false`",
		EgressIDs: []string{"aggregate"},
	},
	{
		ID: "mcp-relay", Name: "MCP relay",
		Sends:     "your AI tool's MCP requests",
		To:        "the MCP servers your team allows",
		When:      "you turn on `[mcp_relay]`",
		Default:   DefaultOff,
		TurnOff:   "`[mcp_relay] enabled = false`",
		EgressIDs: []string{"mcp.egress", "mcp.relay"},
	},
	{
		ID: "doctor", Name: "Doctor reachability check",
		Sends:     "a connection test, no data",
		To:        "the OpenTelemetry collector address you configured",
		When:      "you run `observer doctor`",
		Default:   DefaultWhenYouAct,
		TurnOff:   "do not run it",
		EgressIDs: []string{"diag.probe"},
	},
}

// Markdown renders the list as one Markdown table: Lane, What is sent,
// Where to, When, Default, How to turn it off.
func Markdown() string {
	var b strings.Builder
	b.WriteString("| Lane | What is sent | Where to | When | Default | How to turn it off |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- |\n")
	for _, l := range Lanes {
		cells := []string{l.Name, l.Sends, l.To, l.When, string(l.Default), l.TurnOff}
		b.WriteString("|")
		for _, c := range cells {
			b.WriteString(" ")
			b.WriteString(mdCell(c))
			b.WriteString(" |")
		}
		b.WriteString("\n")
	}
	return b.String()
}

// mdCell makes text safe inside one Markdown table cell.
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.ReplaceAll(s, "\n", " ")
}
