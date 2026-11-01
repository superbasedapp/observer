package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/config"
)

// privacyJSONSchema is the stable --json envelope discriminator, mirroring
// the additive-only versioning convention `observer usage`/`observer
// statusline` already use for their own --json output.
const privacyJSONSchema = "superbased.privacy/1"

// privacyDocsURL is the canonical doc this command points operators at for
// the full-detail privacy model (source-of-truth prose; this command is the
// machine-checkable summary of the same facts).
const privacyDocsURL = "https://superbased.app/docs/reference/measurement-honesty"

// privacyDeps are the injectable I/O seams of `observer privacy` (mirrors
// statuslineDeps in cmd/observer/statusline.go). Production wiring is
// defaultPrivacyDeps(); tests substitute a fixed config.Config so a test
// never touches the operator's real ~/.observer/config.toml.
type privacyDeps struct {
	// loadConfig returns the effective, already-merged-with-defaults
	// config. This is the ONLY input the report is built from — the
	// command makes no other reads and, per its own claim, no network
	// calls at all.
	loadConfig func() (config.Config, error)
}

// defaultPrivacyDeps returns the production seams.
func defaultPrivacyDeps() privacyDeps {
	return privacyDeps{
		loadConfig: func() (config.Config, error) {
			return config.Load(config.LoadOptions{})
		},
	}
}

// privacySocket describes one listener this binary can open, derived from
// the live config rather than hardcoded, so the report stays honest as
// defaults change.
type privacySocket struct {
	Name    string `json:"name"`
	Addr    string `json:"addr"`
	Active  bool   `json:"active"`
	Purpose string `json:"purpose"`
}

// privacyEgress describes one outbound-network capability compiled into
// this binary: what has to be true for it to fire (Gate), whether that's
// currently the case for the loaded config (Active), and a one-line
// explanation of what it sends and to whom.
type privacyEgress struct {
	Name   string `json:"name"`
	Gate   string `json:"gate"`
	Active bool   `json:"active"`
	Detail string `json:"detail"`
}

// privacyReport is the full --json envelope of `observer privacy`.
type privacyReport struct {
	Schema  string          `json:"schema"`
	Sockets []privacySocket `json:"sockets"`
	Egress  []privacyEgress `json:"egress"`
	DocsURL string          `json:"docs_url"`
}

// buildPrivacyReport derives the entire report from cfg. Pure function, no
// I/O — every row is table-driven off a config field, never hardcoded,
// so a config change (a new default, a flipped toggle) is reflected here
// automatically instead of drifting out of sync with a hand-maintained
// claim.
func buildPrivacyReport(cfg config.Config) privacyReport {
	return privacyReport{
		Schema:  privacyJSONSchema,
		Sockets: buildPrivacySockets(cfg),
		Egress:  buildPrivacyEgress(cfg),
		DocsURL: privacyDocsURL,
	}
}

// buildPrivacySockets lists every listener the daemon can open, under
// `observer start` or a standalone subcommand, with its configured bind
// address and whether the config currently arms it. Every socket defaults
// to a 127.0.0.1 loopback bind, but "loopback-only" is NOT a binary-wide
// guarantee, and remote-access is not the only rail that can leave it:
// browser-ingest, otlp-ingest, and processobs-accept each carry their own
// `allow_non_loopback` escape hatch (off by default, noted on their own
// Purpose line below); remote-access is the opt-in wide-exposure rail with
// its own bound-address check (see remoteSocketAddr). The dashboard's
// `--addr` and the proxy's `--bind` CLI flags can also override the
// configured address for a single invocation — this report reflects the
// loaded CONFIG FILE, not any CLI override in effect for a given run.
func buildPrivacySockets(cfg config.Config) []privacySocket {
	proxyPort := cfg.Proxy.Port
	if proxyPort <= 0 {
		proxyPort = 8820
	}
	dashboardAddr := resolveDashboardAddr("", cfg.Dashboard.Addr, "127.0.0.1:8081")

	browserAddr := cfg.Browser.Listener.ListenAddr
	if browserAddr == "" {
		browserAddr = "127.0.0.1:8821"
	}
	browserActive := cfg.Browser.Enabled && cfg.Browser.Listener.Enabled

	otlpGRPCAddr := cfg.Ingest.OTel.GRPCAddr
	if otlpGRPCAddr == "" {
		otlpGRPCAddr = "127.0.0.1:4317"
	}
	otlpHTTPAddr := cfg.Ingest.OTel.HTTPAddr
	if otlpHTTPAddr == "" {
		otlpHTTPAddr = "127.0.0.1:4318"
	}
	// F3: cmd/observer/start.go (~line 704) binds the shared OTLP receiver
	// when EITHER [ingest.otel].enabled (the native-telemetry logs path)
	// OR [observability].enabled (the Plane-A trace receiver) is set — it
	// only stays fully closed when both are off.
	otlpActive := cfg.Ingest.OTel.Enabled || cfg.Observability.Enabled

	processAddr := cfg.Observer.Process.ETW.ListenAddr
	if processAddr == "" {
		processAddr = "127.0.0.1:8823"
	}
	processActive := cfg.Observer.Process.Enabled && cfg.Observer.Process.ETW.Enabled

	proxyPurpose := "Reverse proxy an AI tool can point at to get accurate token counts + conversation compression. The listener binds whenever the daemon runs (`observer start` or `observer proxy start`), REGARDLESS of [proxy].enabled - that flag is validated but never gates the listener. Forwards a request only when a tool is actually configured to route through it. The `--bind` CLI flag can override the bind address shown here for a single invocation."
	// REVIEW-4 P4-19: a build without capture.proxy never binds it, so the
	// row says so instead of reporting a listener that does not exist.
	if reason := proxyNotInBuildReason(); reason != "" {
		proxyPurpose = "Not bound: " + reason + ". Nothing in this binary listens on this port."
	}

	sockets := []privacySocket{
		{
			Name:   "proxy",
			Addr:   fmt.Sprintf("127.0.0.1:%d", proxyPort),
			Active: !proxyNotInBuild(),
			// F8: buildProxy is called unconditionally by both `observer
			// start` and `observer proxy start` — cfg.Proxy.Enabled is
			// validated (port-range check) but never gates whether the
			// listener binds, so Active is true in every build that carries
			// capture.proxy (and false in one that does not, P4-19).
			Purpose: proxyPurpose,
		},
		{
			Name: "dashboard",
			Addr: dashboardAddr,
			// A build without ui.dashboard never binds it (MP-L1M).
			Active:  dashboardInBuild,
			Purpose: "Local analytics dashboard + REST API (`observer start` or `observer dashboard`). Serves the embedded UI and this machine's own captured data. The `--addr` CLI flag can override the bind address shown here for a single invocation.",
		},
		{
			Name:    "browser-ingest",
			Addr:    browserAddr,
			Active:  browserActive,
			Purpose: "Opt-in HTTP receiver for the browser-capture extension. Off by default - the extension's default transport is native messaging, which never opens a socket. Has its own [browser.listener].allow_non_loopback escape hatch (off by default).",
		},
		{
			Name:    "otlp-ingest",
			Addr:    otlpGRPCAddr + " (gRPC), " + otlpHTTPAddr + " (HTTP)",
			Active:  otlpActive,
			Purpose: "Opt-in OTLP receiver: serves an AI tool's own native telemetry export ([ingest.otel].enabled, e.g. Claude Code with CLAUDE_CODE_ENABLE_TELEMETRY=1) AND the generalized-observability trace receiver ([observability].enabled) - it binds when EITHER gate is set, not just the logs one. Has its own [ingest.otel].allow_non_loopback escape hatch (off by default).",
		},
		{
			Name:    "processobs-accept",
			Addr:    processAddr,
			Active:  processActive,
			Purpose: "Opt-in accept listener for the Windows ETW process-observability capturer sidecar. Off by default; only relevant when [observer.process] is enabled with the etw backend. Has its own allow_non_loopback escape hatch (off by default).",
		},
	}

	if cfg.Remote.Enabled {
		addr, bound := remoteSocketAddr(cfg)
		sockets = append(sockets, privacySocket{
			Name:   "remote-access",
			Addr:   addr,
			Active: bound,
			// F10/F11: [remote].enabled alone only arms the substrate —
			// nothing binds non-loopback until an exposure mode resolves
			// to a concrete address (lan bind_addr, or the tailscale
			// backend addr). Active reflects that, not the enabled flag.
			// Not the only rail that can leave loopback — see
			// browser-ingest / otlp-ingest / processobs-accept above.
			Purpose: "Opt-in remote dashboard access (`observer remote enable`) - tailnet-only, or an explicit lan bind_addr, never a bare 0.0.0.0; every request still requires device auth. Armed by [remote].enabled=true, but nothing binds until an exposure mode resolves to a concrete address (see Active).",
		})
	}

	return sockets
}

// remoteSocketAddr renders the [remote] block's active bind address for
// display and reports whether that address is actually BOUND. bound is
// true only when the exposure mode resolves to a concrete, bindable
// address: mode=lan with BindAddr set, or mode=tailscale with the
// tailscale backend addr set. [remote].enabled=true alone (mode=off, or a
// mode chosen but its address not yet assigned) arms the substrate without
// binding anything — that state must never render as "[on]" with no
// address (F10).
func remoteSocketAddr(cfg config.Config) (addr string, bound bool) {
	switch cfg.Remote.Mode {
	case "tailscale":
		if cfg.Remote.TailscaleBackendAddr != "" {
			return cfg.Remote.TailscaleBackendAddr + " (tailnet-local backend, TLS terminated by tailscale serve)", true
		}
	case "lan":
		if cfg.Remote.BindAddr != "" {
			return cfg.Remote.BindAddr, true
		}
	}
	return "(exposure mode not yet configured - substrate armed, nothing bound)", false
}

// guardCloudSweepArmed reports whether the daemon-resident guard-cloud
// sweep dispatcher runs at all, mirroring the gate cmd/observer/start.go
// checks before constructing it: [guard].enabled AND [guard].mode != "off"
// AND [guard.cloud].enabled. It's the shared master half of the webhook
// and LLM-judge rows' gates; reputation is excluded — it's the on-demand
// CLI surface and does not depend on the sweep loop (see
// cmd/observer/guardcloud.go's hasEventFeatures doc comment).
func guardCloudSweepArmed(cfg config.Config) bool {
	return cfg.Guard.Enabled && cfg.Guard.Mode != "off" && cfg.Guard.Cloud.Enabled
}

// guardHasWebhookURL reports whether at least one [[guard.cloud.webhooks]]
// entry has a URL configured — the per-feature half of the guard-cloud
// webhook gate (the master half is guardCloudSweepArmed).
func guardHasWebhookURL(webhooks []config.GuardWebhookConfig) bool {
	for _, w := range webhooks {
		if w.URL != "" {
			return true
		}
	}
	return false
}

// prewarmTargetsList renders the configured TLS pre-warm target list for
// the egress detail line, or a fixed placeholder when the config has
// explicitly emptied the list (which also disables the feature — see
// internal/proxy/prewarm_test.go's explicit-empty-disables case).
func prewarmTargetsList(targets []string) string {
	if len(targets) == 0 {
		return "(none configured)"
	}
	return strings.Join(targets, ", ")
}

// pricingFeedInBuild reports whether this binary carries the
// egress.pricing-feed component (a -tags sbo_omit_egress_pricing_feed build
// links no feed client and never fetches, see pricing_omit.go).
func pricingFeedInBuild() bool {
	return !slices.Contains(components.Omitted(), "egress.pricing-feed")
}

// pricingFeedHours is the effective auto-poll cadence, mirroring
// runPricingAutoSync's own fallback (a non-positive value polls daily).
func pricingFeedHours(fc config.PricingFeedConfig) int {
	if fc.PollIntervalHours <= 0 {
		return 24
	}
	return fc.PollIntervalHours
}

// urlHost renders the host of raw for a detail line, or raw itself when it
// does not parse as an absolute URL.
func urlHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Host
}

// pricingFeedRow is the [pricing.feed] egress row (T-931): the default-on
// background fetch of the signed public price table, which runs only on a
// node that is not enrolled with an org server. Active reflects the config
// flags and the build; enrolment is a DB fact this config-only report cannot
// see, so the gate says so instead of guessing.
func pricingFeedRow(cfg config.Config) privacyEgress {
	fc := cfg.Pricing.Feed
	hours := pricingFeedHours(fc)
	feedURL := nonEmpty(fc.URL, config.DefaultPricingFeedURL)
	detail := fmt.Sprintf("A GET to %s (%s) for the signed public model price table: once when the daemon starts, then every %d h. The request carries an Accept header and, after the first fetch, an If-None-Match of the last table's digest (a 304 when nothing changed); no account, no node id, nothing about your sessions or code. The table is verified offline against a key compiled into the binary before any price is used. Turn it off with [pricing.feed] enabled = false (no fetch at all), or set auto = false to fetch only when you run `observer pricing sync`.", urlHost(feedURL), feedURL, hours)
	if !pricingFeedInBuild() {
		detail = "Not in this build (the egress.pricing-feed component is compiled out): no feed is ever fetched. " + detail
	}
	if cfg.OrgClient.Enabled {
		detail += " For this config: [org_client].enabled = true. If this node is enrolled, its prices come through the org rail and the feed poller refuses on every tick; run `observer org status` to check enrolment."
	}
	return privacyEgress{
		Name:   "pricing feed",
		Gate:   fmt.Sprintf("[pricing.feed].enabled = true AND [pricing.feed].auto = true (both on by default) AND this node is not enrolled with an org server (an enrolled node gets prices from the org rail; enrolment is not checked by this report). Fires automatically at daemon start and every [pricing.feed].poll_interval_hours (now %d), no operator action needed", hours),
		Active: fc.Enabled && fc.Auto && pricingFeedInBuild(),
		Detail: detail,
	}
}

// prewarmRow is the TLS pre-warm egress row: the proxy's on-by-default
// startup HEAD requests against [proxy].prewarm_targets. A build without
// capture.proxy never starts the proxy, so it never fires.
func prewarmRow(cfg config.Config) privacyEgress {
	targets := cfg.Proxy.PrewarmTargets
	hosts := make([]string, 0, len(targets))
	for _, t := range targets {
		hosts = append(hosts, urlHost(t))
	}
	hostList := "(none)"
	if len(hosts) > 0 {
		hostList = strings.Join(hosts, ", ")
	}
	detail := fmt.Sprintf("HEAD requests fired once each time the proxy starts, against: %s (hosts: %s) - to warm the TLS connection so the first real request through the proxy doesn't pay the handshake. No session data, no request body, no headers beyond the bare HEAD; not driven by anything you typed or ran. Turn it off with [proxy] prewarm_targets = [] (an explicitly empty list disables it).", prewarmTargetsList(targets), hostList)
	if reason := proxyNotInBuildReason(); reason != "" {
		detail = "Not fired: " + reason + ". " + detail
	}
	return privacyEgress{
		Name:   "TLS pre-warm",
		Gate:   "[proxy].prewarm_targets is non-empty (default: chatgpt.com + api.openai.com) - fires automatically once at each proxy startup, no operator action needed",
		Active: len(targets) > 0 && !proxyNotInBuild(),
		Detail: detail,
	}
}

// routingProbeRow is the optional routing upstream prober: with routing and
// its active probe both on, the proxy re-fires the pre-warm HEADs against the
// configured Anthropic and OpenAI upstreams on a ticker (cmd/observer/proxy.go).
func routingProbeRow(cfg config.Config) privacyEgress {
	return privacyEgress{
		Name:   "routing upstream probe",
		Gate:   "[routing].enabled = true AND [routing.reliability.probe].enabled = true (off by default)",
		Active: cfg.Routing.Enabled && cfg.Routing.Reliability.Probe.Enabled && !proxyNotInBuild(),
		Detail: fmt.Sprintf("HEAD requests every %d s to the configured upstreams (%s, %s) so connectivity failures show in the daemon log and the connection pool stays warm. No session data, no request body. Turn it off with [routing.reliability.probe] enabled = false.", cfg.Routing.Reliability.Probe.IntervalSeconds, urlHost(cfg.Proxy.AnthropicUpstream), urlHost(cfg.Proxy.OpenAIUpstream)),
	}
}

// buildPrivacyEgress lists every outbound-network capability compiled into
// this binary. Each row states its gate in plain language and whether the
// loaded config currently arms it. Two rows run automatically on a default
// install, and both carry no session data: the pricing feed fetch (standalone
// nodes only) and the TLS pre-warm HEAD requests at proxy startup. Every
// other row forwards your own AI tool's traffic or needs an explicit opt-in.
func buildPrivacyEgress(cfg config.Config) []privacyEgress {
	orgPushDetail := "Pushes rollup rows (hashed by default; raw content only under a local [org_client.share].full_content/admin_managed opt-in - the org admin can never flip this remotely) and polls the org policy bundle. The same poll also fetches the org's dashboard announcement, if any - a GET on the connection this cycle already opens, no extra request and nothing sent about you; it can only put dismissible text in your dashboard banner, there is no acknowledgment wire back, and [dashboard].org_announcements = false silences it locally. Stated plainly, because it is inherent to any fetch and not something a client-side switch can remove: the server can SEE the request - that your enrolled node polled, and when - exactly as it sees the push. There is no read receipt (whether a banner was shown or dismissed is never reported), but the poll itself is observable to the org you enrolled with. The same cycle also fetches this node's own signed BUDGET policy (GET /api/agent/budget) when [org_client] is on - one more conditional GET on the same already-open connection to the same already-enrolled host, sending nothing about you beyond the bearer that identifies the node. What comes BACK is your effective cap; what goes back UP is an enum-only posture row (enforcement point / guard mode / where the numbers came from / last fetch state / proxy-only coverage) carrying no cap value and no team label. Set [guard.budget].from_org = false and the org's numbers are never applied."
	switch {
	case cfg.OrgClient.Enabled && cfg.OrgClient.ConfiguredServerURL():
		orgPushDetail += fmt.Sprintf(" For this config: enrolled against %s.", cfg.OrgClient.OrgServerURL)
	case cfg.OrgClient.Enabled:
		// BLOCK-1 (code review): this report is deliberately DB-free and
		// network-free (defaultPrivacyDeps loads only config), so it
		// cannot see whether a persisted org_enrolment row exists — a
		// blank org_server_url here does NOT mean this node is inactive.
		// cmd/observer/start.go's orgClientShouldStart starts the org
		// client whenever EITHER the config carries a URL OR a persisted
		// row does; the push/announcement/routing-policy loops then dial
		// that row's own server, never this config field. Say so honestly
		// instead of guessing either way.
		orgPushDetail += " For this config: [org_client].enabled = true but org_server_url is empty in config. This report cannot see whether a persisted enrolment record exists (it reads config only, by design) - if one does, the org rail is still ACTIVE against that record's own server; if this node was never enrolled, it is inactive. Run `observer doctor` for the definitive state."
	}

	guardCloudArmed := guardCloudSweepArmed(cfg)
	webhooksConfigured := guardHasWebhookURL(cfg.Guard.Cloud.Webhooks)

	rows := []privacyEgress{
		{
			Name: "proxy forwarding",
			// F8: [proxy].enabled does not gate the listener (see the
			// proxy socket row), so it doesn't gate forwarding either —
			// said explicitly here rather than left implicit.
			Gate:   "an AI tool's own base URL is pointed at the local proxy AND it sends a request ([proxy].enabled is validated but does not gate this - the listener binds regardless)",
			Active: true,
			Detail: "Forwards that request unchanged to the same upstream provider the tool already talks to (Anthropic/OpenAI/Gemini), using the API key already present in the request. Not a new destination - it's the tool's own traffic passing through a local relay.",
		},
		{
			Name: "Teams org push + policy poll",
			// F9: the config flags are all this report can check; whether
			// the push actually goes anywhere ALSO depends on (a) a
			// persisted org_enrolment DB row — a blank org_server_url in
			// config does NOT disable an already-enrolled node, since the
			// push/policy loops dial that row's own server URL instead
			// (config.OrgClientConfig.ConfiguredServerURL / cmd/observer/
			// start.go::orgClientShouldStart) — and (b) a valid enrollment
			// bearer credential. Neither is checked by this report: it is
			// deliberately config-only, no DB open and no network call (see
			// defaultPrivacyDeps). Active therefore reflects only `enabled`
			// — the necessary but not sufficient condition this report CAN
			// see — rather than pretending precision it doesn't have; run
			// `observer doctor` for the definitive state.
			Gate:   "[org_client].enabled = true AND (org_server_url is non-empty OR a persisted enrolment record exists) (Active reflects only this config flag) AND a valid enrollment bearer credential (neither the DB row nor the credential is checked by this report - run `observer doctor` or `observer org status`)",
			Active: cfg.OrgClient.Enabled,
			Detail: orgPushDetail,
		},
		{
			Name:   "dashboard update check",
			Gate:   "the operator clicks \"Check for updates\" in Settings → Health",
			Active: false,
			Detail: "A GET to registry.npmjs.org for the latest published version number. That same response - the published package.json of our own npm package - may also carry an optional release announcement, which the dashboard shows as a dismissible banner. It is read from this one response: no second request, no other host, and nothing is sent about you. Never automatic - no background timer, no fetch on tab load. See web/src/lib/version.ts.",
		},
		{
			Name: "org update manifest + artifact fetch",
			// The manifest GET rides the push cycle the node ALREADY makes,
			// to the host it is ALREADY enrolled with — so it adds no new
			// egress CLASS. The artifact fetch is the same host and the same
			// credential. A node never contacts GitHub, npm or a CDN as part
			// of an update (ruling R8), which is what makes this design
			// air-gap-native rather than air-gap-capable.
			Gate: "[update].enabled = true AND [org_client].enabled = true (Active reflects only these two config flags) AND a valid enrolment bearer credential AND a manifest published ahead of this node",
			// BOTH flags, because ruling R8 makes the org server the ONLY
			// host a node fetches update bytes from: with no enrolment there
			// is no rail at all, so reporting this row active on a solo
			// install would claim an egress capability that cannot fire.
			Active: cfg.Update.Enabled && cfg.OrgClient.Enabled,
			Detail: "Two GETs to the org server this node is already enrolled with, on the connection the push loop already opens: the signed update manifest, and - only when an apply actually runs - the artifact bytes. What it DISCLOSES is inherent to any fetch: that this node asked for version X at time T, exactly as the announcement rail already states. Nothing is sent about the developer, and no other host is contacted. The node's own update state rides the existing push envelope as an enum-only row (version / channel / os / arch / state / target / error class / install method) with no hostname, no path and no free-text error.",
		},
		{
			Name:   "observer summarize",
			Gate:   "the operator runs `observer summarize` AND an API key is set (ANTHROPIC_API_KEY or intelligence.api_key_env)",
			Active: false,
			Detail: "An explicit, on-demand CLI invocation that calls the Anthropic Messages API to summarize a session. Never runs as part of the daemon, a hook, or `observer start`.",
		},
		{
			Name: "aggregate-share rail",
			// F9: same honesty note as org push — a fresh consent
			// receipt is a separate, unverified-by-this-report precondition.
			Gate:   "[aggregate_share].enabled = true (Active reflects only this config flag) AND a valid consent receipt (not checked by this report - run `observer aggregate status`)",
			Active: cfg.AggregateShare.Enabled,
			Detail: fmt.Sprintf("POSTs a coarsened monthly usage aggregate to %s. The product's first opt-in network call outside Teams org-push; off by default and inert without a fresh consent receipt even when the config flag is set.", nonEmpty(cfg.AggregateShare.Endpoint, "the configured collector")),
		},
		{
			Name:   "OTel exporter",
			Gate:   "[exporter.otel].enabled = true",
			Active: cfg.Exporter.OTel.Enabled,
			Detail: fmt.Sprintf("Exports turn-level spans to an OTLP collector at %s. Off by default.", nonEmpty(cfg.Exporter.OTel.Endpoint, "localhost:4318")),
		},
		{
			Name:   "generalized observability (Plane A)",
			Gate:   "[observability].enabled = true",
			Active: cfg.Observability.Enabled,
			Detail: "Optional admission LLM-judge calls, node-side alert webhooks, and egress routing for a hosted app the operator is separately observing. Off by default; only relevant to Plane-A deployments, not to a solo coding-agent install.",
		},
		{
			Name:   "email / digest alerts",
			Gate:   "[email].enabled = true (digest additionally needs [digest].enabled)",
			Active: cfg.Email.Enabled,
			Detail: "Sends SMTP mail to the configured server for a fired budget/security alert or a scheduled cost digest. Off by default.",
		},
		{
			Name: "remote-access notify",
			// F4: cmd/observer/remotenotify.go keys ONLY off
			// [remote.notify].enabled; cmd/observer/attach_standalone.go
			// wires the same OnExit closure for EVERY terminal session
			// (attach/resume/launch), not just remote-originated ones.
			// [remote].enabled is NOT part of this gate.
			Gate:   "[remote.notify].enabled = true - fires on ANY terminal session exit; [remote].enabled is NOT part of this gate",
			Active: cfg.Remote.Notify.Enabled,
			Detail: "Fires a webhook/ntfy call on a terminal session's lifecycle event (session_blocked, session_finished, ...) for every attach/resume/launch session - the OnExit wiring in cmd/observer/attach_standalone.go is shared, it isn't specific to remote-originated sessions. Off by default.",
		},
		// F1: internal/proxy.Prewarm fires HEAD requests against
		// [proxy].prewarm_targets at proxy startup (default non-empty:
		// chatgpt.com + api.openai.com, see internal/config's Default()).
		// One of the two automatic, on-by-default outbound calls; the
		// other is the pricing feed row below (T-931).
		prewarmRow(cfg),
		pricingFeedRow(cfg),
		routingProbeRow(cfg),
		{
			// F2: internal/guard/notify/egress.go is the single egress
			// worker for every guard-cloud call; cmd/observer/start.go
			// only constructs the sweep dispatcher when guardCloudSweepArmed
			// holds, and only fires a webhook when a URL is configured.
			Name:   "guard cloud webhooks",
			Gate:   "[guard].enabled = true AND [guard].mode != \"off\" AND [guard.cloud].enabled = true AND at least one [[guard.cloud.webhooks]] entry has a url set",
			Active: guardCloudArmed && webhooksConfigured,
			Detail: "Posts a guard_events summary (generic/slack/discord/pagerduty, per-webhook min_severity) to each configured [[guard.cloud.webhooks]] URL when the daemon's cloud dispatcher sweeps a qualifying event. Body is redacted (scrub.RawJSON) and capped at [guard.cloud].payload_max_bytes before send.",
		},
		{
			Name:   "guard cloud LLM judge",
			Gate:   "[guard].enabled = true AND [guard].mode != \"off\" AND [guard.cloud].enabled = true AND [guard.cloud.llm_judge].enabled = true",
			Active: guardCloudArmed && cfg.Guard.Cloud.LLMJudge.Enabled,
			Detail: fmt.Sprintf("Sends an ask-class guard event's context to the bring-your-own OpenAI-chat-completions-compatible endpoint at %s for an automated allow/deny recommendation, authenticated with the key named by [guard.cloud.llm_judge].api_key_env. Off by default.", nonEmpty(cfg.Guard.Cloud.LLMJudge.Endpoint, "(no endpoint configured)")),
		},
		{
			// F2: reputation is the on-demand CLI surface
			// (`observer guard mcp reputation`) — it does NOT depend on
			// [guard].enabled/mode or the sweep dispatcher, only its own
			// double opt-in (see cmd/observer/guardcloud.go's
			// newGuardMCPReputationCmd doc comment).
			Name:   "guard cloud reputation lookup",
			Gate:   "[guard.cloud].enabled = true AND [guard.cloud.reputation].enabled = true AND the operator runs `observer guard mcp reputation <package>` (on-demand, no background sweep)",
			Active: cfg.Guard.Cloud.Enabled && cfg.Guard.Cloud.Reputation.Enabled,
			Detail: "One GET per invocation to registry.npmjs.org for an MCP server package's registry metadata (age, maintainers, version count). Never fires automatically - no sweep, no hook.",
		},
		{
			// F2: internal/compression/conversation/rolling.go, wired via
			// cmd/observer/proxy_profiles.go — the summarizer factory is
			// attached whenever Rolling.Enabled is set (independent of
			// [compression.conversation].enabled itself), but it only ever
			// runs inside the conversation-compression pipeline, which only
			// executes on requests the proxy forwards.
			Name:   "rolling conversation summarization",
			Gate:   "[compression.conversation.rolling].enabled = true AND an AI tool is routed through the proxy (the conversation-compression pipeline - and therefore rolling summarization - only runs on requests the proxy forwards)",
			Active: cfg.Compression.Conversation.Rolling.Enabled,
			Detail: fmt.Sprintf("When a session's estimated tokens cross [compression.conversation.rolling].threshold_tokens, sends the accumulated conversation content to the configured summarizer provider (%s for Anthropic-shaped traffic, %s for OpenAI-shaped) to produce a rolling summary that replaces the older turns. Off by default.", nonEmpty(cfg.Compression.Conversation.Rolling.SummaryModel, "claude-haiku-4-5"), nonEmpty(cfg.Compression.Conversation.Rolling.OpenAISummaryModel, "gpt-5-nano")),
		},
	}
	return rows
}

// nonEmpty returns s unless it's empty, in which case it returns fallback —
// a small formatting helper so an unset-but-defaulted config value still
// reads naturally in a sentence.
func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// newPrivacyCmd builds the production `observer privacy` command.
func newPrivacyCmd() *cobra.Command {
	return newPrivacyCmdWith(defaultPrivacyDeps())
}

// newPrivacyCmdWith builds `observer privacy` against an injected deps
// seam — the constructor cmd/observer/privacy_test.go uses so every test
// drives a fixed config.Config instead of the operator's real one.
func newPrivacyCmdWith(deps privacyDeps) *cobra.Command {
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "privacy",
		Short: "Print an honest, config-derived report of every listening socket and outbound network path this binary has",
		Long: `observer privacy inspects the loaded config and prints exactly what network
surface this binary presents: every socket it can listen on, and every
outbound call it can make, each with the condition that has to be true
before it fires.

This command makes no network calls itself and reads no external state
beyond your config file - it's a report on what the binary CAN do given
its current configuration, not a live traffic capture.

Your session content (prompts, code, responses, file contents) never leaves
this machine on this product's behalf without your explicit consent. Two
automatic background requests run on a default install, and neither carries
any of your data: the pricing feed fetch of the public model price table
(once at daemon start, then daily; standalone nodes only - see the "pricing
feed" row) and the TLS pre-warm HEAD requests the proxy fires at startup
against [proxy].prewarm_targets (see the "TLS pre-warm" row). Every other
outbound row below is either forwarding a request your own AI tool already
made, or something you explicitly configured, consented to, or clicked.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := deps.loadConfig()
			if err != nil {
				return fmt.Errorf("observer privacy: loading config: %w", err)
			}
			report := buildPrivacyReport(cfg)
			if jsonOut {
				return writePrivacyJSON(cmd.OutOrStdout(), report)
			}
			writePrivacyText(cmd.OutOrStdout(), report)
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit a machine-readable JSON report instead of plain text")

	return cmd
}

// writePrivacyJSON writes report as an indented JSON document.
func writePrivacyJSON(w io.Writer, report privacyReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("observer privacy: encoding json: %w", err)
	}
	return nil
}

// writePrivacyText renders report as a plain-text, gh-style inspection
// report.
func writePrivacyText(w io.Writer, report privacyReport) {
	fmt.Fprintln(w, "Listening sockets")
	fmt.Fprintln(w, "------------------")
	for _, s := range report.Sockets {
		fmt.Fprintf(w, "  %-18s %-38s %-9s %s\n", s.Name, s.Addr, activeLabel(s.Active), s.Purpose)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Outbound network paths")
	fmt.Fprintln(w, "-----------------------")
	for _, e := range report.Egress {
		fmt.Fprintf(w, "  %-30s %s\n", e.Name, activeLabel(e.Active))
		fmt.Fprintf(w, "    gate:   %s\n", e.Gate)
		fmt.Fprintf(w, "    detail: %s\n", e.Detail)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Two automatic calls run by default, neither carrying session data: the")
	fmt.Fprintln(w, "pricing feed fetch and the TLS pre-warm HEAD requests above. Everything")
	fmt.Fprintln(w, "else needs an explicit opt-in or your own tool's request.")
	fmt.Fprintf(w, "Full detail: %s\n", report.DocsURL)
}

// activeLabel renders active as a fixed-width, glanceable status word.
func activeLabel(active bool) string {
	if active {
		return "[on]"
	}
	return "[off]"
}
