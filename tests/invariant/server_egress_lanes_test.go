package invariant

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secfeed/online"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvshard/shardnet"
)

// server_egress_lanes_test.go is the ONE owner of the org server's
// declared-egress lane list (security plan 8.3 "Where the relay code lives",
// roadmap section 11 item 6, ledger rows SHR-3 and SECP-26 in
// docs/security.md). The node list (egress_lanes_test.go) walks
// ./cmd/observer only; SHR-3 records that the org server's own egress was
// outside it and needed its own statement before the security relay, the
// server's first outbound LOOKUP lane, could ship. This is that statement:
// the same shape and the same checks over ./cmd/observer-org, reusing the
// node list's network-import table and dial-symbol scan.
//
//   - TestServerEgressLanesDeclared: every module package in the server
//     closure (linux, windows, darwin) that DIRECTLY imports a network
//     package has a row here.
//   - TestServerEgressLanesNotStale: every row is still in the closure and
//     still imports a network package.
//   - TestServerEgressLaneKindsHonest: a listen-only or address-only row
//     references no outbound dial symbol.
//   - TestServerEgressLaneTableWellFormed: ids and packages unique, every
//     dialing row names what it reaches, its triggers and its gate.
//   - TestServerSecurityRelayHostsExact: the org.security.relay row names
//     exactly the hosts the relay's client allows (internal/secfeed/online),
//     so the declared hosts cannot drift from the code.
//
// The org server is a network service: it listens on its own ports and it
// already reached admin-configured endpoints (identity providers, vendor
// APIs, webhooks, object stores, model providers) before this list existed.
// Each of those lanes is written down honestly from day one; none of them
// was added or widened by the lane that wrote this file. The same limits
// as the node list apply: the check is on direct imports, so a package that
// reaches the network only by calling a lane is composition and that lane's
// gate governs it, and cmd/observer-org is one blanket row held to its
// Reaches by review.

// serverEgressTrigger is what starts a server lane's network use.
type serverEgressTrigger string

const (
	srvTrigBackground serverEgressTrigger = "background loop"
	srvTrigAdmin      serverEgressTrigger = "admin action"
	srvTrigOperator   serverEgressTrigger = "operator command"
	srvTrigNode       serverEgressTrigger = "node request"
	srvTrigGateway    serverEgressTrigger = "gateway traffic"
	srvTrigSignIn     serverEgressTrigger = "sign-in"
	srvTrigCI         serverEgressTrigger = "CI request"
)

// serverEgressLane is one declared server lane.
type serverEgressLane struct {
	ID       string
	Pkg      string
	Kind     egressKind
	Reaches  string
	Triggers []serverEgressTrigger
	Gate     string
}

// serverEgressLanes is the org server's declared-egress lane list. Order:
// remote, local, listen-only, address-only.
var serverEgressLanes = []serverEgressLane{
	// --- remote: may leave the machine ------------------------------------
	{
		ID: "org.security.relay", Pkg: "internal/secfeed/online", Kind: egressRemote,
		Reaches:  "api.osv.dev, crates.io, proxy.golang.org, pypi.org, registry.npmjs.org, api.nuget.org, rubygems.org, repo.packagist.org, superbased.app (HTTPS, exact host allow-list, no redirects, capped answers; ecosystem, public package name and version only, with the server's IP and a User-Agent of superbased-observer)",
		Triggers: []serverEgressTrigger{srvTrigNode, srvTrigOperator, srvTrigBackground},
		Gate:     "component org.security.relay ([security.relay].enabled, off until configured) with the relay mode set to relay by the org's super admin; queries only for a managed enrolment's lookup cache miss, public names only (private names refused at the server too); `observer-org security mirror sync` fetches the vendor's signed content from superbased.app when the operator runs it, and the leader's scheduled mirror sync does the same only when [security.relay].mirror_sync_interval is set (default off, at least 1h); no relayed lookup in mirror mode",
	},
	{
		ID: "org.security.shards", Pkg: "internal/secscan/osvshard/shardnet", Kind: egressRemote,
		Reaches:  "shards.superbased.app only (HTTPS, exact host, no redirects, every body capped at the size the verified descriptor or index file lists): GETs of <Set>/index/<sha256>.json and <Set>/obj/<sha256>.json.gz, the SuperBased package lookup's advisory shards, which the org mirror stores for its managed nodes (lane RM-3); the paths are the digests the vendor-signed security.osv_shards descriptors pin, the same for every org, so nothing about a node, a project or a package is sent; User-Agent superbased-observer",
		Triggers: []serverEgressTrigger{srvTrigOperator, srvTrigBackground},
		Gate:     "component org.security.relay ([security.relay].enabled, off until configured); `observer-org security mirror shards sync` when the operator runs it, and the leader's scheduled mirror sync only with [security.relay].mirror_sync_interval set AND [security.relay].mirror_shards = true (both default off); only objects the mirror does not already hold verified; an air-gapped org uses `observer-org security mirror shards import <dir>` and this lane sends nothing. Never on a node request: a managed node's shard fetch is served from the mirror, never relayed",
	},
	{
		ID: "org.updates", Pkg: "internal/orgserver/updateartifact", Kind: egressRemote,
		Reaches:  "the vendor's release host for `observer-org update sync` (signed release manifests and archives)",
		Triggers: []serverEgressTrigger{srvTrigOperator},
		Gate:     "the operator runs `observer-org update sync`; never scheduled",
	},
	{
		ID: "org.pricing.feed", Pkg: "internal/orgserver/pricingfeed", Kind: egressRemote,
		Reaches:  "the public pricing feed (superbased.app)",
		Triggers: []serverEgressTrigger{srvTrigBackground, srvTrigAdmin},
		Gate:     "component org.pricing-feed ([pricing_feed].enabled)",
	},
	{
		ID: "org.auth", Pkg: "internal/orgserver/auth", Kind: egressRemote,
		Reaches:  "the configured OIDC issuer (discovery, JWKS, token exchange) and SAML IdP metadata URL",
		Triggers: []serverEgressTrigger{srvTrigSignIn, srvTrigBackground},
		Gate:     "an OIDC or SAML rail configured by an admin",
	},
	{
		ID: "org.pollers.cc", Pkg: "internal/orgserver/ccanalytics", Kind: egressRemote,
		Reaches:  "the Claude Code Analytics API",
		Triggers: []serverEgressTrigger{srvTrigBackground},
		Gate:     "component org.pollers.cc with an admin-configured connection",
	},
	{
		ID: "org.pollers.codex", Pkg: "internal/orgserver/codexanalytics", Kind: egressRemote,
		Reaches:  "the OpenAI Codex org analytics surfaces",
		Triggers: []serverEgressTrigger{srvTrigBackground},
		Gate:     "component org.pollers.codex with an admin-configured connection",
	},
	{
		ID: "org.pollers.copilot", Pkg: "internal/orgserver/copilotanalytics", Kind: egressRemote,
		Reaches:  "the GitHub Copilot engagement, seats and billing APIs",
		Triggers: []serverEgressTrigger{srvTrigBackground},
		Gate:     "component org.pollers.copilot with an admin-configured connection",
	},
	{
		ID: "org.pollers.cortex", Pkg: "internal/orgserver/cortexanalytics", Kind: egressRemote,
		Reaches:  "the customer's Snowflake SQL API (CORTEX_CODE_*_USAGE_HISTORY views, key-pair JWT)",
		Triggers: []serverEgressTrigger{srvTrigBackground},
		Gate:     "[cortex_analytics] enabled with an admin-configured key pair (off by default)",
	},
	{
		ID: "org.pollers.cursor", Pkg: "internal/orgserver/cursoradminpoll", Kind: egressRemote,
		Reaches:  "the Cursor admin API",
		Triggers: []serverEgressTrigger{srvTrigBackground},
		Gate:     "component org.pollers.cursor with an admin-configured connection",
	},
	{
		ID: "org.pollers.kimchi", Pkg: "internal/orgserver/kimchianalytics", Kind: egressRemote,
		Reaches:  "the Cast AI billing model usage report (api.cast.ai or api.eu.cast.ai)",
		Triggers: []serverEgressTrigger{srvTrigBackground},
		Gate:     "[kimchi_analytics] enabled with an admin-configured API key (off by default)",
	},
	{
		ID: "org.pollers.m365", Pkg: "internal/orgserver/m365copilotanalytics", Kind: egressRemote,
		Reaches:  "Microsoft Graph and Entra (Microsoft 365 Copilot usage)",
		Triggers: []serverEgressTrigger{srvTrigBackground},
		Gate:     "component org.pollers.m365 with an admin-configured Entra app",
	},
	{
		ID: "org.vendor.egress", Pkg: "internal/orgserver/vendorconn/egress", Kind: egressRemote,
		Reaches:  "vendor enterprise APIs of admin-configured vendor connections, through an SSRF-safe dialer",
		Triggers: []serverEgressTrigger{srvTrigBackground, srvTrigAdmin},
		Gate:     "an admin-configured vendor connection",
	},
	{
		ID: "org.llm", Pkg: "internal/orgserver/llmprovider", Kind: egressRemote,
		Reaches:  "the admin-configured model providers (assistant, judges, intelligence jobs)",
		Triggers: []serverEgressTrigger{srvTrigAdmin, srvTrigBackground},
		Gate:     "a model provider configured by an admin",
	},
	{
		ID: "org.llmwire", Pkg: "internal/llmwire", Kind: egressRemote,
		Reaches:  "the OpenAI-compatible model endpoints its callers name (the org.llm providers and the bridge agent), through the caller's netguard client",
		Triggers: []serverEgressTrigger{srvTrigAdmin, srvTrigBackground},
		Gate:     "a caller lane's configured provider (each caller's own row states its gate); the package builds no HTTP client and dials nothing on its own (E1.1c)",
	},
	{
		ID: "org.harness", Pkg: "internal/orgserver/harness", Kind: egressRemote,
		Reaches:  "the configured harness gateway (insight agents)",
		Triggers: []serverEgressTrigger{srvTrigAdmin, srvTrigBackground},
		Gate:     "a harness endpoint configured ([intelligence] harness settings)",
	},
	{
		ID: "org.mcp.registry", Pkg: "internal/orgserver/mcpregistry", Kind: egressRemote,
		Reaches:  "admin-registered MCP registries",
		Triggers: []serverEgressTrigger{srvTrigBackground},
		Gate:     "component org.agentaccess with a registry registered by an admin",
	},
	{
		ID: "org.obs.alerts", Pkg: "internal/orgserver/obsalert", Kind: egressRemote,
		Reaches:  "admin-configured alert webhooks, the Slack incoming webhook a rule names (hooks.slack.com / hooks.slack-gov.com only, sealed in org_secret, never logged; Plane A W3-5), and the PagerDuty Events API v2 (events.pagerduty.com/v2/enqueue only, the rule's routing key sealed in org_secret, never logged; Plane A W5-5)",
		Triggers: []serverEgressTrigger{srvTrigBackground},
		Gate:     "an alert rule with a webhook, a Slack webhook or a PagerDuty routing key configured by an admin",
	},
	{
		ID: "org.budget.delivery", Pkg: "internal/orgserver/budget", Kind: egressRemote,
		Reaches:  "admin-configured budget alert webhooks",
		Triggers: []serverEgressTrigger{srvTrigBackground},
		Gate:     "a budget alert webhook configured by an admin",
	},
	{
		ID: "org.security.githubapp", Pkg: "internal/orgserver/secghapp/ghapi", Kind: egressRemote,
		Reaches:  "api.github.com (HTTPS, no redirects, capped answers): mint an installation token with the App's JWT, list the installation's repositories, and post one commit status under the superbased/security context; for a pull_request run's upload, a read token narrowed to contents and pull_requests read on that one repository, the merge commit's parents (git data API) and the pull request's head; and token.actions.githubusercontent.com for its published OIDC key set only (GET /.well-known/jwks, cached an hour, refetched at most once a minute), to check the CI result upload's GitHub Actions token",
		Triggers: []serverEgressTrigger{srvTrigBackground, srvTrigCI},
		Gate:     "component org.security.githubapp ([security.githubapp].enabled, off by default) with an App connection one admin requested and a second admin approved; one status per commit and state, never for a repository the installation does not cover",
	},
	{
		ID: "org.agentaccess.wire", Pkg: "internal/orgserver/agentaccesswire", Kind: egressRemote,
		Reaches:  "the observer-mcpgw companions' health and key endpoints",
		Triggers: []serverEgressTrigger{srvTrigBackground},
		Gate:     "component org.agentaccess ([agent_access].enabled)",
	},
	{
		ID: "org.mcpgw.http", Pkg: "internal/mcpgw/gwhttp", Kind: egressRemote,
		Reaches:  "admin-registered MCP servers' OAuth discovery and token endpoints",
		Triggers: []serverEgressTrigger{srvTrigAdmin, srvTrigGateway},
		Gate:     "component org.agentaccess",
	},
	{
		ID: "org.mcpgw.sts", Pkg: "internal/mcpgw/stswire", Kind: egressRemote,
		Reaches:  "admin-configured trust issuers' JWKS and hosted key endpoints",
		Triggers: []serverEgressTrigger{srvTrigAdmin, srvTrigGateway},
		Gate:     "component org.agentaccess",
	},
	{
		ID: "org.netguard", Pkg: "internal/netguard", Kind: egressRemote,
		Reaches:  "the customer- or admin-supplied URLs its callers name (alert and budget webhooks, SAML metadata, OIDC discovery, token and JWKS, the vendor analytics pollers, the model providers) through the one SSRF-guarded client (MS-R-001): never cloud metadata, link-local, multicast or unspecified; loopback and private space only inside [outbound] allow_private_cidrs; bounded redirects re-checked; a target is resolved and checked before it is handed to an environment proxy",
		Triggers: []serverEgressTrigger{srvTrigBackground, srvTrigAdmin, srvTrigSignIn},
		Gate:     "a caller lane's configured URL (each caller's own row states its gate); the package dials nothing on its own",
	},
	{
		ID: "org.mcp.egress", Pkg: "internal/mcpegress", Kind: egressRemote,
		Reaches:  "admin-supplied MCP upstream URLs, through an SSRF-safe dialer",
		Triggers: []serverEgressTrigger{srvTrigGateway},
		Gate:     "component org.agentaccess",
	},
	{
		ID: "org.agentid.keys", Pkg: "internal/agentid/keyprovider", Kind: egressRemote,
		Reaches:  "Azure Key Vault and the managed identity endpoint",
		Triggers: []serverEgressTrigger{srvTrigBackground, srvTrigAdmin},
		Gate:     "an Azure Key Vault key provider configured for Agent Access",
	},
	{
		ID: "org.aigateway", Pkg: "internal/aigateway", Kind: egressRemote,
		Reaches:  "model provider APIs for gateway requests",
		Triggers: []serverEgressTrigger{srvTrigGateway},
		Gate:     "component org.aigateway ([aigateway].enabled)",
	},
	{
		ID: "org.aigateway.http", Pkg: "internal/aigateway/gwhttp", Kind: egressRemote,
		Reaches:  "model provider APIs for gateway requests",
		Triggers: []serverEgressTrigger{srvTrigGateway},
		Gate:     "component org.aigateway",
	},
	{
		ID: "org.clickhouse", Pkg: "internal/orgserver/telemetry/clickhouse", Kind: egressRemote,
		Reaches:  "the configured ClickHouse HTTP endpoint",
		Triggers: []serverEgressTrigger{srvTrigBackground},
		Gate:     "ClickHouse configured as the analytics plane",
	},
	{
		ID: "org.object", Pkg: "internal/orgserver/telemetry/object", Kind: egressRemote,
		Reaches:  "the configured S3-compatible or Azure Blob object store",
		Triggers: []serverEgressTrigger{srvTrigBackground},
		Gate:     "OBSERVER_OBJECT_BACKEND set to s3 or azblob",
	},
	{
		ID: "org.log.kafka", Pkg: "internal/telemetrylog/kafkalog", Kind: egressRemote,
		Reaches:  "the configured Kafka brokers",
		Triggers: []serverEgressTrigger{srvTrigBackground},
		Gate:     "[log].engine = kafka",
	},
	{
		ID: "org.log.nats", Pkg: "internal/telemetrylog/natslog", Kind: egressRemote,
		Reaches:  "the embedded or configured NATS server",
		Triggers: []serverEgressTrigger{srvTrigBackground},
		Gate:     "the default log engine",
	},
	{
		ID: "org.email", Pkg: "internal/notify/email", Kind: egressRemote,
		Reaches:  "the configured SMTP server",
		Triggers: []serverEgressTrigger{srvTrigBackground, srvTrigAdmin},
		Gate:     "component org.email ([email].enabled)",
	},
	{
		ID: "org.otel.export", Pkg: "internal/exporter/otel", Kind: egressRemote,
		Reaches:  "the configured OTLP/HTTP endpoint",
		Triggers: []serverEgressTrigger{srvTrigBackground},
		Gate:     "an exporter configured (default off)",
	},
	{
		ID: "org.selfobs", Pkg: "internal/selfobs/emit/otelsink", Kind: egressRemote,
		Reaches:  "the configured self-observability OTLP endpoint",
		Triggers: []serverEgressTrigger{srvTrigBackground},
		Gate:     "component org.selfobs",
	},
	{
		ID: "org.openshell.front", Pkg: "internal/orgserver/openshellfront", Kind: egressRemote,
		Reaches:  "the org's own OpenShell gateway at [openshell].gateway_url (private network, TLS, the optional gateway_tls_spki_sha256 pin, the member gateway token the api role issued) and the api role's internal decision API at api_internal_url (loopback or https with api_internal_ca_file, every request signed by the front service key); it serves the developers' gRPC on front_listen",
		Triggers: []serverEgressTrigger{srvTrigNode},
		Gate:     "component org.openshell with [openshell].enabled, in a process started with --role openshell-front only (never part of all); every forwarded call needs a run token the api role's decide allows",
	},
	{
		ID: "org.openshell.gateway", Pkg: "internal/orgserver/openshellgw/gwclient", Kind: egressRemote,
		Reaches:  "the org's own OpenShell gateway at [openshell].gateway_url (private network, TLS, the optional gateway_tls_spki_sha256 pin); the generated openshellv1 client of the tagged SDK",
		Triggers: []serverEgressTrigger{srvTrigBackground, srvTrigAdmin, srvTrigNode},
		Gate:     "component org.openshell with [openshell].enabled: the worker's sync, reaper, drain and collect (sync admin token), and the front's forwarding (member gateway token)",
	},
	{
		ID: "org.server", Pkg: "internal/orgserver", Kind: egressRemote,
		Reaches:  "the composition layer: its own listeners, admin-supplied endpoints it tests on request (connection tests), and every lane above it composes",
		Triggers: []serverEgressTrigger{srvTrigAdmin, srvTrigBackground, srvTrigNode},
		Gate:     "per call: the admin action or the config section that enables the feature",
	},
	{
		ID: "cmd.observer-org", Pkg: "cmd/observer-org", Kind: egressRemote,
		Reaches:  "the composition layer: its own server's health and loopback probes, the NATS log it starts, and every lane above it composes",
		Triggers: []serverEgressTrigger{srvTrigOperator, srvTrigBackground},
		Gate:     "per call: the operator command or the config section",
	},

	// --- listen-only: serves, never dials ---------------------------------
	{ID: "org.security.relay.http", Pkg: "internal/orgserver/secrelay", Kind: egressListen, Reaches: "POST /api/agent/security/lookup, the agent content and shard routes and the relay admin API (its upstream and its shard source are injected: org.security.relay, org.security.shards)"},
	{ID: "org.security.managed", Pkg: "internal/orgserver/secmanaged", Kind: egressListen, Reaches: "the security managed pull's admin API"},
	{ID: "org.security.manifests", Pkg: "internal/orgserver/secmanifests", Kind: egressListen, Reaches: "the custom driver manifest catalog's admin API"},
	{ID: "org.security.fleet", Pkg: "internal/orgserver/secorg", Kind: egressListen, Reaches: "the security fleet views' admin API (findings, rollup, coverage, exceptions, settings, triage, evidence export)"},
	{ID: "org.sandbox.managed", Pkg: "internal/orgserver/sandboxmanaged", Kind: egressListen, Reaches: "the sandbox managed pull's admin API"},
	{ID: "org.managedpull", Pkg: "internal/orgserver/managedpull", Kind: egressListen, Reaches: "the module managed-pull kit's agent routes"},
	{ID: "org.signininvite.http", Pkg: "internal/orgserver/signininvite/adminhttp", Kind: egressListen, Reaches: "the sign-in invitation admin API (create, list, revoke; inbound only, no outbound call)"},
	{ID: "org.intelplatform.consent.http", Pkg: "internal/orgserver/intelplatform/consentapi", Kind: egressListen, Reaches: "the member's consent at login, GET/PUT/DELETE /api/org/me/intel-consent (plan 07 M9.2; inbound only, no outbound call)"},
	{ID: "org.api", Pkg: "internal/orgserver/api", Kind: egressListen, Reaches: "the agent API handlers"},
	{ID: "org.noderail", Pkg: "internal/orgserver/noderail", Kind: egressListen, Reaches: "the node rail's host-to-org binding middleware on the /api/agent/* routes (inbound only, no outbound call)"},
	{ID: "org.api.gen", Pkg: "internal/orgserver/api/gen", Kind: egressListen, Reaches: "generated agent API handlers"},
	{ID: "org.dashboard", Pkg: "internal/orgserver/dashboard", Kind: egressListen, Reaches: "the admin dashboard API"},
	{ID: "org.dashboard.gen", Pkg: "internal/orgserver/dashboard/gen", Kind: egressListen, Reaches: "generated dashboard API handlers"},
	{ID: "org.dashboard.webapp", Pkg: "internal/orgserver/dashboard/webapp", Kind: egressListen, Reaches: "the embedded web app"},
	{ID: "org.gateway", Pkg: "internal/orgserver/gateway", Kind: egressListen, Reaches: "the Plane A OTLP gateway receivers (POST /v1/{traces,logs,metrics} and /api/public/otel/v1/traces, the Langfuse SDK exporter's traces path, behind the same ingest credential; inbound only)"},
	{ID: "org.runtimesettings.http", Pkg: "internal/orgserver/runtimesettings/settingsapi", Kind: egressListen, Reaches: "GET/PUT /api/org/runtime-settings, the admin runtime-settings API (inbound only, no outbound call)"},
	{ID: "org.sdkapi", Pkg: "internal/orgserver/sdkapi", Kind: egressListen, Reaches: "the versioned /v1/sdk/* control API on the gateway listener (Plane A W1c-5)"},
	{ID: "org.evalroutes", Pkg: "internal/orgserver/evalroutes", Kind: egressListen, Reaches: "the dashboard's Plane A score, online-eval, snapshot and review-queue routes (lane B7)"},
	{ID: "org.crossplaneroutes", Pkg: "internal/orgserver/crossplaneroutes", Kind: egressListen, Reaches: "the cross-plane link's admin reads /api/org/crossplane/services* (Plane A W4-3/W5-8, lane C3; inbound only, no outbound call; reads through the request seam)"},
	{ID: "org.promptstore", Pkg: "internal/orgserver/promptstore", Kind: egressListen, Reaches: "the prompt registry's admin routes /api/org/obs/prompts* and /api/org/obs/prompt-* (W5-3, lane C8) and its SDK fetch handlers (Plane A W3-3, lane B8; inbound only, no outbound call; reads and writes through the request seam)"},
	{ID: "org.obsviews", Pkg: "internal/orgserver/obsviews", Kind: egressListen, Reaches: "the explorer's saved views and live tail routes /api/org/obs/views* and /api/org/obs/live-tail (Plane A W5-4, lane C9; inbound only, no outbound call; reads and writes through the request seam)"},
	{ID: "org.sdkcred", Pkg: "internal/orgserver/sdkcred", Kind: egressListen, Reaches: "a member's own machine minting or revoking its SDK key, POST/DELETE /api/agent/sdk-credential (Plane A W2-7; inbound only, no outbound call)"},
	{ID: "org.machinekey", Pkg: "internal/orgserver/machinekey", Kind: egressListen, Reaches: "machine key routes"},
	{ID: "org.mcpgwadmin", Pkg: "internal/orgserver/mcpgwadmin", Kind: egressListen, Reaches: "Agent Access admin routes"},
	// The org-hosted OpenShell gateway's control half (lane G2): it serves
	// and never dials (the front-to-gateway and sync lanes are lane G3's).
	{ID: "org.openshell.control", Pkg: "internal/orgserver/openshellctl", Kind: egressListen, Reaches: "the org-hosted OpenShell agent routes, the device-approval page and the front's internal decision API on internal_listen"},
	{ID: "org.openshell.admin", Pkg: "internal/orgserver/openshellgw", Kind: egressListen, Reaches: "the org-hosted OpenShell admin routes /api/org/openshell/* and the member's collect fetch (its gateway calls go through org.openshell.gateway)"},
	{ID: "org.openshell.issuer", Pkg: "internal/orgserver/openshellidp", Kind: egressListen, Reaches: "the org-hosted OpenShell issuer's public discovery document and JWKS"},
	{ID: "org.orgmsg", Pkg: "internal/orgserver/orgmsg", Kind: egressListen, Reaches: "messaging routes"},
	{ID: "org.scim", Pkg: "internal/orgserver/scim", Kind: egressListen, Reaches: "SCIM provisioning routes"},
	{ID: "org.tenantroute", Pkg: "internal/orgserver/tenantroute", Kind: egressListen, Reaches: "the pooled host router middleware (inbound only: it reads the request Host and binds the org; its tenant_hosts lookup is SQL)"},
	{ID: "org.signinseam", Pkg: "internal/orgserver/signinseam", Kind: egressListen, Reaches: "the sign-in gates, the session generation source and /auth/logout (inbound only; their reads go through the request seam, SQL)"},
	{ID: "org.authrails", Pkg: "internal/orgserver/authrails", Kind: egressListen, Reaches: "the per-organization sign-in rail dispatch for /saml/*, /auth/oidc/* and /auth/rails (inbound only; the rails it serves are built by the org server, whose SAML metadata and OIDC discovery fetches are the auth package's lanes)"},
	{ID: "org.supportaccess.http", Pkg: "internal/orgserver/supportaccess/supporthttp", Kind: egressListen, Reaches: "the support-access gate, the support sign-in completer and the support grant admin API (inbound only, no outbound call)"},
	{ID: "org.oplog.http", Pkg: "internal/orgserver/oplog/oploghttp", Kind: egressListen, Reaches: "GET /api/org/operator-actions (inbound only, no outbound call)"},
	{ID: "org.planusage.http", Pkg: "internal/orgserver/planusage", Kind: egressListen, Reaches: "GET /api/org/plan-usage (inbound only, no outbound call; reads through the request seam and the quota service's last pass)"},
	{ID: "org.gateway.meterhttp", Pkg: "internal/orgserver/gateway/metering/meterhttp", Kind: egressListen, Reaches: "GET /api/org/gateway/usage (inbound only, no outbound call; reads gateway_usage_monthly and the runtime settings through the request seam; Plane A W1c-3a)"},
	{ID: "org.pairing.http", Pkg: "internal/orgserver/pairingroutes", Kind: egressListen, Reaches: "the install page's pairing-code routes (mint, list, revoke; inbound only, no outbound call)"},
	{ID: "org.recovery.http", Pkg: "internal/orgserver/recovery/recoveryhttp", Kind: egressListen, Reaches: "the recovery-link redemption page and route (GET and POST /auth/recover; inbound only, no outbound call)"},
	{ID: "org.pooledgate", Pkg: "internal/orgserver/pooledgate", Kind: egressListen, Reaches: "the pooled route gate middleware (inbound only: it asks the mux which pattern a request resolves to and refuses the pooled inventory's not-yet-on-seam and refused-in-pooled routes; no outbound call, no SQL)"},
	{ID: "org.hostlisten", Pkg: "internal/orgserver/hostlisten", Kind: egressListen, Reaches: "the pooled host API's own mTLS listener (/platform/v1, [platform.host_api]; inbound only: the control plane calls it, it calls nothing)"},
	{ID: "org.hostapi", Pkg: "internal/orgserver/hostapi", Kind: egressListen, Reaches: "the host API handler (/platform/v1: the signed envelope, nonce, idempotency, audit-before-act), mounted by internal/orgserver/hostlisten; inbound only, no outbound call"},
	{ID: "org.aigateway.providerext", Pkg: "internal/aigateway/providerext", Kind: egressListen, Reaches: "provider request shaping (header types)"},
	{ID: "org.scimpool", Pkg: "internal/orgserver/scimpool", Kind: egressListen, Reaches: "a pooled organization's SCIM 2.0 front and its SCIM token admin routes (mint, list, revoke; inbound only, no outbound call)"},
	{ID: "org.scimroutes", Pkg: "internal/orgserver/scimroutes", Kind: egressListen, Reaches: "the SCIM 2.0 route family's mux patterns (inbound only, no outbound call)"},
	{ID: "org.samlspadmin", Pkg: "internal/orgserver/samlspadmin", Kind: egressListen, Reaches: "a pooled organization's SAML SP key list and rotation, GET /api/org/auth/saml/sp-keys and POST .../rotate (inbound only, no outbound call)"},
	{ID: "org.seamhttp", Pkg: "internal/orgserver/seamhttp", Kind: egressListen, Reaches: "the request seam's HTTP half: serves a family's handler set inside one tenant transaction (inbound only, no outbound call)"},
	{ID: "org.otelroutes", Pkg: "internal/orgserver/otelroutes", Kind: egressListen, Reaches: "the OTel-direct receiver (POST /ingest/otel/v1/{logs,metrics,traces}), the member's telemetry token routes and the org switch (inbound only, no outbound call)"},
	{ID: "org.secseam", Pkg: "internal/orgserver/secseam", Kind: egressListen, Reaches: "the org.security admin routes bound to the request seam on a pooled server (inbound only; the relay and shard fetches stay the org.security.relay and org.security.shards lanes)"},

	// --- address-only: types and parsing, no connection --------------------
	{ID: "org.agentid", Pkg: "internal/agentid", Kind: egressAddress, Reaches: "IP parsing"},
	{ID: "org.config.node", Pkg: "internal/config", Kind: egressAddress, Reaches: "host and port validation"},
	{ID: "org.dataauthority", Pkg: "internal/dataauthority", Kind: egressAddress, Reaches: "IP classification"},
	{ID: "org.mcpgw.truststore", Pkg: "internal/mcpgw/truststore", Kind: egressAddress, Reaches: "address checks"},
	{ID: "org.mcpintel.discover", Pkg: "internal/mcpintel/discover", Kind: egressAddress, Reaches: "endpoint formatting"},
	{ID: "org.netpolicy", Pkg: "internal/netpolicy", Kind: egressAddress, Reaches: "IP classification and dial control"},
	{ID: "org.ipclass", Pkg: "internal/ipclass", Kind: egressAddress, Reaches: "IP classification"},
	{ID: "org.policy", Pkg: "internal/policy", Kind: egressAddress, Reaches: "host and IP parsing for the guard network rules"},
	{ID: "org.agentaccessdiag", Pkg: "internal/orgserver/agentaccessdiag", Kind: egressAddress, Reaches: "address checks"},
	{ID: "org.authcfg", Pkg: "internal/orgserver/authcfg", Kind: egressAddress, Reaches: "address checks"},
	{ID: "org.config", Pkg: "internal/orgserver/config", Kind: egressAddress, Reaches: "host and port validation"},
	{ID: "org.storagecfg", Pkg: "internal/orgserver/storagecfg", Kind: egressAddress, Reaches: "endpoint validation"},
	{ID: "org.sshspec", Pkg: "internal/sshspec", Kind: egressAddress, Reaches: "SSH target parsing"},
	{ID: "org.vendorapi.github", Pkg: "internal/vendorapi/github", Kind: egressAddress, Reaches: "endpoint parsing"},
	{ID: "org.vendorapi.microsoft", Pkg: "internal/vendorapi/microsoft", Kind: egressAddress, Reaches: "endpoint parsing"},
	{ID: "org.vendorsurface", Pkg: "internal/vendorsurface", Kind: egressAddress, Reaches: "endpoint parsing"},
}

var (
	serverClosureMu sync.Mutex
	serverClosures  = map[string]map[string]egressPkgInfo{}
)

// serverClosure returns the module packages of ./cmd/observer-org's
// dependency closure on goos (default tags), cached per GOOS.
func serverClosure(t *testing.T, goos string) map[string]egressPkgInfo {
	t.Helper()
	serverClosureMu.Lock()
	defer serverClosureMu.Unlock()
	if c, ok := serverClosures[goos]; ok {
		return c
	}
	root := repoRoot(t)
	if _, err := os.Stat(filepath.Join(root, "cmd", "observer-org")); err != nil {
		t.Skip("cmd/observer-org is not in this tree")
	}
	cmd := exec.Command("go", "list", "-deps", "-f",
		"{{if not .Standard}}{{.ImportPath}}\t{{.Dir}}\t{{join .GoFiles \",\"}}\t{{join .Imports \",\"}}{{end}}",
		"./cmd/observer-org")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOOS="+goos, "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps ./cmd/observer-org (GOOS=%s) failed: %v\n%s", goos, err, out)
	}
	c := map[string]egressPkgInfo{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 4 || !strings.HasPrefix(f[0], modulePath) {
			continue
		}
		info := egressPkgInfo{Rel: strings.TrimPrefix(f[0], modulePath), Dir: f[1]}
		if f[2] != "" {
			info.Files = strings.Split(f[2], ",")
		}
		if f[3] != "" {
			info.Imports = strings.Split(f[3], ",")
		}
		c[info.Rel] = info
	}
	for _, must := range []string{"cmd/observer-org", "internal/orgserver"} {
		if _, ok := c[must]; !ok {
			t.Fatalf("GOOS=%s: server closure lacks %s; the egress guard would be vacuous", goos, must)
		}
	}
	serverClosures[goos] = c
	return c
}

func serverLaneByPkg() map[string]serverEgressLane {
	m := make(map[string]serverEgressLane, len(serverEgressLanes))
	for _, l := range serverEgressLanes {
		m[l.Pkg] = l
	}
	return m
}

func TestServerEgressLaneTableWellFormed(t *testing.T) {
	ids, pkgs := map[string]bool{}, map[string]bool{}
	for _, l := range serverEgressLanes {
		if l.ID == "" || l.Pkg == "" || l.Reaches == "" {
			t.Errorf("server lane %+v: ID, Pkg and Reaches are required", l)
		}
		if ids[l.ID] || pkgs[l.Pkg] {
			t.Errorf("server lane %q (%s): duplicate id or package", l.ID, l.Pkg)
		}
		ids[l.ID], pkgs[l.Pkg] = true, true
		switch l.Kind {
		case egressRemote, egressLocal:
			if len(l.Triggers) == 0 || l.Gate == "" {
				t.Errorf("server lane %q dials: it must name its triggers and gate", l.ID)
			}
		case egressListen, egressAddress:
			if len(l.Triggers) != 0 || l.Gate != "" {
				t.Errorf("server lane %q opens no connection: triggers and gate belong to dialing lanes only", l.ID)
			}
		default:
			t.Errorf("server lane %q: unknown kind %q", l.ID, l.Kind)
		}
	}
}

func TestServerEgressLanesDeclared(t *testing.T) {
	toolchainTest(t)
	declared := serverLaneByPkg()
	for _, goos := range egressGOOS {
		for rel, info := range serverClosure(t, goos) {
			nets := networkImportsOf(info.Imports)
			if len(nets) == 0 {
				continue
			}
			if _, ok := declared[rel]; !ok {
				t.Errorf("GOOS=%s: %s imports %s but is not a declared org server egress lane. The org server's "+
					"network access happens only through the lanes in tests/invariant/server_egress_lanes_test.go: "+
					"add a row with its kind, what it reaches, its triggers and its gate", goos, rel, strings.Join(nets, ", "))
			}
		}
	}
}

func TestServerEgressLanesNotStale(t *testing.T) {
	toolchainTest(t)
	for _, l := range serverEgressLanes {
		var present, networked bool
		for _, goos := range egressGOOS {
			info, ok := serverClosure(t, goos)[l.Pkg]
			if !ok {
				continue
			}
			present = true
			networked = networked || len(networkImportsOf(info.Imports)) > 0
		}
		switch {
		case !present:
			t.Errorf("server lane %q: %s is not in the org server's closure; delete or move the row", l.ID, l.Pkg)
		case !networked:
			t.Errorf("server lane %q: %s no longer imports a network package; delete the row", l.ID, l.Pkg)
		}
	}
}

func TestServerEgressLaneKindsHonest(t *testing.T) {
	toolchainTest(t)
	declared := serverLaneByPkg()
	for _, goos := range egressGOOS {
		for rel, info := range serverClosure(t, goos) {
			l, ok := declared[rel]
			if !ok || l.Kind.dials() {
				continue
			}
			for _, hit := range dialSymbolUses(t, info) {
				t.Errorf("GOOS=%s: server lane %q is declared %s but %s", goos, l.ID, l.Kind, hit)
			}
		}
	}
}

// TestServerSecurityRelayHostsExact pins the relay row's Reaches to the
// client's real allow-list: every allowed host is named, and the row is
// the only remote lane on that package.
func TestServerSecurityRelayHostsExact(t *testing.T) {
	var row serverEgressLane
	for _, l := range serverEgressLanes {
		if l.ID == "org.security.relay" {
			row = l
		}
	}
	if row.Pkg != "internal/secfeed/online" || row.Kind != egressRemote {
		t.Fatalf("org.security.relay row: %+v", row)
	}
	hosts := online.New(online.Options{}).AllowedHosts()
	sort.Strings(hosts)
	// Set equality both ways (SEC-E4 merge finding 6): the host list that
	// opens Reaches (before its parenthesis) is exactly the client's allow
	// list, so neither a host the client may reach nor one it never uses can
	// be listed wrongly.
	listed := strings.Split(strings.TrimSpace(strings.SplitN(row.Reaches, " (", 2)[0]), ", ")
	sort.Strings(listed)
	if !slices.Equal(listed, hosts) {
		t.Errorf("org.security.relay names the hosts %v, its client allows %v", listed, hosts)
	}
	// One remote row owns the client: a second row on the same package
	// would declare hosts this check never compares.
	n := 0
	for _, l := range serverEgressLanes {
		if l.Pkg == "internal/secfeed/online" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("internal/secfeed/online has %d server egress rows, want exactly the org.security.relay row", n)
	}
	// The relay handler package itself must stay listen-only: its
	// upstream is injected, never built there.
	for _, l := range serverEgressLanes {
		if l.Pkg == "internal/orgserver/secrelay" && l.Kind != egressListen {
			t.Errorf("internal/orgserver/secrelay must be listen-only: %+v", l)
		}
	}
	if !slices.Contains(hosts, online.OSVHost) {
		t.Error("the relay client lost the OSV host")
	}
}

// TestServerSecurityShardsHostsExact: the org.security.shards row names the
// one host the shard client allows (internal/secscan/osvshard/shardnet,
// lane RM-3), and only the server packages that schedule or run the sync
// link it.
func TestServerSecurityShardsHostsExact(t *testing.T) {
	var row serverEgressLane
	for _, l := range serverEgressLanes {
		if l.ID == "org.security.shards" {
			row = l
		}
	}
	if row.Pkg != "internal/secscan/osvshard/shardnet" || row.Kind != egressRemote {
		t.Fatalf("org.security.shards row: %+v", row)
	}
	hosts := shardnet.AllowedHosts()
	if len(hosts) != 1 || !strings.HasPrefix(row.Reaches, hosts[0]+" only") {
		t.Fatalf("org.security.shards names %q, its client allows %v", row.Reaches, hosts)
	}
}
