package components

// catalog_server.go holds the org-side rows (plan section 3.4). In this plan
// the server offers exactly two coarse images, observer-org:<v> (full, as
// today) and observer-org:<v>-core (org.core plus org.oidc, operator ruling
// Q11 accepted under D-374). A server module is L1 only in the sense "absent
// from the core image"; choosing modules individually on the server is L2
// (config and role). Vendor enterprise API sources (org.vendorapi.*) are
// owned by lane ENTAPI and join this table as their own rows.

// img builds an image column set.
func img(full, core ImageDefault) map[Image]ImageDefault {
	return map[Image]ImageDefault{ImageFull: full, ImageCore: core}
}

func serverRows() []Component {
	// Lane MP-ORG (P6): l1Done rows compile out of the core image with their
	// sbo_omit_ tag (package and module absence proved by the invariant
	// tests) and are inert when deselected; l2Done rows are inert when
	// inactive (route guard plus config mask, internal/orgserver
	// server_components.go) but still compiled into the core image.
	l1Done := lv(l1l2l3, l1l2l3, "")
	l2OfL1 := lv(l2l3, l1l2l3, "P6")
	l2Done := lv(l2l3, l2l3, "")
	return []Component{
		{
			ID: "org.core", Class: ClassCore, Binary: BinaryOrg,
			Title:  "Org server core",
			About:  "API, ingest, rollup, retention, RBAC, local auth, the admin dashboard, budgets, pricing, the update mirror, policy rails, SQLite and PostgreSQL, the local object store and the embedded NATS log.",
			Levels: lv(onlyL0, onlyL0, ""),
			DirectModules: []string{
				"github.com/jackc/pgx/v5", "modernc.org/sqlite", "github.com/nats-io/nats-server/v2", "github.com/nats-io/nats.go",
				"github.com/parquet-go/parquet-go", "github.com/BurntSushi/toml", "github.com/spf13/cobra", "github.com/google/uuid",
				"golang.org/x/sys", "golang.org/x/crypto", "golang.org/x/text", "github.com/tailscale/hujson", "gopkg.in/yaml.v3",
				"github.com/oapi-codegen/runtime", "github.com/coder/websocket", "google.golang.org/grpc", "google.golang.org/protobuf",
				"go.opentelemetry.io/proto/otlp",
				// The neutral self-observability model (internal/selfobs/shape
				// builds OTel attribute values) is core (D-436).
				"go.opentelemetry.io/otel",
			},
			Surface:   Surface{Listeners: []Listener{{Proto: "tcp", Addr: ":8443", Auth: "SSO / local sign-in sessions", Trigger: TriggerAutomatic}}},
			Stability: StabilityStable,
			Images:    img(ImageIn, ImageIn),
			Note:      "Embedded NATS is part of org.core: it is the default log engine (Q11).",
		},
		{
			ID: "org.oidc", Class: ClassServer, Binary: BinaryOrg,
			Title:  "OIDC sign-in",
			About:  "Authorization-code plus PKCE sign-in with Entra, Okta, Google or a generic OIDC provider.",
			Levels: l2OfL1, HostedIn: []string{"internal/orgserver/auth"},
			Routes:        []string{"/auth/oidc"},
			DirectModules: []string{"github.com/golang-jwt/jwt/v4"},
			Surface:       Surface{Egress: []Egress{{Host: "<configured OIDC issuer>", Purpose: "Discovery, JWKS and token exchange", Gate: "config", Trigger: TriggerOptIn}}},
			Stability:     StabilityStable,
			Images:        img(ImageIn, ImageIn),
		},
		{
			ID: "org.saml", Class: ClassServer, Binary: BinaryOrg,
			Title:  "SAML sign-in",
			About:  "SAML 2.0 service provider sign-in and single logout.",
			Levels: l1Done, HostedIn: []string{"internal/orgserver/auth"},
			Routes:        []string{"/saml"},
			DirectModules: []string{"github.com/crewjam/saml"},
			Surface:       Surface{Egress: []Egress{{Host: "<configured IdP metadata URL>", Purpose: "IdP metadata", Gate: "config", Trigger: TriggerOptIn}}},
			Stability:     StabilityStable,
			Images:        img(ImageIn, ImageOut),
		},
		{
			ID: "org.scim", Class: ClassServer, Binary: BinaryOrg,
			Title:  "SCIM provisioning",
			About:  "SCIM 2.0 user and group provisioning from the identity provider.",
			Levels: l1Done, Packages: []string{"internal/orgserver/scim"},
			Routes:        []string{"/scim"},
			DirectModules: []string{"github.com/elimity-com/scim", "github.com/scim2/filter-parser/v2", "github.com/jackc/pgx/v5"},
			Stability:     StabilityStable,
			Images:        img(ImageIn, ImageOut),
		},
		{
			ID: "org.log.kafka", Class: ClassServer, Binary: BinaryOrg,
			Title:  "Kafka log engine",
			About:  "Kafka as the durable telemetry log instead of embedded NATS.",
			Levels: l1Done, Packages: []string{"internal/telemetrylog/kafkalog"},
			DirectModules: []string{"github.com/twmb/franz-go", "github.com/twmb/franz-go/pkg/kmsg"},
			Surface:       Surface{Egress: []Egress{{Host: "<configured Kafka brokers>", Purpose: "Telemetry log", Gate: "config", Trigger: TriggerOptIn}}},
			Stability:     StabilityPreview,
			Images:        img(ImageOff, ImageOut),
		},
		{
			ID: "org.sor.s3", Class: ClassServer, Binary: BinaryOrg,
			Title:  "S3-compatible storage",
			About:  "Typed Parquet system of record on S3-compatible object storage.",
			Levels: l1Done, HostedIn: []string{"internal/orgserver/telemetry/object"},
			DirectModules: []string{"github.com/minio/minio-go/v7"},
			Surface:       Surface{Egress: []Egress{{Host: "<configured S3 endpoint>", Purpose: "System of record objects", Gate: "config", Trigger: TriggerOptIn}}},
			Stability:     StabilityStable,
			Images:        img(ImagePerDeploy, ImageOut),
		},
		{
			ID: "org.sor.azblob", Class: ClassServer, Binary: BinaryOrg,
			Title:  "Azure Blob storage",
			About:  "Typed Parquet system of record on Azure Blob Storage.",
			Levels: l1Done, HostedIn: []string{"internal/orgserver/telemetry/object"},
			DirectModules: []string{"github.com/Azure/azure-sdk-for-go/sdk/azcore", "github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"},
			Surface:       Surface{Egress: []Egress{{Host: "<configured storage account>", Purpose: "System of record objects", Gate: "config", Trigger: TriggerOptIn}}},
			Stability:     StabilityStable,
			Images:        img(ImagePerDeploy, ImageOut),
		},
		{
			ID: "org.analytics.clickhouse", Class: ClassServer, Binary: BinaryOrg,
			Title: "ClickHouse analytics",
			About: "Optional analytics plane fed from the system of record, over plain HTTP.",
			// L2 (T-686): inactive, the ClickHouse consumer worker is not
			// built, the telemetry bundle and the setup probe never dial it.
			Levels:    l2Done,
			Packages:  []string{"internal/orgserver/telemetry/clickhouse", "internal/orgserver/consumers/clickhouseworker"},
			Surface:   Surface{Egress: []Egress{{Host: "<configured ClickHouse>", Purpose: "Analytics writes and queries", Gate: "config", Trigger: TriggerOptIn}}},
			Stability: StabilityPreview,
			Images:    img(ImageOff, ImageOut),
		},
		{
			ID: "org.opamp", Class: ClassServer, Binary: BinaryOrg,
			Title:  "OpAMP collector management",
			About:  "Manages OpenTelemetry collectors over OpAMP.",
			Levels: l1Done, Packages: []string{"internal/orgserver/opamp"},
			Routes:        []string{"/api/org/opamp", "/v1/opamp"},
			DirectModules: []string{"github.com/open-telemetry/opamp-go", "google.golang.org/protobuf", "github.com/google/uuid"},
			Stability:     StabilityPreview,
			Images:        img(ImageIn, ImageOut),
		},
		{
			ID: "org.planea.gateway", Class: ClassServer, Binary: BinaryOrg,
			Title:  "Plane A OTLP gateway",
			About:  "OTLP gRPC and HTTP ingest for hosted AI apps, with classification and the span convention.",
			Levels: l1Done,
			Routes: []string{"/api/org/gateway"},
			Packages: []string{
				"internal/orgserver/gateway", "internal/orgserver/gateway/convention",
				"internal/orgserver/consumers/otlpapplier",
			},
			DirectModules: []string{"google.golang.org/grpc", "google.golang.org/protobuf", "go.opentelemetry.io/proto/otlp"},
			Surface:       Surface{Listeners: []Listener{{Proto: "tcp", Addr: ":4317", Auth: "machine identity credential", Trigger: TriggerOptIn}}},
			Stability:     StabilityPreview,
			Images:        img(ImageIn, ImageOut),
			Note:          "Compiled out by -tags sbo_omit_org_planea_gateway (lane MP-L1F): the wiring pairs server_gateway.go, clickhouseworker codec_otlp.go and recovery apply_otlp.go link their _off.go files, leaving the gateway, its span convention and the OTLP applier consumer out. Two packages it once listed are core: internal/orgserver/collector publishes node pushes as well as OTLP batches onto the durable log, and internal/orgserver/gateway/classify is the pure content classifier the insight runtime also uses. Without it the ClickHouse worker parks every OTLP record and a log replay stops at the first OTLP record.",
		},
		{
			ID: "org.aigateway", Class: ClassServer, Binary: BinaryOrg,
			Title: "AI gateway",
			About: "The org AI gateway with budget reservations and the rate card, in process or as the observer-aigateway image.",
			// L1 (lane MP-L1G, ruling D-504): -tags sbo_omit_org_aigateway
			// leaves out the serving gateway, its admin routes and runtime and
			// the Plane B admission wiring. The budget and rate-card projections
			// (internal/orgserver/gwprojection), the rate card types
			// (internal/aigateway/gwcore) and the gw_rate_card writer
			// (gwcore/ratecardstore) are core: budgets, pricing and access
			// grants own them.
			Levels: l1Done,
			Routes: []string{"/api/org/ai-gateway"},
			Packages: []string{
				"internal/aigateway", "internal/aigateway/providerext", "internal/aigateway/gwhttp", "internal/aigateway/gwstore",
				"internal/orgserver/gwadmin", "internal/orgserver/gwmembers", "internal/orgserver/gwreconcile",
				"internal/orgserver/planebadmit",
			},
			DirectModules: []string{"github.com/google/uuid"},
			Surface:       Surface{Egress: []Egress{{Host: "<model provider APIs>", Purpose: "Forwards gateway requests", Gate: "config", Trigger: TriggerOptIn}}},
			Stability:     StabilityPreview,
			Images:        img(ImageOff, ImageOut),
			Note:          "Compiled out by -tags sbo_omit_org_aigateway (lane MP-L1G). Without it the budget caps and the rate card are still projected into gw_budget_cap and gw_rate_card (a standalone observer-aigateway reads them), the assistant's gateway tools refuse with the state, and a break-glass approval fails loudly because there is no upstream registry to seal from.",
		},
		{
			ID: "org.agentaccess", Class: ClassServer, Binary: BinaryOrg,
			Title: "Agent Access",
			About: "The control half of agent identity and the governed MCP gateway: admin, STS client, vault and audit. The data plane ships as the observer-mcpgw image.",
			// L1 (lanes MP-L1F, MP-L1G): -tags sbo_omit_org_agentaccess links
			// the _off.go halves of the wiring pairs (server boot and routes,
			// push MCP discovery, the relay ingest, the cmd verbs) and leaves
			// the tools.mcp_access compiler unregistered (policyfam's linked
			// family seam). The strict-class vocabulary the config validates
			// is core (internal/mcpaccess/strictvocab).
			Levels: l1Done,
			Routes: []string{"/api/org/agent-access", "/api/agent/agent-access", "/oauth2/authorize", "/oauth2/consent", "/connect"},
			Packages: []string{
				"internal/mcpgw/vault", "internal/mcpgw/vaultstore", "internal/mcpgw/audit", "internal/mcpgw/auditlease",
				"internal/mcpgw/sts", "internal/mcpgw/pdp", "internal/mcpgw/mcpgwstore", "internal/mcpgw/auditwriter",
				"internal/mcpgw/regstore", "internal/mcpgw/truststore", "internal/mcpgw/approvalstore", "internal/mcpgw/gwhttp",
				"internal/mcpgw/oauthstore", "internal/mcpgw/stswire", "internal/orgserver/agentaccesspurge",
				"internal/orgserver/agentaccessalert", "internal/orgserver/agentaccessdiag", "internal/orgserver/agentaccesswire",
				"internal/orgserver/agentaccessreapply", "internal/orgserver/mcpgwadmin", "internal/orgserver/mcpregistry",
				"internal/mcpaccess", "internal/policyfam/mcpaccess", "internal/agentid/idstore", "internal/agentid/keyprovider",
			},
			// The audit writer's OTLP span sink (otlp_sdk.go) is built only by
			// observer-mcpgw; in observer-org the writer needs no exporter, so
			// org.selfobs is no longer required compiled (lane MP-L1F).
			DirectModules: []string{"cel.dev/cel-go", "go.opentelemetry.io/otel", "go.opentelemetry.io/otel/sdk", "go.opentelemetry.io/otel/trace", "golang.org/x/crypto", "github.com/google/uuid"},
			Stability:     StabilityPreview,
			Images:        img(ImageOff, ImageOut),
			Note:          "Off by default and inert when off in every deployment shape (docs/agent-access.md). Without it (-tags sbo_omit_org_agentaccess) a node push is still accepted by member key: its MCP relay rows are dropped with a counted, logged reason, never a 400 (ruling D-504), and a tools.mcp_access policy publish is refused because its compiler is not in the image.",
		},
		{
			// Security pillar Phase E (security plan 4.2, lane SEC-E): "off
			// until configured". E1 builds the server half of the
			// security.scanning family compiler (its pair file
			// internal/policyfam/family_securityscanning.go) and the
			// GET /api/agent/security managed pull's body provider and admin
			// API, mounted only while [security].enabled. Ingest, fleet views,
			// alerts and exports join in the later E lanes.
			ID: "org.security", Class: ClassServer, Binary: BinaryOrg,
			Title:     "Code security (org)",
			About:     "The org half of the Code security module: the security.scanning floors family and the enforce.security managed pull that switches security parts on for managed nodes.",
			Levels:    l1Done,
			Routes:    []string{"/api/org/security/managed", "/api/org/security/manifests", "/api/org/security/findings", "/api/org/security/rollup", "/api/org/security/coverage", "/api/org/security/exceptions", "/api/org/security/settings", "/api/org/security/export"},
			Packages:  []string{"internal/orgserver/secmanaged", "internal/orgserver/secmanifests", "internal/policyfam/securityscanning", "internal/orgserver/secorg"},
			Ledger:    []string{"SECP-10"},
			Stability: StabilityPreview,
			Images:    img(ImageOff, ImageOut),
			Note:      "Off by default ([security].enabled in the server config). Without it, or in an image built with -tags sbo_omit_org_security, GET /api/agent/security answers the managed-pull kit's 404 not_supported (a node keeps its own values and never clears on it) and a security.scanning publish is refused because its compiler is not in the image.",
		},
		{
			// Security pillar Phase E (security plan 4.2 and 8.3, lane
			// SEC-E4): "off until configured", the org server's first
			// outbound lookup lane. [security.relay].enabled mounts
			// POST /api/agent/security/lookup, the agent content route
			// /api/agent/security/content/ and the admin API
			// /api/org/security/relay; the org's super admin then picks the
			// mode (off, relay or mirror). Its declared egress is the server
			// lane org.security.relay (tests/invariant/server_egress_lanes_test.go):
			// the exact hosts of internal/secfeed/online, only in relay mode
			// and for `observer-org security mirror sync`.
			ID: "org.security.relay", Class: ClassServer, Binary: BinaryOrg,
			Title:         "Code security relay and mirror",
			About:         "Answers managed nodes' online package checks (relay mode, querying the public sources on their behalf) or from the org's imported mirror (mirror mode, air-gapped), and serves the mirrored security content.",
			Levels:        l1Done,
			Routes:        []string{"/api/agent/security/lookup", "/api/agent/security/content", "/api/org/security/relay"},
			Packages:      []string{"internal/orgserver/secrelay", "internal/secfeed", "internal/secfeed/online"},
			DirectModules: []string{"golang.org/x/mod", "github.com/BurntSushi/toml", "gopkg.in/yaml.v3"},
			Requires:      []string{"org.security"},
			Surface:       Surface{Egress: []Egress{{Host: "api.osv.dev, the public package registries, superbased.app", Purpose: "Relayed package checks and mirror sync", Gate: "config", Trigger: TriggerOptIn}}},
			Ledger:        []string{"SECP-26"},
			Stability:     StabilityPreview,
			Images:        img(ImageOff, ImageOut),
			Note:          "Off by default ([security.relay].enabled in the server config, then a relay mode chosen by the super admin). Without it, or in an image built with -tags sbo_omit_org_security_relay, the lookup and content routes answer 404 not_supported and a managed node keeps showing online_unknown or not scanned, never a public fallback (X19).",
		},
		{
			// Security pillar Phase F2 (security plan 4.2, 7.9 F2 and 7.10,
			// lane SEC-F2B): "off until configured". [security.ci].enabled
			// (with [security].enabled) mounts the node key enrolment route
			// POST /api/agent/security/change-key, the two CI routes behind a
			// CI credential (an ingest credential of the Plane A machine
			// identity tables scoped to ci:verify) and the admin API of the
			// web2 Change records page, and hands secorg the ingest step that
			// countersigns each change record and keeps the replay store. No
			// egress: the CI job fetches from the server, the server reaches
			// nothing.
			ID: "org.security.ci", Class: ClassServer, Binary: BinaryOrg,
			Title:     "Code security CI check and change records",
			About:     "Certifies managed nodes' change-record keys, countersigns each AI change record the org receives, keeps the replay store and the revocation list, and serves the signed CI policy, the change record lookup and pinned drivers from the security mirror to a CI job holding a CI credential.",
			Levels:    l1Done,
			Routes:    []string{"/api/agent/security/change-key", "/api/ci/security/policy", "/api/ci/security/change-records", "/api/ci/security/content", "/api/org/security/change-records", "/api/org/security/change-keys", "/api/org/security/ci"},
			Packages:  []string{"internal/orgserver/secci"},
			Requires:  []string{"org.security"},
			Ledger:    []string{"SECP-31", "SECP-32"},
			Stability: StabilityPreview,
			Images:    img(ImageOff, ImageOut),
			Note:      "Off by default ([security.ci].enabled in the server config, with [security].enabled). Without it, or in an image built with -tags sbo_omit_org_security_ci, the enrolment and CI routes answer 404 not_supported, web2's Change records page says the check is off (and is hidden from the sidebar in an image without the component) and change records are stored exactly as before (no countersign, no replay store).",
		},
		{
			// Lane GATES-SEC (security plan 4.2 and 7.9 "Later (Q16)", gap
			// G5, operator ruling P-129): the org's own GitHub App, posting a
			// superbased/security commit status from the uploaded CI results.
			// It only adds a check: no other check, status, branch protection
			// or ruleset is touched. Off until [security.githubapp].enabled
			// (with [security].enabled and [security.ci].enabled), and posts
			// nothing until a second, different admin approved its connection.
			ID: "org.security.githubapp", Class: ClassServer, Binary: BinaryOrg,
			Title:    "GitHub App commit status",
			About:    "Takes the CI verify results the workflow's separate upload job sends under the CI credential and a GitHub Actions OIDC token of the policy repository's workflow (the token binds the repository, the commit and the run attempt) and, through the org's own GitHub App (four-eyes approved), posts one superbased/security commit status per result: pass success, fail failure, no verdict error. Polls the result table; no webhook receiver.",
			Levels:   l1Done,
			Routes:   []string{"/api/ci/security/results", "/api/org/security/githubapp"},
			Packages: []string{"internal/orgserver/secghapp", "internal/orgserver/secghapp/ghapi"},
			Requires: []string{"org.security.ci"},
			Surface: Surface{Egress: []Egress{{
				Host: "api.github.com", Purpose: "mint an installation token, list the installation's repositories and post the superbased/security commit status",
				Gate: "config: [security.githubapp].enabled, and a connection two different admins approved", Trigger: TriggerOptIn,
			}, {
				Host: "token.actions.githubusercontent.com", Purpose: "read GitHub Actions' published OIDC key set (cached an hour) to check a CI result upload's token",
				Gate: "config: [security.githubapp].enabled, on a CI result upload", Trigger: TriggerOptIn,
			}}},
			Ledger:    []string{"SECP-35"},
			Stability: StabilityPreview,
			Images:    img(ImageOff, ImageOut),
			Note:      "Off by default ([security.githubapp].enabled, with [security].enabled and [security.ci].enabled). Without it, or in an image built with -tags sbo_omit_org_security_githubapp, the result upload and the App routes answer 404 not_supported and nothing reaches GitHub.",
		},
		{
			ID: "org.assistant", Class: ClassServer, Binary: BinaryOrg,
			Title:         "Admin assistant",
			About:         "The admin chat assistant, its closed tool table and judge warm-up, calling a configured model provider.",
			Levels:        l2Done,
			Routes:        []string{"/api/org/chat"},
			Packages:      []string{"internal/orgserver/chat", "internal/orgserver/judgewarm"},
			DirectModules: []string{"github.com/google/uuid"},
			Surface:       Surface{Egress: []Egress{{Host: "<configured model provider>", Purpose: "Assistant completions", Gate: "config", Trigger: TriggerOptIn}}},
			Stability:     StabilityPreview,
			Images:        img(ImageIn, ImageOut),
		},
		{
			ID: "org.harness", Class: ClassServer, Binary: BinaryHarness,
			Title:     "Insight harness",
			About:     "External insight agents run by the separate harness-gateway image.",
			Levels:    lv(noLevels(), []Level{L1}, "P6"),
			Stability: StabilityPreview,
			Images:    img(ImageSeparate, ImageOut),
		},
		pollerRow("org.pollers.cc", "Claude Code analytics poller", "Polls the Claude Code Analytics API for org usage.", "internal/orgserver/ccanalytics"),
		pollerRow("org.pollers.codex", "Codex analytics poller", "Polls the OpenAI Codex org analytics surfaces.", "internal/orgserver/codexanalytics"),
		pollerRow("org.pollers.cursor", "Cursor admin poller", "Polls the Cursor admin API.", "internal/orgserver/cursoradminpoll", "internal/orgserver/cursoradmin"),
		pollerRow("org.pollers.copilot", "Copilot analytics poller", "Polls GitHub Copilot engagement, seats and billing.", "internal/orgserver/copilotanalytics"),
		pollerRow("org.pollers.m365", "M365 Copilot analytics poller", "Polls Microsoft 365 Copilot usage through an Entra app.", "internal/orgserver/m365copilotanalytics"),
		pollerRow("org.pollers.cortex", "Snowflake Cortex Code usage poller", "Reads the Cortex Code usage views in the customer's Snowflake account over the SQL API.", "internal/orgserver/cortexanalytics"),
		pollerRow("org.pollers.kimchi", "Cast AI usage poller (Kimchi)", "Polls the Cast AI billing model usage report (org-wide, Kimchi among it).", "internal/orgserver/kimchianalytics"),
		{
			ID: "org.email", Class: ClassServer, Binary: BinaryOrg,
			Title: "Org email",
			About: "Sends org notification email over a configured SMTP server.",
			// L2 (T-686): the [email] switch is masked off when inactive.
			Levels:    l2Done,
			Packages:  []string{"internal/orgserver/orgnotify"},
			Surface:   Surface{Egress: []Egress{{Host: "<configured SMTP server>", Purpose: "Email delivery", Gate: "config", Trigger: TriggerOptIn}}},
			Stability: StabilityStable,
			Images:    img(ImageOff, ImageOut),
		},
		{
			ID: "org.digest", Class: ClassServer, Binary: BinaryOrg,
			Title: "Org digest",
			About: "The periodic org digest, delivered by org email.",
			// L2 (T-686): the [digest] switch is masked off when inactive.
			Levels:    l2Done,
			Packages:  []string{"internal/orgserver/digest"},
			Requires:  []string{"org.email"},
			Stability: StabilityStable,
			Images:    img(ImageOff, ImageOut),
		},
		{
			ID: "org.pricing-feed", Class: ClassServer, Binary: BinaryOrg,
			Title:     "Org pricing feed",
			About:     "Fetches the model price table from superbased.app for the org's pricing rail.",
			Levels:    l2Done,
			Routes:    []string{"/api/org/pricing/feed"},
			Packages:  []string{"internal/orgserver/pricingfeed"},
			Surface:   Surface{Egress: []Egress{{Host: "superbased.app", Purpose: "Model price table refresh", Gate: "default on", Trigger: TriggerAutomatic}}},
			Stability: StabilityStable,
			Images:    img(ImageIn, ImageOut),
		},
		{
			ID: "org.selfobs", Class: ClassServer, Binary: BinaryOrg,
			Title: "Org self-observability",
			About: "Exports the org server's own telemetry through the OpenTelemetry SDK.",
			// L2 (T-686): inactive, the sink is never wired (no service
			// account, no credential, no export). L1 (lane MP-L1F): -tags
			// sbo_omit_org_selfobs links selfobs_wire_off.go and the audit
			// writer's otlp_sdk_off.go, leaving the sink, the exporter and the
			// OpenTelemetry SDK out.
			Levels: l1Done,
			// The neutral self-observability model (selfobs run, keys, shape)
			// and the emit.Sink contract are core in every binary (D-436); this
			// component is the OTLP/HTTP sink and the exporter it builds.
			Packages: []string{
				"internal/selfobs/emit/otelsink",
				"internal/exporter/otel",
			},
			DirectModules: []string{"go.opentelemetry.io/otel", "go.opentelemetry.io/otel/sdk", "go.opentelemetry.io/otel/trace", "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"},
			Surface:       Surface{Egress: []Egress{{Host: "<configured OTLP endpoint>", Purpose: "Self telemetry", Gate: "config", Trigger: TriggerOptIn}}},
			Stability:     StabilityPreview,
			Images:        img(ImageOff, ImageOut),
		},
		{
			ID: "org.deploy-planner", Class: ClassServer, Binary: BinaryOrg,
			Title: "Deploy planner",
			About: "The deployment catalog, sizing and plan rendering, the deploy bundle export with its chart and infrastructure embeds, and the IaC template route.",
			// L1 (lane MP-L1J, ruling D-513): -tags sbo_omit_org_deploy_planner
			// links cmd/observer-org deploy_off.go (the deploy verb refuses)
			// and internal/orgserver deployment_iac_off.go. L2: inactive, the
			// component guard answers /api/org/deployment/iac. The first-run
			// setup wizard's store (internal/orgserver/deploywizard) and its
			// templates (internal/orgserver/setuptemplates) are core, and so is
			// the agentgateway pin (internal/orgserver/agwpin).
			Levels: l1Done,
			Routes: []string{"/api/org/deployment/iac"},
			Packages: []string{
				"internal/orgserver/deploybundle", "deploy", "deploy/catalog", "deploy/catalog/render", "charts/observer-org",
			},
			Stability: StabilityStable,
			Images:    img(ImageIn, ImageOut),
			Note:      "Compiled out by -tags sbo_omit_org_deploy_planner (lane MP-L1J). Ruling D-513 drew the line: the planner is the topology, sizing and plan-generation half (the deploy export, list, plan and grow verbs, the deployment catalog and its renderer, the bundle builder with the embedded deploy tree and Helm chart, and the IaC template route). The first-run setup wizard (its state store, templates, connectors and the telemetry topology it records) is core and runs in every image. The `deploy` verb is config-free and offline, so switching the module off in [components] gates only the route; the verb leaves with the build tag.",
		},
		{
			ID: "org.managed-settings", Class: ClassServer, Binary: BinaryOrg,
			Title:     "Managed settings generator",
			About:     "Generates vendor managed-settings files, macOS configuration profiles and Windows registry imports that the admin deploys through MDM. Observer applies nothing itself.",
			Levels:    l2Done,
			Routes:    []string{"/api/org/agent-config/mdm"},
			Packages:  []string{"internal/managedsettings"},
			Surface:   Surface{OSIntegration: []string{"generated MDM artifacts (applied by the admin, never by Observer)"}},
			Stability: StabilityStable,
			Images:    img(ImageIn, ImageOut),
		},
		{
			ID: "edge", Class: ClassServer, Binary: BinaryEdge,
			Title:     "Plane A edge",
			About:     "The observer-edge collector image for hosted AI app telemetry.",
			Levels:    lv(noLevels(), []Level{L1}, "P6"),
			Stability: StabilityPreview,
			Images:    img(ImageSeparate, ImageOut),
		},
	}
}

func noLevels() []Level { return nil }

// pollerRow builds one vendor analytics poller row (L2, no modules).
func pollerRow(id, title, about string, pkgs ...string) Component {
	return Component{
		ID: id, Class: ClassServer, Binary: BinaryOrg,
		Title: title, About: about,
		Levels:    lv(l2l3, l2l3, ""),
		Packages:  pkgs,
		Surface:   Surface{Egress: []Egress{{Host: "<vendor admin API>", Purpose: "Org usage analytics", Gate: "config", Trigger: TriggerOptIn}}},
		Stability: StabilityPreview,
		Images:    img(ImageOff, ImageOut),
	}
}
