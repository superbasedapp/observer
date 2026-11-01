package invariant

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// egress_lanes_test.go is the ONE owner of the node's declared-egress lane
// list (joint roadmap F0-5; ledger row SHR-3 in docs/security.md). CLAUDE.md's
// "Don'ts" points here: node network access happens only through the lanes
// declared in egressLanes, and nothing else.
//
// It generalizes the internal/cloudgateway precedent of cloud_egress_test.go
// (one named package may reach the network, behind one named gate) from one
// feature to the whole node binary. The per-feature pins stay where they are
// (cloud_egress_test.go, pricing_feed_egress_test.go,
// planlimits_egress_test.go, delivery_egress_test.go); each lane row names the
// pins that hold it further, and the table test fails if a named pin file
// disappears.
//
// What the tests check, over the import graph of the node binary
// (./cmd/observer) on linux, windows and darwin:
//
//   - TestEgressLanesDeclared: every module package in the closure that
//     DIRECTLY imports a network package (egressNetworkImports) has a row.
//     A package outside the list that gains a network import fails here.
//   - TestEgressLanesNotStale: every live row is still in the closure and
//     still imports a network package, so the list cannot go stale.
//   - TestEgressLaneKindsHonest: a row declared listen-only or address-only
//     references no outbound dial symbol (egressDialSymbols), so a package
//     that starts dialing must move to a dialing kind, with its trigger and
//     gate written down.
//   - TestEgressPlannedLanesNotYetLive: a planned lane (egressPlannedLanes)
//     whose package has gained a network import must be promoted to a live
//     row with its real gate.
//   - TestEgressLaneTableWellFormed: ids and packages unique, every dialing
//     row names what it reaches, its triggers and its gate.
//
// How to add a lane: add one row to egressLanes (kind, what it reaches, the
// triggers, the gate in front of it), add a matching sentence to SHR-3 in
// docs/security.md when the lane can leave the machine, and, when the lane
// sends anything a user did not type themselves, a dedicated pin in the
// style of cloud_egress_test.go that keeps the always-on daemon paths from
// linking it.
//
// Limits, stated plainly. The check is on DIRECT imports and on the package
// that holds the dial: a package that reaches the network only by calling a
// lane (for example internal/aggregatesvc calling internal/aggregateclient)
// is composition, and the lane row's gate is what governs it. Third-party
// modules that dial internally (for example the D-Bus client under the
// keyring) are reached through a module package and are not listed on their
// own; egressNetworkImports names the third-party network modules a module
// package could import directly, including the ones the plans bring later.

// egressKind says how far a lane's package may reach.
type egressKind string

const (
	// egressRemote: may open outbound connections that leave the machine.
	egressRemote egressKind = "remote"
	// egressLocal: dials only loopback, an owner-only unix socket or named
	// pipe, or a local process; nothing that leaves the machine.
	egressLocal egressKind = "local"
	// egressListen: serves on a listener or registers handlers; opens no
	// outbound connection itself.
	egressListen egressKind = "listen"
	// egressAddress: imports a network package only for address types,
	// parsing or classification; opens no connection and serves nothing.
	egressAddress egressKind = "address"
)

// dials reports whether the kind may open an outbound connection.
func (k egressKind) dials() bool { return k == egressRemote || k == egressLocal }

// egressTrigger is what starts a lane's network use.
type egressTrigger string

const (
	trigDaemonLoop   egressTrigger = "daemon loop"
	trigUserCommand  egressTrigger = "user command"
	trigUserAction   egressTrigger = "dashboard or launch action"
	trigProxyRequest egressTrigger = "proxy request"
	trigWatcher      egressTrigger = "watcher parse"
	trigAIClient     egressTrigger = "AI client traffic"
	// trigHookProcess: an `observer hook` process the AI tool started for
	// one event (security plan section 8.3; JSP-11). security.ask is the
	// first lane a hook starts.
	trigHookProcess egressTrigger = "hook process"
)

// egressLane is one declared lane: the package allowed to hold a network
// import, what it may reach, what triggers it and the gate in front of it.
type egressLane struct {
	ID       string
	Pkg      string // module-relative package path
	Kind     egressKind
	Reaches  string
	Triggers []egressTrigger
	Gate     string
	Pins     []string // further pins in tests/invariant, by file name
}

// egressLanes is the declared-egress lane list of the node binary. Order:
// remote lanes, local lanes, listen-only, address-only.
var egressLanes = []egressLane{
	// --- remote: may leave the machine ------------------------------------
	{
		ID: "cloud.client", Pkg: "internal/cloudclient", Kind: egressRemote,
		Reaches:  "the Observer Cloud API at the configured cloud base URL",
		Triggers: []egressTrigger{trigUserCommand, trigDaemonLoop},
		Gate:     "reachable only through internal/cloudgateway, which checks a live consent receipt fail-closed (sign-in is the user's own action); the daemon tickers are opt-in and only spawn the CLI",
		Pins:     []string{"cloud_egress_test.go"},
	},
	{
		ID: "cloud.gateway", Pkg: "internal/cloudgateway", Kind: egressRemote,
		Reaches:  "the Observer Cloud API, through internal/cloudclient",
		Triggers: []egressTrigger{trigUserCommand, trigDaemonLoop, trigUserAction},
		Gate:     "the consent seam itself: no request without a live grant for the purpose",
		Pins:     []string{"cloud_egress_test.go"},
	},
	{
		ID: "org.client", Pkg: "internal/orgclient", Kind: egressRemote,
		Reaches:  "the one org server the node is enrolled with: push, signed policy, pricing, budget and display pulls, update manifests and artifacts from the org mirror, and the org server's security relay lookup on a managed node (install gate queries, public package names only)",
		Triggers: []egressTrigger{trigDaemonLoop, trigUserCommand},
		Gate:     "enrolment: no org URL or credential exists until `observer org enroll`",
	},
	{
		ID: "org.client.gen", Pkg: "internal/orgclient/gen", Kind: egressRemote,
		Reaches:  "the enrolled org server (generated API client, imported only by internal/orgclient)",
		Triggers: []egressTrigger{trigDaemonLoop, trigUserCommand},
		Gate:     "as org.client",
	},
	{
		ID: "pricing.feed", Pkg: "internal/pricingfeed/client", Kind: egressRemote,
		Reaches:  "the public pricing feed URL",
		Triggers: []egressTrigger{trigDaemonLoop, trigUserCommand},
		Gate:     "`[pricing.feed] enabled` (default on, opt-out), reachable only through internal/pricingfeedgate",
		Pins:     []string{"pricing_feed_egress_test.go", "pricing_feed_default_url_test.go"},
	},
	{
		ID: "pricing.feed.gate", Pkg: "internal/pricingfeedgate", Kind: egressRemote,
		Reaches:  "the public pricing feed URL, through internal/pricingfeed/client",
		Triggers: []egressTrigger{trigDaemonLoop, trigUserCommand},
		Gate:     "the feed's egress seam: `[pricing.feed] enabled`",
		Pins:     []string{"pricing_feed_egress_test.go"},
	},
	{
		ID: "plans.limits", Pkg: "internal/planlimitsnet", Kind: egressRemote,
		Reaches:  "vendor plan and usage hosts from its exact-host table, over HTTPS with no redirects",
		Triggers: []egressTrigger{trigDaemonLoop, trigUserCommand},
		Gate:     "the user adds an account; experimental sources are a per-provider opt-in",
		Pins:     []string{"planlimits_egress_test.go"},
	},
	// The hosted sandbox drivers (sandbox plan section 13 P7, lane SBX-P7):
	// the promoted sandbox.remote planned lane, one row per vendor client.
	{
		ID: "sandbox.remote.e2b", Pkg: "internal/sandboxremote/e2b", Kind: egressRemote,
		Reaches:  "E2B's control plane (api.<region domain>) and envd (sandbox.<region domain>), over HTTPS with no redirects",
		Triggers: []egressTrigger{trigUserAction},
		Gate:     "a user-launched sandboxed terminal on the e2b row (listed in backends, the terminals.sandbox.e2b component active, consent recorded) or a user's confirm in the leftover-box list (I6); the probe never calls it",
		Pins:     []string{"sandbox_remote_egress_test.go"},
	},
	{
		ID: "sandbox.remote.modal", Pkg: "internal/sandboxremote/modal", Kind: egressRemote,
		Reaches:  "Modal's control plane (api.modal.com:443) and the input-plane and per-box command-router hosts it names, over gRPC with TLS through Modal's Go SDK; an interceptor refuses any host outside the bound endpoint's domain",
		Triggers: []egressTrigger{trigUserAction},
		Gate:     "a user-launched sandboxed terminal on the modal row (listed in backends, the terminals.sandbox.modal component active, consent recorded) or a user's confirm in the leftover-box list (I6); the probe never calls it",
		Pins:     []string{"sandbox_remote_egress_test.go"},
	},
	{
		ID: "sandbox.remote.vercel", Pkg: "internal/sandboxremote/vercel", Kind: egressRemote,
		Reaches:  "Vercel's REST API (api.vercel.com, the team- and project-scoped sandbox paths), over HTTPS with no redirects",
		Triggers: []egressTrigger{trigUserAction},
		Gate:     "a user-launched sandboxed terminal on the vercel-sandbox row (listed in backends, the terminals.sandbox.vercel component active, consent recorded) or a user's confirm in the leftover-box list (I6); the probe never calls it",
		Pins:     []string{"sandbox_remote_egress_test.go"},
	},
	{
		ID: "delivery", Pkg: "internal/deliverynet", Kind: egressRemote,
		Reaches:  "the GitHub API and the git remotes of tracked repositories",
		Triggers: []egressTrigger{trigDaemonLoop, trigUserCommand},
		Gate:     "the user connects a code host or opts into a mirror",
		Pins:     []string{"delivery_egress_test.go"},
	},
	{
		ID: "aggregate", Pkg: "internal/aggregateclient", Kind: egressRemote,
		Reaches:  "the opt-in aggregate rail endpoint",
		Triggers: []egressTrigger{trigUserCommand, trigDaemonLoop},
		Gate:     "off by default; Submit requires a consent Gate minted by Authorize, after a mandatory preview",
		Pins:     []string{"aggregate_test.go"},
	},
	{
		ID: "security.online", Pkg: "internal/secfeed/online", Kind: egressRemote,
		Reaches:  "the OSV API (api.osv.dev), the public package registries in the ecosystem table and the vendor's signed content feed (superbased.app), over HTTPS to an exact host allow-list with no redirects; ecosystem, public package name and version only",
		Triggers: []egressTrigger{trigDaemonLoop, trigUserCommand},
		Gate:     "queries: `security.deps` active and `[security.deps] online` on (default on there), and the first-run disclosure accepted on the dashboard or the CLI (no query before it); never a private package name; the feed download: `security.deps` active on an individual node, whatever the online setting (plain GETs of public files, no package named); linked only into the daemon's security service; never used on a managed node or while the tenancy cannot be read (the security service is not handed the public client there; zero-request test); also the sandbox content kinds sandbox.image and sandbox.native_files (lane SBX-P3D, cmd/observer/sandbox_content*.go): plain GETs of public feed files, only on a node that is not enrolled, only while the kind's consuming sandbox driver is active, on `observer sandbox content fetch` or the daemon's first resolve that needs the kind",
		Pins:     []string{"security_online_egress_test.go"},
	},
	{
		ID: "security.ci.fetch", Pkg: "internal/seccifetch", Kind: egressRemote,
		Reaches:  "the org server a CI job names with --org-url: its signed CI policy, the change record lookup for a pull request's commits (commit shas and patch fingerprint hashes), pinned drivers from the org's security mirror and the CI result upload, with the CI credential; and, for the upload only, the GitHub Actions runner's own OIDC token request URL ($ACTIONS_ID_TOKEN_REQUEST_URL) for a token whose audience is the org; https only (plain http to a loopback host), no redirect followed",
		Triggers: []egressTrigger{trigUserCommand},
		Gate:     "`observer security verify fetch` only, run by a CI job; the security module compiled in; no daemon path links it",
	},
	{
		ID: "security.scan.osv.db", Pkg: "internal/secscan/osvnet", Kind: egressRemote,
		Reaches:  "the OSV database bucket (osv-vulnerabilities.storage.googleapis.com: the per-ecosystem exports, metadata first, the body only when its CRC32C changed; only the ecosystem name is sent) and the OSV API (api.osv.dev, online matching: ecosystem, public package name and version), over HTTPS to an exact host allow-list with no redirects",
		Triggers: []egressTrigger{trigDaemonLoop, trigUserCommand},
		Gate:     "a dependency scanner component selected (security.scan.scalibr or security.scan.osv, with security.deps), `[security.deps] online` on and its first-run disclosure recorded, on an individual node only (a managed node is never handed this client); online matching only on `observer security scan --online`; linked only into the daemon's scan loop and the scan command",
		Pins:     []string{"security_scan_egress_test.go"},
	},
	{
		ID: "security.scan.scalibr", Pkg: "internal/secscan/scalibrfacade", Kind: egressRemote,
		Reaches:  "nothing of its own: it hands SCALIBR's osvdev enricher the security.scan.osv.db lane's client for online matching (api.osv.dev by that client's allow-list); the local matcher runs with Download off and a client that refuses every request; gRPC and Google clients are refused",
		Triggers: []egressTrigger{trigUserCommand},
		Gate:     "as security.scan.osv.db; the facade runs inside the scan child for the local path, which is never handed a network client",
		Pins:     []string{"security_scan_egress_test.go", "security_scalibr_test.go"},
	},
	{
		ID: "security.scan.opengrep.net", Pkg: "internal/secscan/opengrep/opengrepnet", Kind: egressRemote,
		Reaches:  "the pinned Opengrep release asset on github.com (redirects followed only to release-assets.githubusercontent.com and objects.githubusercontent.com) and the vendor's signed content feed on superbased.app for the security.rule_pack and security.engine kinds, over HTTPS to an exact host allow-list, every body capped; nothing about a project is sent",
		Triggers: []egressTrigger{trigUserCommand, trigUserAction, trigDaemonLoop},
		Gate:     "security.scan.opengrep selected (opt-in) on an individual node; the release download only after the developer's one-time size consent for the pin in force (dashboard dialog or CLI, never an agent: R-165); the feed only while [security.scan.opengrep] feed is on; never on a managed node (its engine and pack come from the org mirror); linked only into the cmd layer",
		Pins:     []string{"security_opengrep_egress_test.go"},
	},
	{
		ID: "security.scan.trivy.net", Pkg: "internal/secscan/trivy/trivynet", Kind: egressRemote,
		Reaches:  "the pinned Trivy release archive and its sigstore bundle on github.com (redirects followed only to release-assets.githubusercontent.com and objects.githubusercontent.com), over HTTPS to an exact host allow-list, every body capped; nothing about a project is sent",
		Triggers: []egressTrigger{trigUserCommand, trigUserAction},
		Gate:     "security.scan.trivy selected (opt-in) on an individual node, only after the developer's one-time size consent for the pin in force (dashboard or CLI, never an agent: R-165); never on a managed node (its engine comes from the org mirror); linked only into the cmd layer (lane GATES-SEC)",
	},
	{
		ID: "proxy.upstream", Pkg: "internal/proxy", Kind: egressRemote,
		Reaches:  "the AI providers' API hosts and the configured [proxy.upstreams]",
		Triggers: []egressTrigger{trigProxyRequest},
		Gate:     "an AI client routed through the proxy (observer init, a launcher, or a managed node's maintained route); the proxy forwards what the client sent",
	},
	{
		ID: "proxy.summary", Pkg: "internal/messagesummary", Kind: egressRemote,
		Reaches:  "the Anthropic or OpenAI API, with the credentials the proxied request itself carried",
		Triggers: []egressTrigger{trigProxyRequest},
		Gate:     "`[compression.conversation.rolling] enabled` (default off)",
	},
	{
		ID: "summary", Pkg: "internal/intelligence/summary", Kind: egressRemote,
		Reaches:  "the Anthropic Messages API",
		Triggers: []egressTrigger{trigUserCommand},
		Gate:     "the user runs `observer summarize` with an API key configured",
	},
	{
		ID: "judge", Pkg: "internal/judgeclient", Kind: egressRemote,
		Reaches:  "the configured OpenAI-compatible judge endpoint (local or remote; a non-loopback judge gets secret redaction and a payload cap)",
		Triggers: []egressTrigger{trigDaemonLoop, trigUserAction, trigUserCommand},
		Gate:     "a judge endpoint configured under [observability] (opt-in)",
	},
	{
		ID: "guard.cloud", Pkg: "internal/guard/notify", Kind: egressRemote,
		Reaches:  "config-declared guard webhooks, the guard LLM judge and reputation lookups",
		Triggers: []egressTrigger{trigDaemonLoop},
		Gate:     "`[guard.cloud] enabled` (explicit opt-in); the endpoint allow-list is derived from configured destinations only",
	},
	{
		ID: "email", Pkg: "internal/notify/email", Kind: egressRemote,
		Reaches:  "the configured SMTP server",
		Triggers: []egressTrigger{trigDaemonLoop},
		Gate:     "an [email] section configured for alert or digest delivery",
	},
	{
		ID: "otel.export", Pkg: "internal/exporter/otel", Kind: egressRemote,
		Reaches:  "the configured OTLP/HTTP endpoint",
		Triggers: []egressTrigger{trigDaemonLoop},
		Gate:     "`[exporter.otel] enabled` (default off)",
	},
	{
		ID: "selfobs.export", Pkg: "internal/selfobs/emit/otelsink", Kind: egressRemote,
		Reaches:  "the org gateway's OTLP/HTTP endpoint",
		Triggers: []egressTrigger{trigDaemonLoop},
		Gate:     "[selfobs] configured with the enrolment credential",
		Pins:     []string{"selfobs_test.go"},
	},
	{
		ID: "mcp.egress", Pkg: "internal/mcpegress", Kind: egressRemote,
		Reaches:  "admin-supplied MCP upstream URLs, through an SSRF-safe dialer (internal/netpolicy)",
		Triggers: []egressTrigger{trigAIClient},
		Gate:     "`[mcp_relay].enabled` (default off)",
		Pins:     []string{"mcprelay_privacy_test.go"},
	},
	{
		ID: "mcp.relay", Pkg: "internal/mcprelay", Kind: egressRemote,
		Reaches:  "the org's MCP policy front and node-local MCP servers",
		Triggers: []egressTrigger{trigAIClient},
		Gate:     "`[mcp_relay].enabled` (default off) on an enrolled node",
		Pins:     []string{"mcprelay_privacy_test.go"},
	},
	{
		ID: "sandbox.egress", Pkg: "internal/sandboxnet", Kind: egressRemote,
		Reaches:  "the internet for a sandboxed agent through the egress gateway (host-local and private ranges refused), and the loopback proxy; for the container driver's first-start install, only the tool's documented install hosts (the gateway's host allow-list, lane SBX-P3C), and those same hosts' registry metadata for the install version picker (lane LEFT-SBX)",
		Triggers: []egressTrigger{trigUserAction},
		Gate:     "a user-launched sandboxed terminal in the network tier ([terminal.sandbox], default off); the install gateway only with [terminal.sandbox.oci].install_cache on and after the user's yes on the run's terminal; the version picker's read only on the user's click in the Container sandboxes card, with install_cache on",
	},
	{
		ID: "winrelay", Pkg: "internal/winrelaysvc", Kind: egressRemote,
		Reaches:  "Observer's own proxy on loopback and, only when no connection to it opens, the provider host of the request's lane (api.anthropic.com for claude-code); the request is the AI client's own, passed through",
		Triggers: []egressTrigger{trigAIClient},
		Gate:     "`observer relay serve` on the Windows host, refused until live checks LC6 and LC14 pass (winrelay.Gate, DEC-12); each fail-open forward is recorded in the bypass journal first and refused when it cannot be",
		Pins:     []string{"winrelay_test.go"},
	},
	{
		ID: "diag.probe", Pkg: "internal/diag", Kind: egressRemote,
		Reaches:  "a TCP reachability probe of the configured native-console OTLP collector address",
		Triggers: []egressTrigger{trigUserCommand},
		Gate:     "the user runs `observer doctor`",
	},
	// Known limit: cmd/observer is one blanket remote row. The check works
	// per package, so a new direct network call added anywhere in
	// cmd/observer passes without a row of its own; it is held to this row's
	// Reaches list by review only (SHR-3 residuals).
	{
		ID: "cmd.observer", Pkg: "cmd/observer", Kind: egressRemote,
		Reaches:  "the composition layer: loopback probes of its own daemon, proxy and dashboard, loopback local model servers (setup wizard), a remote instance's status over a loopback SSH forward, [observability.alerts] webhooks and [remote.notify] notifications; every other egress it composes goes through a lane above",
		Triggers: []egressTrigger{trigUserCommand, trigDaemonLoop, trigUserAction},
		Gate:     "per call: a user command, or the config section that enables the feature (alert webhooks and remote notify are off by default)",
		Pins:     []string{"remotenotify_boundary_test.go"},
	},

	// --- local: loopback, owner-only sockets and pipes, local processes ---
	{
		ID: "antigravity.ls", Pkg: "internal/adapter/antigravity", Kind: egressLocal,
		Reaches:  "the Antigravity language server on 127.0.0.1 (its own self-signed TLS)",
		Triggers: []egressTrigger{trigWatcher},
		Gate:     "the Antigravity adapter is enabled and its language server is running",
	},
	{
		ID: "localipc", Pkg: "internal/localipc", Kind: egressLocal,
		Reaches:  "an owner-only unix socket or named pipe",
		Triggers: []egressTrigger{trigUserCommand, trigAIClient},
		Gate:     "same-user local IPC only",
	},
	{
		ID: "security.quickscan", Pkg: "internal/secipc", Kind: egressLocal,
		Reaches:  "the daemon's owner-only quick-scan endpoint (a unix socket under a 0700 directory, or an owner-only named pipe), never TCP and never off the machine",
		Triggers: []egressTrigger{trigAIClient, trigDaemonLoop},
		Gate:     "the security module is active; same-user local IPC only; the hook asks only at an agent commit or push (security plan section 4.8, JSP-11)",
	},
	{
		ID: "security.ask", Pkg: "internal/secask", Kind: egressLocal,
		Reaches:  "the daemon's owner-only security ask endpoint, through internal/localipc (a unix socket under a 0700 directory, or an owner-only named pipe), never TCP and never off the machine",
		Triggers: []egressTrigger{trigHookProcess, trigDaemonLoop},
		Gate:     "`security.deps` active, an install command (or a manifest edit), an online-cache miss for a package name, the install-gate wait (default 1.5 s); the daemon serves it only while online checks are on and disclosed (security plan section 8.3, JSP-11)",
	},
	{
		ID: "sandbox.relay", Pkg: "internal/sandboxrelayd", Kind: egressLocal,
		Reaches:  "the capture relay's owner-only local endpoints: a sandbox box's per-run relay socket (served by the host helper) and the daemon's link endpoint under the observer directory (an owner-only named pipe on native Windows, the MXC row, lane SBX-P6, whose box reaches its helper on the run's token-checked loopback port served by cmd/observer); the package itself never dials TCP and never leaves the machine",
		Triggers: []egressTrigger{trigAIClient, trigUserAction},
		Gate:     "a user-launched sandboxed terminal (the Sandboxes and VMs module active); same-user local IPC only, peer uid checked, every frame keyed to the run (sandbox plan section 5.2, lane sbx-p2)",
	},
	{
		ID: "sandbox.engine", Pkg: "internal/sandboxengine", Kind: egressLocal,
		Reaches:  "the local Docker Engine or Podman API on its unix socket (the oci-runc sandbox driver): never TCP, never SSH and never off the machine; an image pull is the engine's own fetch, asked for only by the user's `observer sandbox oci pull` or `observer sandbox oci image pull`, or by a user-launched oci launch of Observer's default image by its signed digest (lane SBX-P3C)",
		Triggers: []egressTrigger{trigUserAction, trigUserCommand},
		Gate:     "the terminals.sandbox.oci driver selected in a [components] block, [terminal.sandbox].enabled true and oci-runc in [terminal.sandbox].backends; the socket must pass the no-symlink, owner and identity checks first (sandbox plan section 4.6, lane SBX-P3A)",
	},
	{
		ID: "sandbox.vmm", Pkg: "internal/sandboxvmm", Kind: egressLocal,
		Reaches:  "the per-run Cloud Hypervisor VMM's REST API socket and its hybrid vsock socket, both unix sockets in the run's 0700 state dir (the cloud-hypervisor microVM sandbox driver): never TCP and never off the machine; the VM has no network device",
		Triggers: []egressTrigger{trigUserAction},
		Gate:     "the terminals.sandbox.vm driver selected in a [components] block, [terminal.sandbox].enabled true and cloud-hypervisor in [terminal.sandbox].backends; dialled only by the run's own host helper after a user launch (sandbox plan section 13 P4, lane SBX-P4)",
	},
	{
		ID: "attachsock", Pkg: "internal/attachsock", Kind: egressLocal,
		Reaches:  "the session-attach control channel (owner-only socket or pipe)",
		Triggers: []egressTrigger{trigUserCommand},
		Gate:     "same-user local IPC only",
	},
	{
		ID: "inspectionbroker", Pkg: "internal/intervention/inspectionbroker", Kind: egressLocal,
		Reaches:  "the privileged process-identity broker's unix socket",
		Triggers: []egressTrigger{trigUserAction, trigDaemonLoop},
		Gate:     "the broker is installed by the operator",
	},
	{
		ID: "sshforward", Pkg: "internal/sshforward", Kind: egressLocal,
		Reaches:  "the loopback end of an `ssh -L` forward (the ssh process carries the bytes)",
		Triggers: []egressTrigger{trigUserAction},
		Gate:     "the user switches to a remote instance",
	},

	// --- listen-only: serves, never dials ---------------------------------
	{ID: "dashboard", Pkg: "internal/intelligence/dashboard", Kind: egressListen, Reaches: "the loopback dashboard's HTTP and websocket handlers"},
	{ID: "dashboard.webapp", Pkg: "internal/intelligence/dashboard/webapp", Kind: egressListen, Reaches: "the embedded web app handler"},
	{ID: "dashapi", Pkg: "internal/dashapi", Kind: egressListen, Reaches: "dashboard route vocabulary (handler types)"},
	{ID: "metrics", Pkg: "internal/metrics", Kind: egressListen, Reaches: "the /metrics handler"},
	{ID: "obs.httpapi", Pkg: "internal/obs/httpapi", Kind: egressListen, Reaches: "Plane A observability routes on the dashboard"},
	{ID: "ingest.browser", Pkg: "internal/ingest/browser", Kind: egressListen, Reaches: "the loopback browser-extension ingest listener"},
	{ID: "ingest.otlp", Pkg: "internal/ingest/otlp", Kind: egressListen, Reaches: "the OTLP gRPC and HTTP receiver"},
	{ID: "processobs.bridge", Pkg: "internal/processobs/bridge", Kind: egressListen, Reaches: "the cross-OS process-capture listener and pipe transport"},
	{ID: "remotecfg", Pkg: "internal/remotecfg", Kind: egressListen, Reaches: "a loopback port probe while arming remote access"},

	// --- address-only: types and parsing, no connection --------------------
	{ID: "config", Pkg: "internal/config", Kind: egressAddress, Reaches: "host and port validation"},
	{ID: "dataauthority", Pkg: "internal/dataauthority", Kind: egressAddress, Reaches: "IP classification"},
	{ID: "agentid", Pkg: "internal/agentid", Kind: egressAddress, Reaches: "IP parsing"},
	{ID: "hook", Pkg: "internal/hook", Kind: egressAddress, Reaches: "IP parsing while registering hooks"},
	{ID: "hookliveness", Pkg: "internal/hookliveness", Kind: egressAddress, Reaches: "loopback classification of hook env base URLs"},
	{ID: "sshspec", Pkg: "internal/sshspec", Kind: egressAddress, Reaches: "SSH target parsing"},
	{ID: "telemetrywire", Pkg: "internal/telemetrywire", Kind: egressAddress, Reaches: "endpoint parsing"},
	{ID: "vendorsurface", Pkg: "internal/vendorsurface", Kind: egressAddress, Reaches: "endpoint parsing"},
	{ID: "mcpintel.discover", Pkg: "internal/mcpintel/discover", Kind: egressAddress, Reaches: "endpoint formatting"},
	{ID: "netpolicy", Pkg: "internal/netpolicy", Kind: egressAddress, Reaches: "the pure IP classification and dial-control hook mcp.egress dials through"},
	{ID: "processobs", Pkg: "internal/processobs", Kind: egressAddress, Reaches: "endpoint formatting"},
	{ID: "processbridge.setup", Pkg: "internal/processbridge/setup", Kind: egressAddress, Reaches: "endpoint parsing"},
	{ID: "ingest.hostguard", Pkg: "internal/ingest/hostguard", Kind: egressAddress, Reaches: "Host header and peer address checks"},
}

// egressPlannedLane is a lane a plan of record names but that is not built.
// It is documentation with one check: once its package exists with a network
// import, it must be promoted to egressLanes with its real gate.
type egressPlannedLane struct {
	ID       string
	Pkg      string // the package the plan names; "" when not named yet
	Reaches  string
	Triggers []egressTrigger
	Gate     string
	Source   string // the plan section and ledger row that own it
}

// egressPlannedLanes are the future lanes the security and sandbox plans name.
var egressPlannedLanes = []egressPlannedLane{
	{
		ID: "sandbox.remote", Pkg: "",
		Reaches:  "the hosted sandbox providers not built yet (Codespaces through gh, Coder, Kubernetes agent-sandbox, AWS AgentCore), one package per provider driver; E2B, Modal and Vercel Sandbox are live rows (sandbox.remote.*)",
		Triggers: []egressTrigger{trigUserAction},
		Gate:     "a user-launched session or an explicit user action only (I6); probes stay local; the driver component active",
		Source:   "sandbox plan section 11.3 and P7, invariant I6",
	},
}

// egressNetworkImports are the import paths that make a package a network
// importer. An entry ending in "/" matches the path and every subpackage.
var egressNetworkImports = []string{
	"net",
	"net/http",
	"net/http/httputil",
	"net/smtp",
	"net/rpc",
	"net/rpc/jsonrpc",
	"crypto/tls",
	"google.golang.org/grpc",
	"github.com/coder/websocket/",
	"github.com/gorilla/websocket/",
	"nhooyr.io/websocket/",
	"golang.org/x/net/",
	"golang.org/x/crypto/ssh/",
	"go.opentelemetry.io/otel/exporters/otlp/",
	"github.com/nats-io/nats.go/",
	"github.com/nats-io/nats-server/",
	// Owner-only Windows named pipes (dial and listen).
	"github.com/Microsoft/go-winio/",
	// Azure SDK clients (Blob, Key Vault, identity) all reach Azure.
	"github.com/Azure/azure-sdk-for-go/",
	// The Google client and OSV API modules OSV-SCALIBR's walker and
	// matchers link (security plan section 8.4, JSP-9b audit, P-019): a
	// module package that imported one directly would need a lane row; the
	// facade reaches them only through SCALIBR
	// (security_scalibr_binary_test.go pins that).
	"cloud.google.com/go/",
	"golang.org/x/oauth2/",
	"google.golang.org/api/",
	"osv.dev/bindings/go/",
	"deps.dev/api/",
	// Named by the sandbox plan's P7 drivers; listed now so they cannot
	// arrive undeclared.
	"k8s.io/client-go/",
	"github.com/aws/aws-sdk-go-v2/",
	// Modal's Go SDK (the modal hosted driver, lane SBX-P7).
	"github.com/modal-labs/modal-client/go/",
}

// isNetworkImport reports whether path is in egressNetworkImports.
func isNetworkImport(path string) bool {
	for _, p := range egressNetworkImports {
		if strings.HasSuffix(p, "/") {
			base := strings.TrimSuffix(p, "/")
			if path == base || strings.HasPrefix(path, p) {
				return true
			}
			continue
		}
		if path == p {
			return true
		}
	}
	return false
}

// egressDialSymbols are the selectors that open an outbound connection, per
// import path. "*" means any use of the package. A listen-only or
// address-only row may reference none of them.
var egressDialSymbols = map[string][]string{
	"net":                        {"Dial", "DialTimeout", "DialTCP", "DialUDP", "DialIP", "DialUnix", "Dialer"},
	"net/http":                   {"Get", "Head", "Post", "PostForm", "Client", "DefaultClient", "DefaultTransport", "Transport"},
	"net/http/httputil":          {"ReverseProxy", "NewSingleHostReverseProxy"},
	"net/smtp":                   {"Dial", "SendMail", "NewClient"},
	"crypto/tls":                 {"Dial", "DialWithDialer", "Dialer", "Client"},
	"google.golang.org/grpc":     {"Dial", "DialContext", "NewClient"},
	"github.com/coder/websocket": {"Dial"},
	"golang.org/x/crypto/ssh":    {"Dial", "NewClient", "NewClientConn"},
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp": {"*"},
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc": {"*"},
}

// egressPkgInfo is one module package of the node closure on one GOOS.
type egressPkgInfo struct {
	Rel     string
	Dir     string
	Files   []string
	Imports []string
}

// egressGOOS are the platforms whose node closure is checked.
var egressGOOS = []string{"linux", "windows", "darwin"}

var (
	egressClosureMu sync.Mutex
	egressClosures  = map[string]map[string]egressPkgInfo{}
)

// egressClosure returns the module packages of ./cmd/observer's dependency
// closure on goos, keyed by module-relative path. Cached per GOOS.
func egressClosure(t *testing.T, goos string) map[string]egressPkgInfo {
	t.Helper()
	egressClosureMu.Lock()
	defer egressClosureMu.Unlock()
	if c, ok := egressClosures[goos]; ok {
		return c
	}
	cmd := exec.Command("go", "list", "-deps", "-f",
		"{{if not .Standard}}{{.ImportPath}}\t{{.Dir}}\t{{join .GoFiles \",\"}}\t{{join .Imports \",\"}}{{end}}",
		"./cmd/observer")
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), "GOOS="+goos, "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps ./cmd/observer (GOOS=%s) failed: %v\n%s", goos, err, out)
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
	// Non-vacuous: the closure must hold the binary itself and a known
	// network lane, so a broken listing cannot pass silently.
	for _, must := range []string{"cmd/observer", "internal/proxy"} {
		if _, ok := c[must]; !ok {
			t.Fatalf("GOOS=%s: node closure lacks %s (%d module packages); the egress guard would be vacuous", goos, must, len(c))
		}
	}
	egressClosures[goos] = c
	return c
}

// networkImportsOf returns the network imports among imports, sorted.
func networkImportsOf(imports []string) []string {
	var out []string
	for _, imp := range imports {
		if isNetworkImport(imp) {
			out = append(out, imp)
		}
	}
	sort.Strings(out)
	return out
}

// egressLaneByPkg indexes egressLanes by package.
func egressLaneByPkg() map[string]egressLane {
	m := make(map[string]egressLane, len(egressLanes))
	for _, l := range egressLanes {
		m[l.Pkg] = l
	}
	return m
}

// TestEgressLaneTableWellFormed checks the table itself; no toolchain.
func TestEgressLaneTableWellFormed(t *testing.T) {
	root := repoRoot(t)
	public := inPublicTree(root)
	ids := map[string]bool{}
	pkgs := map[string]bool{}
	for _, l := range egressLanes {
		if l.ID == "" || l.Pkg == "" || l.Reaches == "" {
			t.Errorf("lane %+v: ID, Pkg and Reaches are required", l)
		}
		if ids[l.ID] {
			t.Errorf("duplicate lane id %q", l.ID)
		}
		ids[l.ID] = true
		if pkgs[l.Pkg] {
			t.Errorf("duplicate lane package %q: one row per package", l.Pkg)
		}
		pkgs[l.Pkg] = true
		switch l.Kind {
		case egressRemote, egressLocal:
			if len(l.Triggers) == 0 || l.Gate == "" {
				t.Errorf("lane %q (%s) dials: it must name its triggers and the gate in front of it", l.ID, l.Kind)
			}
		case egressListen, egressAddress:
			if len(l.Triggers) != 0 || l.Gate != "" {
				t.Errorf("lane %q (%s) opens no connection: triggers and gate belong to dialing lanes only", l.ID, l.Kind)
			}
		default:
			t.Errorf("lane %q: unknown kind %q", l.ID, l.Kind)
		}
		for _, pin := range l.Pins {
			if _, err := os.Stat(filepath.Join(root, "tests", "invariant", pin)); err != nil {
				// A pin that imports a private-only package (the org
				// server's config, for the pricing feed's lock-step pin) is
				// swept from the public tree by scripts/release.sh; the
				// private tree still requires every pin.
				if public && errors.Is(err, fs.ErrNotExist) {
					t.Logf("lane %q pin %s: absent on the public tree (private-only importer)", l.ID, pin)
					continue
				}
				t.Errorf("lane %q names pin %s, which does not exist: %v", l.ID, pin, err)
			}
		}
	}
	for _, p := range egressPlannedLanes {
		if p.ID == "" || p.Reaches == "" || p.Gate == "" || p.Source == "" || len(p.Triggers) == 0 {
			t.Errorf("planned lane %+v: ID, Reaches, Triggers, Gate and Source are required", p)
		}
		if ids[p.ID] {
			t.Errorf("planned lane id %q collides with another lane", p.ID)
		}
		ids[p.ID] = true
		if p.Pkg != "" && pkgs[p.Pkg] {
			t.Errorf("planned lane %q names package %s, which already has a live row", p.ID, p.Pkg)
		}
	}
}

// TestEgressLanesDeclared is the primary guard: every module package of the
// node binary that directly imports a network package has a row.
func TestEgressLanesDeclared(t *testing.T) {
	toolchainTest(t)
	declared := egressLaneByPkg()
	for _, goos := range egressGOOS {
		for rel, info := range egressClosure(t, goos) {
			nets := networkImportsOf(info.Imports)
			if len(nets) == 0 {
				continue
			}
			if _, ok := declared[rel]; !ok {
				t.Errorf("GOOS=%s: %s imports %s but is not a declared egress lane. Node network access "+
					"happens only through the lanes in tests/invariant/egress_lanes_test.go: add a row with "+
					"its kind, what it reaches, its triggers and its gate, and SHR-3 in docs/security.md when "+
					"it can leave the machine", goos, rel, strings.Join(nets, ", "))
			}
		}
	}
}

// TestEgressLanesNotStale fails when a live row's package left the node
// closure or no longer imports a network package on any checked GOOS.
func TestEgressLanesNotStale(t *testing.T) {
	toolchainTest(t)
	root := repoRoot(t)
	public := inPublicTree(root)
	for _, l := range egressLanes {
		// A lane in a private-only package (internal/obs/httpapi, the Plane A
		// routes) has no source on the public tree, whose binary links the
		// obs stub instead; the private tree still holds it to the closure.
		if public && !dirExists(root, l.Pkg) {
			continue
		}
		var present, networked bool
		for _, goos := range egressGOOS {
			info, ok := egressClosure(t, goos)[l.Pkg]
			if !ok {
				continue
			}
			present = true
			if len(networkImportsOf(info.Imports)) > 0 {
				networked = true
			}
		}
		switch {
		case !present:
			t.Errorf("lane %q: %s is not in the node binary's closure on %v; delete or move the row", l.ID, l.Pkg, egressGOOS)
		case !networked:
			t.Errorf("lane %q: %s no longer imports a network package; delete the row", l.ID, l.Pkg)
		}
	}
}

// TestEgressLaneKindsHonest fails when a listen-only or address-only row
// references an outbound dial symbol in its non-test source.
func TestEgressLaneKindsHonest(t *testing.T) {
	toolchainTest(t)
	declared := egressLaneByPkg()
	for _, goos := range egressGOOS {
		for rel, info := range egressClosure(t, goos) {
			l, ok := declared[rel]
			if !ok || l.Kind.dials() {
				continue
			}
			for _, hit := range dialSymbolUses(t, info) {
				t.Errorf("GOOS=%s: lane %q is declared %s but %s; make it a %s or %s lane with its triggers "+
					"and gate", goos, l.ID, l.Kind, hit, egressRemote, egressLocal)
			}
		}
	}
}

// TestEgressPlannedLanesNotYetLive fails when a planned lane's package has
// landed with a network import: it must become a live row with its gate.
func TestEgressPlannedLanesNotYetLive(t *testing.T) {
	toolchainTest(t)
	for _, p := range egressPlannedLanes {
		if p.Pkg == "" {
			continue
		}
		for _, goos := range egressGOOS {
			info, ok := egressClosure(t, goos)[p.Pkg]
			if ok && len(networkImportsOf(info.Imports)) > 0 {
				t.Errorf("GOOS=%s: planned lane %q (%s) has landed in %s with a network import; move it to "+
					"egressLanes with its real gate and update SHR-3", goos, p.ID, p.Source, p.Pkg)
			}
		}
	}
}

// dialSymbolUses parses info's Go files and returns a description of every
// selector that names an egressDialSymbols entry.
func dialSymbolUses(t *testing.T, info egressPkgInfo) []string {
	t.Helper()
	var hits []string
	fset := token.NewFileSet()
	for _, name := range info.Files {
		path := filepath.Join(info.Dir, name)
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		local := map[string][]string{} // local package name -> dial symbols
		for _, spec := range f.Imports {
			ipath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				continue
			}
			syms, ok := egressDialSymbols[ipath]
			if !ok {
				continue
			}
			name := ipath[strings.LastIndex(ipath, "/")+1:]
			if spec.Name != nil {
				name = spec.Name.Name
			}
			if name == "_" || name == "." {
				continue
			}
			local[name] = syms
		}
		if len(local) == 0 {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			syms, ok := local[id.Name]
			if !ok {
				return true
			}
			for _, s := range syms {
				if s == "*" || s == sel.Sel.Name {
					hits = append(hits, fmt.Sprintf("%s uses %s.%s", fset.Position(sel.Pos()), id.Name, sel.Sel.Name))
					break
				}
			}
			return true
		})
	}
	return hits
}
