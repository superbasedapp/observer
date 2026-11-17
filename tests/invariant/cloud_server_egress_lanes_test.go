package invariant

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// cloud_server_egress_lanes_test.go is the ONE owner of the hosted cloud
// service's declared-egress lane list (cmd/observer-cloud: serve, worker,
// staff serve, the signers and the operator commands; ledger row ENTLWORK-4
// in docs/security.md). The node list (egress_lanes_test.go) walks
// ./cmd/observer and the org server's list (server_egress_lanes_test.go)
// walks ./cmd/observer-org; until this file the hosted service had no
// statement at all (lead decision L-43: "the hosted cloud service has no
// egress-lane table"). It is the same shape and the same checks, reusing
// the node list's network-import table and dial-symbol scan:
//
//   - TestCloudServerEgressLanesDeclared: every module package in the
//     hosted service's closure (linux, windows, darwin) that DIRECTLY
//     imports a network package has a row here.
//   - TestCloudServerEgressLanesNotStale: every row is still in the closure
//     and still imports a network package.
//   - TestCloudServerEgressLaneKindsHonest: a listen-only or address-only
//     row references no outbound dial symbol.
//   - TestCloudServerEgressLaneTableWellFormed: ids and packages unique,
//     every dialing row names what it reaches, its triggers and its gate.
//
// The hosted service is a network service: it listens for devices, the
// portal, the staff console and provider webhooks, and it already reached
// its model providers, WorkOS and Azure before this list existed. Each of
// those lanes is written down as it is; the host-API client (the worker's
// mTLS lane to the tenant hosts' private network) is the one this file's
// lane added. The same limits as the other lists apply: the check is on
// direct imports, the Postgres driver is not a network import in the shared
// table (every process's database DSN is its configuration), and
// cmd/observer-cloud is one blanket row held to its Reaches by review.

// cloudEgressTrigger is what starts a hosted lane's network use.
type cloudEgressTrigger string

const (
	cloudTrigWorker   cloudEgressTrigger = "worker loop"
	cloudTrigJob      cloudEgressTrigger = "analysis job"
	cloudTrigSignIn   cloudEgressTrigger = "sign-in"
	cloudTrigRequest  cloudEgressTrigger = "inbound request"
	cloudTrigOperator cloudEgressTrigger = "operator command"
	cloudTrigStart    cloudEgressTrigger = "process start"
)

// cloudEgressLane is one declared hosted lane.
type cloudEgressLane struct {
	ID       string
	Pkg      string
	Kind     egressKind
	Reaches  string
	Triggers []cloudEgressTrigger
	Gate     string
}

// cloudEgressLanes is the hosted service's declared-egress lane list.
// Order: remote, local, listen-only, address-only.
var cloudEgressLanes = []cloudEgressLane{
	// --- remote: may leave the machine ------------------------------------
	{
		ID: "cloud.hostapi.client", Pkg: "internal/cloudserver/hostapi/hostclient", Kind: egressRemote,
		Reaches:  "the tenant hosts' private host-API origins named in SBCI_HOSTAPI_HOSTS_FILE (https over mTLS with the platform CA as the only root; the dial filter refuses any address that is not RFC 1918 / RFC 4193; no redirects, no environment proxy; every answer verified against the host's pinned response key)",
		Triggers: []cloudEgressTrigger{cloudTrigWorker},
		Gate:     "SBCI_HOSTAPI_HOSTS_FILE (unset: off) plus the document signer's host-API key",
	},
	{
		ID: "cloud.anthropic", Pkg: "internal/cloudserver/anthropic", Kind: egressRemote,
		Reaches:  "the Anthropic Messages API for session enrichment and project digests",
		Triggers: []cloudEgressTrigger{cloudTrigJob, cloudTrigOperator},
		Gate:     "SBCI_INFERENCE_PROVIDER anthropic, a provisioned key, and the execution lease's kill-switch, credential and attestation gates",
	},
	{
		ID: "cloud.foundry", Pkg: "internal/cloudserver/foundry", Kind: egressRemote,
		Reaches:  "the configured Azure AI Foundry endpoint",
		Triggers: []cloudEgressTrigger{cloudTrigJob, cloudTrigOperator},
		Gate:     "SBCI_INFERENCE_PROVIDER foundry and a provisioned key, behind the same execution lease",
	},
	{
		ID: "cloud.llmwire", Pkg: "internal/llmwire", Kind: egressRemote,
		Reaches:  "the OpenAI-compatible route endpoints of the route registry, through the caller's netguard client",
		Triggers: []cloudEgressTrigger{cloudTrigJob},
		Gate:     "an openai_compatible route in the route registry and its provisioned key",
	},
	{
		ID: "cloud.netguard", Pkg: "internal/netguard", Kind: egressRemote,
		Reaches:  "the guarded HTTP client those routes use (SSRF dial control)",
		Triggers: []cloudEgressTrigger{cloudTrigJob},
		Gate:     "its caller's (cloud.llmwire)",
	},
	{
		ID: "cloud.attest", Pkg: "internal/cloudserver/attest", Kind: egressRemote,
		Reaches:  "Azure Resource Manager (the provider's content-logging state) and the instance metadata endpoint for its token",
		Triggers: []cloudEgressTrigger{cloudTrigJob, cloudTrigStart},
		Gate:     "the attestation mode the deployment configures",
	},
	{
		ID: "cloud.identity", Pkg: "internal/cloudserver/identity", Kind: egressRemote,
		Reaches:  "the WorkOS API (device sign-in verification)",
		Triggers: []cloudEgressTrigger{cloudTrigSignIn},
		Gate:     "WORKOS_CLIENT_ID and its key (unset: the fail-closed placeholder, no call)",
	},
	{
		ID: "cloud.api", Pkg: "internal/cloudserver/api", Kind: egressRemote,
		Reaches:  "the WorkOS API (the portal's browser sign-in code exchange and the start-up client check) besides serving the device, portal, staff and webhook routes",
		Triggers: []cloudEgressTrigger{cloudTrigSignIn, cloudTrigStart, cloudTrigRequest},
		Gate:     "SBCI_PORTAL_WORKOS=1 with both WorkOS credentials",
	},
	{
		ID: "cloud.paddle", Pkg: "internal/cloudserver/seatbilling/paddleapi", Kind: egressRemote,
		Reaches:  "the Paddle Billing API, api.paddle.com or sandbox-api.paddle.com by the key's environment (GET and PATCH /subscriptions/{id} for the seat sync, POST /subscriptions/{id}/cancel for an org deletion's cancel_billing step, POST /customers/{id}/portal-sessions for the portal's billing link; nothing else)",
		Triggers: []cloudEgressTrigger{cloudTrigWorker, cloudTrigRequest},
		Gate:     "SBCI_PADDLE_API_KEY_FILE (unset: no call, the portal-session routes answer 501); the worker's seat sync only with SBCI_PADDLE_SEAT_SYNC on (default off); the deletion cancel only for an org deletion past its cooling-off window with a live subscription; a key's prefix must match the base URL's environment",
	},
	{
		ID: "cmd.observer-cloud", Pkg: "cmd/observer-cloud", Kind: egressRemote,
		Reaches:  "the composition layer: its Postgres DSNs, its listeners, the signers' sockets, and every lane above it composes",
		Triggers: []cloudEgressTrigger{cloudTrigOperator, cloudTrigStart, cloudTrigWorker},
		Gate:     "per call: the command and its SBCI_* configuration",
	},

	// --- local: loopback or an owner-only socket --------------------------
	{
		ID: "cloud.signerd", Pkg: "internal/cloudserver/oidcissuer/signerd", Kind: egressLocal,
		Reaches:  "the OIDC signer's and the document signer's unix sockets on the same VM (one allowed peer uid by SO_PEERCRED); the signers listen there",
		Triggers: []cloudEgressTrigger{cloudTrigSignIn, cloudTrigWorker, cloudTrigStart},
		Gate:     "SBCI_OIDC_ISSUER (serve) or SBCI_HOSTAPI_HOSTS_FILE (worker); the signer commands themselves",
	},

	// --- listen-only: serves, never dials ----------------------------------
	{ID: "cloud.oidchttp", Pkg: "internal/cloudserver/oidcissuer/oidchttp", Kind: egressListen, Reaches: "the platform OIDC issuer's /oauth2 routes"},
	{ID: "cloud.webcloud", Pkg: "webcloud", Kind: egressListen, Reaches: "the embedded portal single-page app"},
	{ID: "cloud.metricshttp", Pkg: "internal/cloudserver/cloudmetricshttp", Kind: egressListen, Reaches: "the optional Prometheus /metrics listener of serve and worker (SBCI_METRICS_LISTEN; empty, the default, opens nothing; its own socket, never the public mux; tests/invariant/cloud_metrics_listener_test.go)"},

	// --- address-only: types and parsing, no connection --------------------
	{ID: "cloud.config.node", Pkg: "internal/config", Kind: egressAddress, Reaches: "host and port validation"},
	{ID: "cloud.dataauthority", Pkg: "internal/dataauthority", Kind: egressAddress, Reaches: "IP classification"},
	{ID: "cloud.ipclass", Pkg: "internal/ipclass", Kind: egressAddress, Reaches: "IP classification"},
	{ID: "cloud.netpolicy", Pkg: "internal/netpolicy", Kind: egressAddress, Reaches: "IP classification and dial control"},
	{ID: "cloud.sshspec", Pkg: "internal/sshspec", Kind: egressAddress, Reaches: "SSH target parsing"},
	{ID: "cloud.vendorsurface", Pkg: "internal/vendorsurface", Kind: egressAddress, Reaches: "endpoint parsing"},
}

var (
	cloudClosureMu sync.Mutex
	cloudClosures  = map[string]map[string]egressPkgInfo{}
)

// cloudServerClosure returns the module packages of ./cmd/observer-cloud's
// dependency closure on goos (default tags), cached per GOOS.
func cloudServerClosure(t *testing.T, goos string) map[string]egressPkgInfo {
	t.Helper()
	cloudClosureMu.Lock()
	defer cloudClosureMu.Unlock()
	if c, ok := cloudClosures[goos]; ok {
		return c
	}
	root := repoRoot(t)
	if _, err := os.Stat(filepath.Join(root, "cmd", "observer-cloud")); err != nil {
		t.Skip("cmd/observer-cloud is not in this tree")
	}
	cmd := exec.Command("go", "list", "-deps", "-f",
		"{{if not .Standard}}{{.ImportPath}}\t{{.Dir}}\t{{join .GoFiles \",\"}}\t{{join .Imports \",\"}}{{end}}",
		"./cmd/observer-cloud")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOOS="+goos, "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps ./cmd/observer-cloud (GOOS=%s) failed: %v\n%s", goos, err, out)
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
	for _, must := range []string{"cmd/observer-cloud", "internal/cloudserver/api", "internal/cloudserver/hostapi/hostclient"} {
		if _, ok := c[must]; !ok {
			t.Fatalf("GOOS=%s: hosted closure lacks %s; the egress guard would be vacuous", goos, must)
		}
	}
	cloudClosures[goos] = c
	return c
}

func cloudLaneByPkg() map[string]cloudEgressLane {
	m := make(map[string]cloudEgressLane, len(cloudEgressLanes))
	for _, l := range cloudEgressLanes {
		m[l.Pkg] = l
	}
	return m
}

func TestCloudServerEgressLaneTableWellFormed(t *testing.T) {
	ids, pkgs := map[string]bool{}, map[string]bool{}
	for _, l := range cloudEgressLanes {
		if l.ID == "" || l.Pkg == "" || l.Reaches == "" {
			t.Errorf("hosted lane %+v: ID, Pkg and Reaches are required", l)
		}
		if ids[l.ID] || pkgs[l.Pkg] {
			t.Errorf("hosted lane %q (%s): duplicate id or package", l.ID, l.Pkg)
		}
		ids[l.ID], pkgs[l.Pkg] = true, true
		switch l.Kind {
		case egressRemote, egressLocal:
			if len(l.Triggers) == 0 || l.Gate == "" {
				t.Errorf("hosted lane %q dials: it must name its triggers and gate", l.ID)
			}
		case egressListen, egressAddress:
			if len(l.Triggers) != 0 || l.Gate != "" {
				t.Errorf("hosted lane %q opens no connection: triggers and gate belong to dialing lanes only", l.ID)
			}
		default:
			t.Errorf("hosted lane %q: unknown kind %q", l.ID, l.Kind)
		}
	}
}

func TestCloudServerEgressLanesDeclared(t *testing.T) {
	toolchainTest(t)
	declared := cloudLaneByPkg()
	for _, goos := range egressGOOS {
		for rel, info := range cloudServerClosure(t, goos) {
			nets := networkImportsOf(info.Imports)
			if len(nets) == 0 {
				continue
			}
			if _, ok := declared[rel]; !ok {
				t.Errorf("GOOS=%s: %s imports %s but is not a declared hosted cloud egress lane. The hosted service's "+
					"network access happens only through the lanes in tests/invariant/cloud_server_egress_lanes_test.go: "+
					"add a row with its kind, what it reaches, its triggers and its gate", goos, rel, strings.Join(nets, ", "))
			}
		}
	}
}

func TestCloudServerEgressLanesNotStale(t *testing.T) {
	toolchainTest(t)
	for _, l := range cloudEgressLanes {
		var present, networked bool
		for _, goos := range egressGOOS {
			info, ok := cloudServerClosure(t, goos)[l.Pkg]
			if !ok {
				continue
			}
			present = true
			networked = networked || len(networkImportsOf(info.Imports)) > 0
		}
		switch {
		case !present:
			t.Errorf("hosted lane %q: %s is not in the hosted service's closure; delete or move the row", l.ID, l.Pkg)
		case !networked:
			t.Errorf("hosted lane %q: %s no longer imports a network package; delete the row", l.ID, l.Pkg)
		}
	}
}

func TestCloudServerEgressLaneKindsHonest(t *testing.T) {
	toolchainTest(t)
	declared := cloudLaneByPkg()
	for _, goos := range egressGOOS {
		for rel, info := range cloudServerClosure(t, goos) {
			l, ok := declared[rel]
			if !ok || l.Kind.dials() {
				continue
			}
			for _, hit := range dialSymbolUses(t, info) {
				t.Errorf("GOOS=%s: hosted lane %q is declared %s but %s", goos, l.ID, l.Kind, hit)
			}
		}
	}
}
