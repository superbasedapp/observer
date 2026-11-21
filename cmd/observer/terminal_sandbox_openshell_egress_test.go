//go:build !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxnet"
	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// The package's tests never bind the fixed receiver port: a daemon-shaped
// driver built by any test listens on an ephemeral loopback port instead.
func init() { openShellOCSFListen = "127.0.0.1:0" }

// Sentinel values: no real box, run, path or host.
const (
	egressTestBox = "0a415311-0000-4000-8000-00000000beef"
	egressTestRun = "-RunSENTINEL0000_o3"
	egressTestBin = "/home/dev/.observer/bin/observer"
)

// TestOpenShellOCSFRulesAreN1s pins the planner's spelled rule and key
// names to lane N1's frozen contract (internal/sandboxnet refusal.go).
func TestOpenShellOCSFRulesAreN1s(t *testing.T) {
	t.Parallel()
	keys := []string{sandboxnet.KeyEgressAllowHosts, sandboxnet.KeyEgressAllowCIDRs, sandboxnet.KeyEgress, sandboxnet.KeyProviderDirect}
	for _, r := range sandboxopenshell.OCSFRuleRows() {
		if !sandboxnet.RefusalRule(r.Rule).Valid() {
			t.Errorf("%s: rule %q is not in N1's vocabulary", r.ID, r.Rule)
		}
		if !slices.Contains(keys, r.Key) {
			t.Errorf("%s: key %q is not one of N1's keys", r.ID, r.Key)
		}
	}
	pairs := [][2]string{
		{sandboxopenshell.OCSFRuleAllowListMiss, string(sandboxnet.RefusalAllowListMiss)},
		{sandboxopenshell.OCSFRulePrivateRange, string(sandboxnet.RefusalPrivateRange)},
		{sandboxopenshell.OCSFRuleProviderHost, string(sandboxnet.RefusalProviderHost)},
		{sandboxopenshell.OCSFRuleHostLocal, string(sandboxnet.RefusalHostLocal)},
		{sandboxopenshell.OCSFRuleTierNone, string(sandboxnet.RefusalTierNone)},
		{sandboxopenshell.OCSFRuleSSRFFloor, string(sandboxnet.RefusalSSRFFloor)},
		{sandboxopenshell.OCSFRuleLiteralIP, string(sandboxnet.RefusalLiteralIP)},
		{sandboxopenshell.OCSFRulePortNotAllowed, string(sandboxnet.RefusalPortNotAllowed)},
		{sandboxopenshell.OCSFKeyEgressAllowHosts, sandboxnet.KeyEgressAllowHosts},
		{sandboxopenshell.OCSFKeyEgressAllowCIDRs, sandboxnet.KeyEgressAllowCIDRs},
		{sandboxopenshell.OCSFKeyEgress, sandboxnet.KeyEgress},
		{sandboxopenshell.OCSFKeyProviderDirect, sandboxnet.KeyProviderDirect},
	}
	for _, p := range pairs {
		if p[0] != p[1] {
			t.Errorf("%q != N1's %q", p[0], p[1])
		}
	}
}

// TestOpenShellHelperNeverRunsTheGateway is rule W4: on every tier the row
// offers, the host helper's network profile starts no Observer egress
// gateway beside OpenShell's proxy, and the model proxy is still forwarded
// wherever the tier has one.
func TestOpenShellHelperNeverRunsTheGateway(t *testing.T) {
	t.Parallel()
	cases := []struct {
		tier    sandbox.Egress
		want    sandbox.Egress
		forward bool
	}{
		{sandbox.EgressInternet, sandbox.EgressProxyOnly, true},
		{sandbox.EgressProxyOnly, sandbox.EgressProxyOnly, true},
		{sandbox.EgressNone, sandbox.EgressNone, false},
	}
	row := openShellRow()
	if len(cases) != len(row.Net.Egress) {
		t.Fatalf("%d cases for the row's tiers %v", len(cases), row.Net.Egress)
	}
	for _, tc := range cases {
		got := openShellHelperEgress(tc.tier)
		prof, err := sandbox.ResolveEgress(string(got))
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want || prof.Gateway || prof.ForwardProxy != tc.forward {
			t.Errorf("%s: helper profile %s (gateway %v, forward %v), want %s with no gateway", tc.tier, got, prof.Gateway, prof.ForwardProxy, tc.want)
		}
	}
}

func TestOpenShellOCSFExportFrom(t *testing.T) {
	t.Parallel()
	want := sandboxopenshell.OCSFReceiverEndpoint()
	cases := []struct {
		name string
		toml string
		err  error
		st   sandboxopenshell.OCSFExportState
	}{
		{"unreadable", "", errors.New("permission denied"), sandboxopenshell.OCSFExportUnknown},
		{"not toml", "[[[", nil, sandboxopenshell.OCSFExportUnknown},
		{"no otlp table", "[openshell.drivers.docker]\nallow_driver_config = true\n", nil, sandboxopenshell.OCSFExportMissing},
		{"traces only", "[openshell.gateway.otlp]\nendpoint = \"" + want + "\"\n", nil, sandboxopenshell.OCSFExportMissing},
		{"README step 1", "[openshell.gateway.otlp]\nendpoint = \"" + want + "\"\n\n[openshell.gateway.otlp.ocsf]\nenabled = true\n", nil, sandboxopenshell.OCSFExportPresent},
		{"own endpoint", "[openshell.gateway.otlp.ocsf]\nenabled = true\nendpoint = \"" + want + "\"\n", nil, sandboxopenshell.OCSFExportPresent},
		{"another collector", "[openshell.gateway.otlp.ocsf]\nenabled = true\nendpoint = \"http://127.0.0.1:4317\"\n", nil, sandboxopenshell.OCSFExportMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, why := sandboxopenshell.ClassifyOCSFExport(openShellOCSFExportFrom("/home/dev/.config/openshell/gateway.toml", []byte(tc.toml), tc.err), want)
			if st != sandboxopenshell.OCSFExportPresent && !strings.Contains(why, "/home/dev/.config/openshell/gateway.toml") {
				t.Fatalf("reason %q does not name the file", why)
			}
			if st != tc.st {
				t.Fatalf("%s, want %s", st, tc.st)
			}
		})
	}
}

// TestOpenShellEgressRefusal: one case per launch outcome of the egress
// check at Create, the receiver's state included (audit finding O3-A1).
func TestOpenShellEgressRefusal(t *testing.T) {
	present := sandboxopenshell.OCSFExport{Read: true, Enabled: true, Endpoint: sandboxopenshell.OCSFReceiverEndpoint()}
	missing := sandboxopenshell.OCSFExport{Read: true}
	up := sandboxopenshell.OCSFReceiverFacts{Listener: true, ListenerOurUID: true, Marker: true, MarkerOwnsListener: true, SinkReady: true}
	oldExport, oldFacts, oldPath := openShellOCSFExportAt, openShellOCSFReceiverFactsFn, openShellOCSFConfigPathFn
	t.Cleanup(func() {
		openShellOCSFExportAt, openShellOCSFReceiverFactsFn, openShellOCSFConfigPathFn = oldExport, oldFacts, oldPath
	})
	cfg := func(hosts ...string) config.TerminalSandboxConfig {
		return config.TerminalSandboxConfig{EgressAllowHosts: hosts}
	}
	pinned := cfg()
	pinned.PinnedNoEgressHost = "terminal.sandbox.egress_allow_hosts"
	cases := []struct {
		name   string
		cfg    config.TerminalSandboxConfig
		tier   vocab.Tier
		export sandboxopenshell.OCSFExport
		recv   sandboxopenshell.OCSFReceiverFacts
		upstr  []string
		note   string
		says   string
	}{
		{"internet, list, export present, receiver up", cfg("api.github.com", "*.npmjs.org"), vocab.TierInternet, present, up, nil, " network_rules=2 ocsf_export=present ocsf_receiver=listening", ""},
		{"internet, no list", cfg(), vocab.TierInternet, present, up, nil, "", "egress_allow_hosts"},
		{"internet, export missing", cfg("api.github.com"), vocab.TierInternet, missing, up, nil, "", "[openshell.gateway.otlp.ocsf] enabled"},
		{"internet, gateway config unread", cfg("api.github.com"), vocab.TierInternet, sandboxopenshell.OCSFExport{Path: "/cfg/gateway.toml"}, up, nil, "", "/cfg/gateway.toml"},
		{"internet, no receiver (no daemon)", cfg("api.github.com"), vocab.TierInternet, present, sandboxopenshell.OCSFReceiverFacts{}, nil, "", "observer start"},
		{"internet, port taken by another user", cfg("api.github.com"), vocab.TierInternet, present, sandboxopenshell.OCSFReceiverFacts{Listener: true}, nil, "", "another user's"},
		{"internet, port taken by another process", cfg("api.github.com"), vocab.TierInternet, present, sandboxopenshell.OCSFReceiverFacts{Listener: true, ListenerOurUID: true, Marker: true}, nil, "", "not this Observer daemon's receiver"},
		{"internet, relay not serving", cfg("api.github.com"), vocab.TierInternet, present, sandboxopenshell.OCSFReceiverFacts{Listener: true, ListenerOurUID: true, Marker: true, MarkerOwnsListener: true}, nil, "", "not wired"},
		{"internet, provider host", cfg("api.github.com", "*.anthropic.com"), vocab.TierInternet, present, up, nil, "", "model provider"},
		{"internet, host alias", cfg("host.openshell.internal"), vocab.TierInternet, present, up, nil, "", "host-alias"},
		{"internet, configured upstream", cfg("llm.corp.example"), vocab.TierInternet, present, up, []string{"llm.corp.example"}, "", "model provider"},
		{"internet, bad list", cfg("Bad Host"), vocab.TierInternet, present, up, nil, "", "egress_allow_hosts"},
		{"internet, org pin left none", pinned, vocab.TierInternet, present, up, nil, " network_rules=0 ocsf_export=present ocsf_receiver=listening", ""},
		{"proxy_only, export missing, no receiver", cfg(), vocab.TierProxyOnly, missing, sandboxopenshell.OCSFReceiverFacts{}, nil, " network_rules=0 ocsf_export=missing ocsf_receiver=absent", ""},
		{"none, export present", cfg("api.anthropic.com"), vocab.TierNone, present, up, nil, " network_rules=0 ocsf_export=present ocsf_receiver=listening", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotPath string
			openShellOCSFConfigPathFn = func() string { return "/cfg/gateway.toml" }
			openShellOCSFExportAt = func(p string) sandboxopenshell.OCSFExport { gotPath = p; return tc.export }
			var gotState string
			openShellOCSFReceiverFactsFn = func(stateDir string) sandboxopenshell.OCSFReceiverFacts { gotState = stateDir; return tc.recv }
			note, err := openShellEgressRefusal(tc.cfg, tc.tier, tc.upstr, egressTestBin, "/state", openShellOCSFGateway{Mode: sandboxopenshell.GatewayExternal})
			if tc.says != "" {
				var re sandboxRefusalError
				if err == nil || !errors.As(err, &re) || !strings.Contains(err.Error(), tc.says) {
					t.Fatalf("err %v, want a refusal naming %q", err, tc.says)
				}
				return
			}
			if err != nil || note != tc.note {
				t.Fatalf("note %q err %v, want %q", note, err, tc.note)
			}
			if gotPath != "/cfg/gateway.toml" || gotState != "/state" {
				t.Fatalf("probed %q and %q", gotPath, gotState)
			}
		})
	}
}

// TestOpenShellOCSFSourceRows (lane OC item 3): one row per gateway mode
// of the D3 probe's source table. Managed mode reads the private gateway's
// own config (never the user's) and its refusal says Observer writes it;
// external mode reads the user's config and its refusal says Observer
// never writes it. A managed launch whose probe recorded no private config
// reads unknown and refuses.
func TestOpenShellOCSFSourceRows(t *testing.T) {
	const userCfg, managedCfg = "/home/dev/.config/openshell/gateway.toml", "/state/gateway/gateway.toml"
	present := sandboxopenshell.OCSFExport{Read: true, Enabled: true, Endpoint: sandboxopenshell.OCSFReceiverEndpoint()}
	up := sandboxopenshell.OCSFReceiverFacts{Listener: true, ListenerOurUID: true, Marker: true, MarkerOwnsListener: true, SinkReady: true}
	oldExport, oldFacts, oldPath := openShellOCSFExportAt, openShellOCSFReceiverFactsFn, openShellOCSFConfigPathFn
	t.Cleanup(func() {
		openShellOCSFExportAt, openShellOCSFReceiverFactsFn, openShellOCSFConfigPathFn = oldExport, oldFacts, oldPath
	})
	openShellOCSFConfigPathFn = func() string { return userCfg }
	openShellOCSFReceiverFactsFn = func(string) sandboxopenshell.OCSFReceiverFacts { return up }
	cases := []struct {
		name string
		gw   openShellOCSFGateway
		// files: the export each config path reads (absent: unread).
		files    map[string]sandboxopenshell.OCSFExport
		wantPath string
		note     string
		says     string
		notSays  string
	}{
		{
			name: "managed, the private config exports", gw: openShellOCSFGateway{Mode: sandboxopenshell.GatewayManaged, ManagedConfigPath: managedCfg},
			files: map[string]sandboxopenshell.OCSFExport{managedCfg: present}, wantPath: managedCfg, note: " network_rules=1 ocsf_export=present ocsf_receiver=listening",
		},
		{
			name: "managed, the private config predates the export", gw: openShellOCSFGateway{Mode: sandboxopenshell.GatewayManaged, ManagedConfigPath: managedCfg},
			files: map[string]sandboxopenshell.OCSFExport{managedCfg: {Read: true, Path: managedCfg}, userCfg: present}, wantPath: managedCfg,
			says: "Observer writes its private gateway's config", notSays: "never writes your gateway's config",
		},
		{
			name: "managed, no private config recorded", gw: openShellOCSFGateway{Mode: sandboxopenshell.GatewayManaged},
			files: map[string]sandboxopenshell.OCSFExport{userCfg: present}, wantPath: "", says: "could not be read",
		},
		{
			name: "external, the user's config exports", gw: openShellOCSFGateway{Mode: sandboxopenshell.GatewayExternal, ManagedConfigPath: managedCfg},
			files: map[string]sandboxopenshell.OCSFExport{userCfg: present}, wantPath: userCfg, note: " network_rules=1 ocsf_export=present ocsf_receiver=listening",
		},
		{
			name: "external, the user's config does not export", gw: openShellOCSFGateway{Mode: sandboxopenshell.GatewayExternal},
			files: map[string]sandboxopenshell.OCSFExport{userCfg: {Read: true, Path: userCfg}, managedCfg: present}, wantPath: userCfg,
			says: "Observer never writes your gateway's config", notSays: "Observer writes its private",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var probed []string
			openShellOCSFExportAt = func(p string) sandboxopenshell.OCSFExport {
				probed = append(probed, p)
				if e, ok := tc.files[p]; ok {
					return e
				}
				return sandboxopenshell.OCSFExport{Path: p}
			}
			note, err := openShellEgressRefusal(config.TerminalSandboxConfig{EgressAllowHosts: []string{"api.github.com"}}, vocab.TierInternet, nil, egressTestBin, "/state", tc.gw)
			if len(probed) != 1 || probed[0] != tc.wantPath {
				t.Fatalf("probed %q, want only %q", probed, tc.wantPath)
			}
			if tc.says != "" {
				if err == nil || !strings.Contains(err.Error(), tc.says) || (tc.notSays != "" && strings.Contains(err.Error(), tc.notSays)) {
					t.Fatalf("err %v, want a refusal naming %q", err, tc.says)
				}
				return
			}
			if err != nil || note != tc.note {
				t.Fatalf("note %q err %v, want %q", note, err, tc.note)
			}
		})
	}
}

// fakeOpenShellAllows is a fake of OpenShell's L4 decision over a compiled
// rule set, as doc 01 section 8 and doc 03 section 4.2 describe it: a
// connection is allowed only when some endpoint's host pattern matches the
// target name (exact, or "**." for one or more leading labels), the port
// is listed, and the resolved address lies in allowed_ips. No rule: deny.
func fakeOpenShellAllows(rules []sandboxopenshell.NetRule, host string, port int, addr netip.Addr) bool {
	for _, r := range rules {
		for _, e := range r.Endpoints {
			name, glob := strings.CutPrefix(e.Host, "**.")
			if !(host == name && !glob) && !(glob && strings.HasSuffix(host, "."+name)) {
				continue
			}
			if !slices.Contains(e.Ports, port) {
				continue
			}
			if slices.ContainsFunc(e.AllowedIPs, func(p netip.Prefix) bool { return p.Contains(addr) }) {
				return true
			}
		}
	}
	return false
}

// TestOpenShellModelHostNeverReachable is the adversarial row (lane O3,
// rule W4) through the driver's own composition and a fake of OpenShell's
// decision: whatever the developer's list says, no model provider host (nor
// a subdomain, nor the proxy's configured upstream) is reachable directly
// from the box on any tier; the list's own hosts are.
func TestOpenShellModelHostNeverReachable(t *testing.T) {
	t.Parallel()
	upstream := "llm.corp.example"
	public := netip.MustParseAddr("93.184.216.34")
	lists := [][]string{
		{"api.github.com", "*.npmjs.org", "proxy.golang.org"},
		{"*.githubusercontent.com", "docs.anthropic.com", "platform.openai.com"},
	}
	providers := append(vocab.ModelProviderHosts(), upstream)
	for _, tier := range []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone} {
		for _, list := range lists {
			in, _, err := openShellRunNet(config.TerminalSandboxConfig{EgressAllowHosts: list}, tier, []string{upstream}, egressTestBin)
			if err != nil {
				t.Fatal(err)
			}
			rules, err := sandboxopenshell.CompileNetRules(tier, in)
			if err != nil {
				t.Fatalf("%s %v: %v", tier, list, err)
			}
			for _, p := range providers {
				for _, h := range []string{p, "eu." + p} {
					for _, port := range []int{443, 80} {
						if fakeOpenShellAllows(rules, h, port, public) {
							t.Errorf("%s %v: %s:%d is reachable directly", tier, list, h, port)
						}
					}
				}
			}
			listed := tier == vocab.TierInternet
			if got := fakeOpenShellAllows(rules, "api.github.com", 443, public) || fakeOpenShellAllows(rules, "docs.anthropic.com", 443, public); got != listed {
				t.Errorf("%s %v: a listed host reachable %v, want %v", tier, list, got, listed)
			}
			if fakeOpenShellAllows(rules, "api.github.com", 443, netip.MustParseAddr("10.0.0.1")) {
				t.Errorf("%s: a listed host resolving to a private address is reachable", tier)
			}
		}
	}
	// A list naming a provider by any spelling is refused before a box.
	for _, entry := range []string{"api.anthropic.com", "*.anthropic.com", "eu.api.openai.com", "*.corp.example", upstream} {
		in, _, err := openShellRunNet(config.TerminalSandboxConfig{EgressAllowHosts: []string{entry}}, vocab.TierInternet, []string{upstream}, egressTestBin)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sandboxopenshell.CompileNetRules(vocab.TierInternet, in); !errors.Is(err, sandboxopenshell.ErrNetProviderHost) {
			t.Errorf("%q: err %v, want ErrNetProviderHost", entry, err)
		}
	}
}

// egressTestRunDir writes one run dir with a recorded box id and egress
// file, as compose and the host helper do.
func egressTestRunDir(t *testing.T, stateDir, runID, boxID string, re sandboxopenshell.RunEgress) {
	t.Helper()
	dir := openShellRunDir(stateDir, runID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := openShellWriteEgress(dir, re); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, openShellSandboxIDFile), []byte(boxID+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func otlpStr(k, v string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}}
}

func otlpRecord(box, uid, body string) *logspb.LogRecord {
	return &logspb.LogRecord{
		Body:       &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: body}},
		Attributes: []*commonpb.KeyValue{otlpStr("openshell.sandbox.id", box), otlpStr("ocsf.metadata.uid", uid), {Key: "ocsf.class_uid", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: 4001}}}},
	}
}

// TestOpenShellOCSFReachesTheSink: an OCSF export over OTLP gRPC to the
// daemon's loopback receiver lands exactly one report per denied
// connection of a run's box on the relay's refusal hook (the one N1
// receiver and store seam), named by the run's own egress facts; another
// box's event, an allowed event and a redelivered uid land nothing.
func TestOpenShellOCSFReachesTheSink(t *testing.T) {
	stateDir, observerDir := t.TempDir(), t.TempDir()
	egressTestRunDir(t, stateDir, egressTestRun, egressTestBox, sandboxopenshell.RunEgress{Tier: vocab.TierInternet, Hosts: []string{"api.github.com"}})
	var mu sync.Mutex
	var got []sandboxrelay.EgressRefusalReport
	var runs []string
	sink := func(rr sandboxrelayd.RunRecord, rep sandboxrelay.EgressRefusalReport) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, rep)
		runs = append(runs, rr.RunID)
	}
	// The relay hands every registered source its hook at start.
	for _, src := range sandboxEgressRefusalSources {
		src(sink)
	}
	t.Cleanup(func() {
		for _, src := range sandboxEgressRefusalSources {
			src(nil)
		}
	})
	if !openShellStartOCSFReceiver(stateDir, observerDir, nil) {
		t.Fatal("the receiver did not start")
	}
	t.Cleanup(openShellStopOCSFReceiver)
	processOpenShellOCSF.mu.Lock()
	addr := processOpenShellOCSF.recv.GRPCAddr()
	processOpenShellOCSF.mu.Unlock()
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("receiver on %s, want loopback", addr)
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	denied := `{"class_uid":4001,"action":"Denied","dst_endpoint":{"domain":"example.com","port":443},"status_detail":"policy_dns_ineligible","time":` + jsonInt(time.Now().UnixMilli()) + `}`
	allowed := strings.Replace(denied, "Denied", "Allowed", 1)
	req := &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{otlpStr("service.name", "openshell-sandbox")}},
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{
			otlpRecord(egressTestBox, "u-1", denied),
			otlpRecord(egressTestBox, "u-1", denied), // redelivered
			otlpRecord(egressTestBox, "u-2", allowed),
			otlpRecord("0a415311-0000-4000-8000-0000000000ff", "u-3", denied), // another box
		}}},
	}}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := collogspb.NewLogsServiceClient(conn).Export(ctx, req); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || runs[0] != egressTestRun {
		t.Fatalf("reports %+v for runs %v, want one for %s", got, runs, egressTestRun)
	}
	r := got[0]
	if r.Host != "example.com" || r.Port != 443 || r.Rule != string(sandboxnet.RefusalAllowListMiss) || r.Key != sandboxnet.KeyEgressAllowHosts || r.AtMS == 0 {
		t.Fatalf("report %+v", r)
	}
}

func jsonInt(v int64) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// TestOpenShellRecordSandboxID: the helper asks until the gateway answers
// with an id, then writes it; a box that never answers writes nothing.
func TestOpenShellRecordSandboxID(t *testing.T) {
	old := openShellBoxIDPoll
	openShellBoxIDPoll = 10 * time.Millisecond
	t.Cleanup(func() { openShellBoxIDPoll = old })
	dir := t.TempDir()
	calls := 0
	get := func(context.Context) ([]byte, error) {
		calls++
		if calls < 3 {
			return nil, errors.New("not yet")
		}
		return []byte(`{"id":"` + egressTestBox + `"}`), nil
	}
	if err := openShellRecordSandboxID(context.Background(), get, dir); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, openShellSandboxIDFile))
	if err != nil || strings.TrimSpace(string(b)) != egressTestBox {
		t.Fatalf("recorded %q %v", b, err)
	}
	empty := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := openShellRecordSandboxID(ctx, func(context.Context) ([]byte, error) { return []byte(`{}`), nil }, empty); err == nil {
		t.Fatal("no id, yet recorded")
	}
	if _, err := os.Stat(filepath.Join(empty, openShellSandboxIDFile)); !os.IsNotExist(err) {
		t.Fatalf("a file without an id: %v", err)
	}
}

// TestOpenShellBoxIDGetterUsesTheRunTarget (lane OC item 1): the host
// helper's `sandbox get` runs through the run's pinned target, so a managed
// run's get carries the private gateway's config home and never inherits
// the user's own registry or active gateway; an external run's get keeps
// the user's environment.
func TestOpenShellBoxIDGetterUsesTheRunTarget(t *testing.T) {
	const cfgHome = "/run/user/1000/observer-openshell-0123456789ab/cli"
	t.Setenv("XDG_CONFIG_HOME", "/home/dev/.config")
	t.Setenv("OPENSHELL_GATEWAY", "mine")
	cases := []struct {
		name    string
		target  sandboxopenshell.Target
		wantEnv string
		notEnv  []string
	}{
		{
			name: "managed", target: sandboxopenshell.Target{Gateway: "observer-0123456789ab", ConfigHome: cfgHome},
			wantEnv: "XDG_CONFIG_HOME=" + cfgHome, notEnv: []string{"XDG_CONFIG_HOME=/home/dev/.config", "OPENSHELL_GATEWAY=mine"},
		},
		{
			name: "external", target: sandboxopenshell.Target{Gateway: "openshell"},
			notEnv: []string{"XDG_CONFIG_HOME=" + cfgHome},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := healthyOpenShell()
			f.answer = func(prog string, args []string) (extrun.ExecFacts, bool) {
				if prog == "openshell" && slices.Contains(args, "get") {
					return extrun.ExecFacts{Stdout: []byte(`{"id":"` + egressTestBox + `"}`), PeakChildren: -1}, true
				}
				return extrun.ExecFacts{}, false
			}
			r, ex := f.runner()
			pf := openShellPlanFile{Version: openShellPlanVersion, RunID: egressTestRun, Target: tc.target, Name: sandboxopenshell.SandboxName("run-0000-oc")}
			get := openShellBoxIDGetter(r, pf)
			if get == nil {
				t.Fatal("no getter for a valid plan")
			}
			b, err := get(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if id, ok := sandboxopenshell.ParseSandboxID(b); !ok || id != egressTestBox {
				t.Fatalf("answer %q", b)
			}
			calls := ex.Calls()
			if len(calls) != 1 || !slices.Contains(calls[0].Args, "get") || !slices.Contains(calls[0].Args, tc.target.Gateway) {
				t.Fatalf("calls %+v", calls)
			}
			if tc.wantEnv != "" && !slices.Contains(calls[0].Env, tc.wantEnv) {
				t.Fatalf("env %v lacks %q", calls[0].Env, tc.wantEnv)
			}
			for _, bad := range tc.notEnv {
				if slices.Contains(calls[0].Env, bad) {
					t.Fatalf("env %v carries %q", calls[0].Env, bad)
				}
			}
		})
	}
	if openShellBoxIDGetter(nil, openShellPlanFile{Name: "x"}) != nil {
		t.Fatal("an unpinned plan got a getter")
	}
}

// egressTestIngest is an ingest over a run dir with a recorded box, its
// sink capturing reports.
func egressTestIngest(t *testing.T, re sandboxopenshell.RunEgress) (*openShellOCSFIngest, string, func() []sandboxrelay.EgressRefusalReport) {
	t.Helper()
	stateDir := t.TempDir()
	egressTestRunDir(t, stateDir, egressTestRun, egressTestBox, re)
	var mu sync.Mutex
	var got []sandboxrelay.EgressRefusalReport
	g := newOpenShellOCSFIngest(stateDir, t.TempDir(), nil)
	g.sink = func() func(sandboxrelayd.RunRecord, sandboxrelay.EgressRefusalReport) {
		return func(_ sandboxrelayd.RunRecord, r sandboxrelay.EgressRefusalReport) {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, r)
		}
	}
	return g, stateDir, func() []sandboxrelay.EgressRefusalReport {
		mu.Lock()
		defer mu.Unlock()
		return append([]sandboxrelay.EgressRefusalReport(nil), got...)
	}
}

func egressTestExport(box, uid, gateway, host string) *collogspb.ExportLogsServiceRequest {
	res := []*commonpb.KeyValue{otlpStr("service.name", "openshell-sandbox")}
	if gateway != "" {
		res = append(res, otlpStr("openshell.gateway.name", gateway))
	}
	body := `{"class_uid":4001,"action":"Denied","dst_endpoint":{"domain":"` + host + `","port":443}}`
	return &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource:  &resourcepb.Resource{Attributes: res},
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{otlpRecord(box, uid, body)}}},
	}}}
}

// egressTestLog is a concurrency-safe log buffer for an ingest's logger.
type egressTestLog struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *egressTestLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *egressTestLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// TestOpenShellOCSFGatewayName is audit finding O3-V3 (superseding the
// O3-A2 drop): a record whose openshell.gateway.name differs from the
// run's pinned name is still recorded, because the CLI's registered name
// and the gateway's own name are not shown equal; the first event of the
// run logs whether the names match, which live register O3-L1 records.
func TestOpenShellOCSFGatewayName(t *testing.T) {
	g, _, got := egressTestIngest(t, sandboxopenshell.RunEgress{Tier: vocab.TierInternet, Hosts: []string{"api.github.com"}, Gateway: "openshell"})
	var log egressTestLog
	g.logger = slog.New(slog.NewTextHandler(&log, nil))
	ctx := context.Background()
	_ = g.handle(ctx, egressTestExport(egressTestBox, "g-1", "other-gateway", "example.net"))
	_ = g.handle(ctx, egressTestExport(egressTestBox, "g-2", "openshell", "example.com"))
	_ = g.handle(ctx, egressTestExport(egressTestBox, "g-3", "", "example.org"))
	r := got()
	if len(r) != 3 {
		t.Fatalf("reports %+v, want all three recorded", r)
	}
	out := log.String()
	if strings.Count(out, "first OCSF event of the run") != 1 || !strings.Contains(out, "gateway_names_match=false") || !strings.Contains(out, "event_gateway=other-gateway") {
		t.Fatalf("log %q: want one first-event line naming the mismatch", out)
	}
}

// TestOpenShellOCSFEarlyDenialIsHeld is audit finding O3-A7: a denial that
// arrives before the host helper recorded the box id is held and delivered
// once the id is there, and its uid is not consumed by the miss.
func TestOpenShellOCSFEarlyDenialIsHeld(t *testing.T) {
	old := openShellOCSFRetry
	openShellOCSFRetry = 20 * time.Millisecond
	t.Cleanup(func() { openShellOCSFRetry = old })
	g, stateDir, got := egressTestIngest(t, sandboxopenshell.RunEgress{Tier: vocab.TierInternet, Hosts: []string{"api.github.com"}})
	late := "0a415311-0000-4000-8000-00000000cafe"
	ctx := context.Background()
	_ = g.handle(ctx, egressTestExport(late, "e-1", "", "early.example"))
	// The id appears after the first look (well inside a second, so the
	// ordinary rescan bound alone would have missed it).
	egressTestRunDir(t, stateDir, "-RunSENTINEL0000_late", late, sandboxopenshell.RunEgress{Tier: vocab.TierInternet, Hosts: []string{"api.github.com"}})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && len(got()) == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	r := got()
	if len(r) != 1 || r[0].Host != "early.example" {
		t.Fatalf("reports %+v, want the held early denial", r)
	}
	// The same uid was not consumed by the miss: a redelivery of it is now
	// a duplicate only because it was delivered once.
	_ = g.handle(ctx, egressTestExport(late, "e-1", "", "early.example"))
	if len(got()) != 1 {
		t.Fatalf("a redelivered uid landed twice: %+v", got())
	}
}

// egressTestExportN is one export carrying n denials of box (uids and
// hosts numbered from base).
func egressTestExportN(box string, base, n int) *collogspb.ExportLogsServiceRequest {
	var recs []*logspb.LogRecord
	for i := 0; i < n; i++ {
		id := strconv.Itoa(base + i)
		recs = append(recs, otlpRecord(box, "n-"+box+"-"+id, `{"class_uid":4001,"action":"Denied","dst_endpoint":{"domain":"h`+id+`.example","port":443}}`))
	}
	return &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{ScopeLogs: []*logspb.ScopeLogs{{LogRecords: recs}}}}}
}

// TestOpenShellOCSFJunkCannotStarveARun reproduces audit finding O3-V1's
// probe: empty and junk exports, and another run's flood, in the same
// second never cost a run its denials; a run past its own bound loses only
// the excess, which the summary logs as one line for that run.
func TestOpenShellOCSFJunkCannotStarveARun(t *testing.T) {
	g, stateDir, got := egressTestIngest(t, sandboxopenshell.RunEgress{Tier: vocab.TierInternet, Hosts: []string{"api.github.com"}})
	noisy := "0a415311-0000-4000-8000-00000000f00d"
	egressTestRunDir(t, stateDir, "-RunSENTINEL0000_noisy", noisy, sandboxopenshell.RunEgress{Tier: vocab.TierInternet})
	var log egressTestLog
	g.logger = slog.New(slog.NewTextHandler(&log, nil))
	fixed := time.Unix(1793000000, 0)
	g.now = func() time.Time { return fixed }
	ctx := context.Background()
	// The probe: 50 empty exports, then junk, then one real denial.
	for i := 0; i < 50; i++ {
		_ = g.handle(ctx, &collogspb.ExportLogsServiceRequest{})
	}
	for i := 0; i < 200; i++ {
		_ = g.handle(ctx, &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{otlpRecord(egressTestBox, "j-"+strconv.Itoa(i), "not json")}}}}}})
	}
	// Another run floods well past its own bound in the same second.
	_ = g.handle(ctx, egressTestExportN(noisy, 0, openShellOCSFPerRunPerSecond+250))
	_ = g.handle(ctx, egressTestExport(egressTestBox, "real-1", "", "example.com"))
	mine, theirs := 0, 0
	for _, r := range got() {
		if r.Host == "example.com" {
			mine++
		} else {
			theirs++
		}
	}
	if mine != 1 {
		t.Fatalf("the run's real denial landed %d times, want once", mine)
	}
	if theirs != openShellOCSFPerRunPerSecond {
		t.Fatalf("the noisy run landed %d, want its bound %d", theirs, openShellOCSFPerRunPerSecond)
	}
	g.summarize()
	out := log.String()
	if strings.Count(out, "OCSF denials of the run were dropped") != 1 || !strings.Contains(out, "run=-RunSENTINEL0000_noisy") || !strings.Contains(out, "dropped=250") {
		t.Fatalf("summary %q: want one line for the noisy run with dropped=250", out)
	}
}

// egressFakeID is the i-th made-up box id.
func egressFakeID(i int) string {
	return "0a415311-0000-4000-8000-" + strings.Repeat("0", 12-len(strconv.Itoa(i))) + strconv.Itoa(i)
}

// egressHeld reports how many entries the hold keeps and whether one of
// them is box id.
func egressHeld(g *openShellOCSFIngest, id string) (int, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	held := false
	for _, p := range g.pending {
		if p.d.SandboxID == id {
			held = true
		}
	}
	return len(g.pending), held
}

// TestOpenShellOCSFHoldIsFair is audit findings O3-V2 and O3-W1: neither
// one export of 256 made-up box ids, nor 600 made-up ids sent one each
// (the W1 probe: a local sender takes a new source port per connection,
// which the hold no longer keys on), nor ids that pile up entries, can
// evict a real box's early denial held before them; every drop is counted;
// the real one is delivered once its id is recorded.
func TestOpenShellOCSFHoldIsFair(t *testing.T) {
	old := openShellOCSFRetry
	openShellOCSFRetry = time.Hour // retried by hand below
	t.Cleanup(func() { openShellOCSFRetry = old })
	g, stateDir, got := egressTestIngest(t, sandboxopenshell.RunEgress{Tier: vocab.TierInternet, Hosts: []string{"api.github.com"}})
	now := time.Unix(1793000000, 0)
	g.now = func() time.Time { return now }
	ctx := context.Background()
	real := "0a415311-0000-4000-8000-00000000beaf"
	_ = g.handle(ctx, egressTestExport(real, "r-1", "", "early.example"))
	now = now.Add(10 * time.Millisecond)
	flood := &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{ScopeLogs: []*logspb.ScopeLogs{{}}}}}
	for i := 0; i < 256; i++ {
		flood.ResourceLogs[0].ScopeLogs[0].LogRecords = append(flood.ResourceLogs[0].ScopeLogs[0].LogRecords, otlpRecord(egressFakeID(i), "f-"+strconv.Itoa(i), `{"class_uid":4001,"action":"Denied","dst_endpoint":{"domain":"x.example","port":443}}`))
	}
	_ = g.handle(ctx, flood)
	// The W1 probe: 600 more made-up ids, one export (one connection) each.
	for i := 0; i < 600; i++ {
		now = now.Add(time.Millisecond)
		_ = g.handle(ctx, egressTestExport(egressFakeID(1000+i), "w-"+strconv.Itoa(i), "", "x.example"))
	}
	n, held := egressHeld(g, real)
	if !held || n != openShellOCSFHoldTotal {
		t.Fatalf("after the single-entry flood: hold %d, real one held %v", n, held)
	}
	g.mu.Lock()
	counted := g.unattributed
	g.mu.Unlock()
	if want := 1 + 256 + 600 - openShellOCSFHoldTotal; counted != want {
		t.Fatalf("%d drops counted, want %d", counted, want)
	}
	// Ids that pile up entries evict themselves first.
	for sec := 1; sec <= 4; sec++ {
		now = now.Add(time.Second)
		for c := 0; c < 40; c++ {
			_ = g.handle(ctx, egressTestExportN(egressFakeID(5000+c), sec*100, 32))
		}
	}
	if n, held := egressHeld(g, real); !held || n > openShellOCSFHoldTotal {
		t.Fatalf("after the piling flood: hold %d, real one held %v", n, held)
	}
	egressTestRunDir(t, stateDir, "-RunSENTINEL0000_real", real, sandboxopenshell.RunEgress{Tier: vocab.TierInternet, Hosts: []string{"api.github.com"}})
	g.retry()
	found := false
	for _, r := range got() {
		if r.Host == "early.example" {
			found = true
		}
	}
	if !found {
		t.Fatal("the real box's early denial was not delivered")
	}
}

// TestOpenShellOCSFReholdIsBoundedAndCounted (audit finding O3-W1): a
// retry pass that finds the hold refilled puts its older entry back by the
// same eviction rule (a newer single-entry id goes, never the older one),
// and every drop is counted, the expired ones included.
func TestOpenShellOCSFReholdIsBoundedAndCounted(t *testing.T) {
	old := openShellOCSFRetry
	openShellOCSFRetry = time.Hour
	t.Cleanup(func() { openShellOCSFRetry = old })
	g, _, _ := egressTestIngest(t, sandboxopenshell.RunEgress{Tier: vocab.TierInternet})
	now := time.Unix(1793000000, 0)
	g.now = func() time.Time { return now }
	older := openShellOCSFPending{d: sandboxopenshell.OCSFDenial{SandboxID: egressFakeID(1), Host: "early.example"}, first: now}
	now = now.Add(time.Second)
	for i := 0; i < openShellOCSFHoldTotal; i++ {
		g.hold(sandboxopenshell.OCSFDenial{SandboxID: egressFakeID(100 + i), Host: "x.example"})
	}
	g.rehold(older)
	if n, held := egressHeld(g, egressFakeID(1)); !held || n != openShellOCSFHoldTotal {
		t.Fatalf("rehold into a full hold: %d entries, older kept %v", n, held)
	}
	if n, held := egressHeld(g, egressFakeID(100+openShellOCSFHoldTotal-1)); held || n != openShellOCSFHoldTotal {
		t.Fatal("the newest single-entry id was not the one evicted")
	}
	g.mu.Lock()
	counted := g.unattributed
	g.mu.Unlock()
	if counted != 1 {
		t.Fatalf("%d drops counted, want the one eviction", counted)
	}
	// Every held entry expires unclaimed on the next pass: all counted.
	now = now.Add(openShellOCSFPendingTTL + time.Second)
	g.retry()
	g.mu.Lock()
	counted = g.unattributed
	g.mu.Unlock()
	if counted != 1+openShellOCSFHoldTotal {
		t.Fatalf("%d drops counted after the expiry, want %d", counted, 1+openShellOCSFHoldTotal)
	}
}

// TestOpenShellOCSFDroppedCountReachesTheAudit (audit finding O3-W2): a
// run's denials dropped past its rate bound, and held denials of its box
// dropped before its id was recorded, are written to the refusal audit's
// dropped count for that run (where its rows are read), not only logged.
func TestOpenShellOCSFDroppedCountReachesTheAudit(t *testing.T) {
	old := openShellOCSFRetry
	openShellOCSFRetry = time.Hour
	t.Cleanup(func() { openShellOCSFRetry = old })
	g, stateDir, _ := egressTestIngest(t, sandboxopenshell.RunEgress{Tier: vocab.TierInternet, Hosts: []string{"api.github.com"}})
	var mu sync.Mutex
	drops := map[string]int{}
	g.dropSink = func() func(sandboxrelayd.RunRecord, egressRefusalDropCount) {
		return func(rr sandboxrelayd.RunRecord, n egressRefusalDropCount) {
			mu.Lock()
			defer mu.Unlock()
			drops[rr.RunID] += n.Dropped
		}
	}
	now := time.Unix(1793000000, 0)
	g.now = func() time.Time { return now }
	ctx := context.Background()
	// Past the known run's bound: 30 dropped.
	_ = g.handle(ctx, egressTestExportN(egressTestBox, 0, openShellOCSFPerRunPerSecond+30))
	// A box not recorded yet piles 20 denials into the hold: 4 past its
	// per-id bound are dropped, then its id is recorded.
	late := "0a415311-0000-4000-8000-00000000d00d"
	_ = g.handle(ctx, egressTestExportN(late, 1000, openShellOCSFHoldPerBox+4))
	egressTestRunDir(t, stateDir, "-RunSENTINEL0000_late", late, sandboxopenshell.RunEgress{Tier: vocab.TierInternet})
	g.summarize()
	mu.Lock()
	defer mu.Unlock()
	if drops[egressTestRun] != 30 || drops["-RunSENTINEL0000_late"] != 4 || len(drops) != 2 {
		t.Fatalf("dropped counts %v", drops)
	}
}
