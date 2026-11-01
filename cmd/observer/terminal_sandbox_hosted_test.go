//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
	"github.com/marmutapp/superbased-observer/internal/policyfam/terminalsisolation"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxnet"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// fakeHostedKeys is an in-memory keystore.
type fakeHostedKeys struct{ m map[string]string }

func (f *fakeHostedKeys) Get(n string) (string, error) {
	v, ok := f.m[n]
	if !ok {
		return "", keystore.ErrNotFound
	}
	return v, nil
}
func (f *fakeHostedKeys) Set(n, v string) error      { f.m[n] = v; return nil }
func (f *fakeHostedKeys) Delete(n string) error      { delete(f.m, n); return nil }
func (f *fakeHostedKeys) Backend() string            { return "memory" }
func (f *fakeHostedKeys) SecurityDiagnostic() string { return "" }

// hostedTestEnv swaps the keystore and the environment for one test.
func hostedTestEnv(t *testing.T, env map[string]string) *fakeHostedKeys {
	t.Helper()
	keys := &fakeHostedKeys{m: map[string]string{}}
	oldOpen, oldEnv := hostedKeystoreOpen, hostedLookupEnv
	hostedKeystoreOpen = func(string, string) keystore.Store { return keys }
	hostedLookupEnv = func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	t.Cleanup(func() { hostedKeystoreOpen, hostedLookupEnv = oldOpen, oldEnv })
	return keys
}

// hostedTestDriver builds a hosted driver over a minimal runtime, with a
// client factory that counts its calls.
func hostedTestDriver(t *testing.T, vendor string, cfg config.TerminalSandboxConfig, calls *int) *hostedDriver {
	t.Helper()
	full := config.Default()
	full.Terminal.Sandbox = cfg
	r := &sandboxRuntime{cfg: cfg, observerDir: t.TempDir(), observerBin: "/usr/local/bin/observer"}
	reg := hostedVendorReg{vendor: vendor, component: "terminals.sandbox." + vendor, newClient: func(sandboxremote.Credential, string) (sandboxremote.Client, error) {
		*calls++
		return nil, errors.New("no vendor in tests")
	}}
	d := newHostedDriver(r, full, reg).(*hostedDriver)
	d.now = func() time.Time { return time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC) }
	return d
}

func hostedTestConfig(backends ...string) config.TerminalSandboxConfig {
	c := config.Default().Terminal.Sandbox
	c.Enabled, c.Backends = true, backends
	return c
}

// TestSandboxRemoteAllowedLine pins the AllowRemote line: true only while
// a hosted row is in the local backends and no org floor forbids it.
func TestSandboxRemoteAllowedLine(t *testing.T) {
	t.Cleanup(func() { hostedListed.Store(false) })
	recordHostedListed(hostedTestConfig("bwrap"))
	if sandboxRemoteAllowed(false) {
		t.Error("allowed with no hosted row listed")
	}
	recordHostedListed(hostedTestConfig("bwrap", sandboxbackend.BackendE2B))
	if !sandboxRemoteAllowed(false) {
		t.Error("not allowed with e2b listed")
	}
	if sandboxRemoteAllowed(true) {
		t.Error("allowed under an org allow_remote = false")
	}
	if !sandboxOrgFloors().AllowRemote {
		t.Error("sandboxOrgFloors does not carry the line with no floor in force")
	}
	if sandboxOrgFloors().InForce() {
		t.Error("AllowRemote alone counted as a floor")
	}
	cfg := hostedTestConfig("bwrap")
	cfg.Enabled = false
	recordHostedListed(cfg)
	if sandboxRemoteAllowed(false) {
		t.Error("allowed with the sandbox off")
	}
}

// TestHostedListedClearedOnRebuild (the SBX-P7 merge's audit finding 8): a
// driver rebuild with no hosted driver active clears the AllowRemote line a
// hosted driver set earlier.
func TestHostedListedClearedOnRebuild(t *testing.T) {
	t.Cleanup(func() { hostedListed.Store(false) })
	hostedListed.Store(true)
	r := &sandboxRuntime{}
	r.buildSandboxDrivers(config.Default())
	if hostedListed.Load() || sandboxRemoteAllowed(false) {
		t.Error("a rebuild with no hosted driver active kept the hosted row listed")
	}
}

// TestHostedProbeLadder walks the local probe ladder row by row: each
// refusal is named, and the probe never builds a client (I6).
func TestHostedProbeLadder(t *testing.T) {
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorE2B)
	cfg := config.Default().Terminal.Sandbox.Hosted
	ok := hostedProbeFacts{listed: true, host: sandboxbackend.HostLinux, credential: sandboxremote.SourceEnv}
	cases := []struct {
		name string
		mut  func(*hostedProbeFacts, *config.TerminalSandboxHostedConfig)
		want string
	}{
		{"available", func(*hostedProbeFacts, *config.TerminalSandboxHostedConfig) {}, sandboxselect.VerdictAvailable},
		{"unlisted", func(f *hostedProbeFacts, _ *config.TerminalSandboxHostedConfig) { f.listed = false }, sandboxselect.VerdictDisabledByConfig},
		{"macos", func(f *hostedProbeFacts, _ *config.TerminalSandboxHostedConfig) { f.host = sandboxbackend.HostMacOS }, sandboxselect.VerdictUnsupportedPlatform},
		{"region", func(_ *hostedProbeFacts, c *config.TerminalSandboxHostedConfig) { c.E2B.Region = "mars-1" }, verdictHostedRegionUnknown},
		{"credential", func(f *hostedProbeFacts, _ *config.TerminalSandboxHostedConfig) { f.credential = "" }, verdictHostedCredentialMissing},
		{"box binary", func(f *hostedProbeFacts, _ *config.TerminalSandboxHostedConfig) { f.boxBinaryErr = errors.New("x") }, verdictHostedBoxBinary},
		{"daily cap", func(f *hostedProbeFacts, _ *config.TerminalSandboxHostedConfig) { f.usedToday = 239 }, sandboxremote.VerdictDailyCapReached},
	}
	for _, c := range cases {
		f, hc := ok, cfg
		c.mut(&f, &hc)
		if got := hostedProbeLadder(v, hc, f); got.Verdict != c.want {
			t.Errorf("%s: verdict %s (%s), want %s", c.name, got.Verdict, got.Reason, c.want)
		}
	}
}

// TestHostedNoVendorCallWithoutUserAction is the I6 invariant for the
// hosted rows: the probe, the status list and every Create refusal run
// without building a client; and statically, a client is built only in the
// host helper (a user-launched run) and the leftover-box actions (a user's
// confirm).
func TestHostedNoVendorCallWithoutUserAction(t *testing.T) {
	skipDriverOffHost(t, "the hosted drivers")
	hostedTestEnv(t, map[string]string{"E2B_API_KEY": "e2b_FAKEKEY_000111"})
	t.Cleanup(func() { hostedListed.Store(false) })
	calls := 0
	cfg := hostedTestConfig(sandboxbackend.BackendE2B)
	cfg.Hosted.KeyCustody = "in_box_api_key"
	d := hostedTestDriver(t, sandboxbackend.BackendE2B, cfg, &calls)
	_ = d.probe(context.Background())
	_ = sandboxBackendListWith(cfg, sandboxAvailForTest(), nil, vocab.TierProxyOnly, map[string]sandboxselect.Probe{sandboxbackend.BackendE2B: d.probe(context.Background())})
	// A real git repository, so the manifest step passes and Create stops
	// at the consent step it is named for (the SBX-P7 merge's audit finding
	// 9; a plain temp dir failed earlier, at the manifest).
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "init", "-q", root).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = d.Create(context.Background(), termsvc.PrepareRequest{Tool: "claude-code", ProjectRoot: root})
	if err == nil {
		t.Fatal("Create passed with no consent")
	}
	if !strings.Contains(err.Error(), verdictHostedConsentRequired) {
		t.Fatalf("Create stopped before the consent step: %v", err)
	}
	if calls != 0 {
		t.Errorf("the vendor client was built %d times without a user action", calls)
	}
	allowed := map[string]bool{"terminal_sandbox_hosted_host.go": true, "terminal_sandbox_hosted_leftovers.go": true}
	files, _ := filepath.Glob("terminal_sandbox_hosted*.go")
	re := regexp.MustCompile(`\.newClient\(`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || allowed[f] {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if re.Match(b) {
			t.Errorf("%s builds a vendor client; only the host helper and the leftover actions may", f)
		}
	}
}

// sandboxAvailForTest is a bwrap probe result for list calls.
func sandboxAvailForTest() sandbox.Availability {
	return sandbox.Availability{Available: true, Verdict: "available", Backend: "bwrap"}
}

// TestHostedCredentialResolution: the keystore first, the environment
// second, bound to its endpoint; values never in an error or a log.
func TestHostedCredentialResolution(t *testing.T) {
	const fake = "e2b_FAKEKEY_9f8e7d6c5b"
	keys := hostedTestEnv(t, map[string]string{"E2B_API_KEY": fake})
	dir := t.TempDir()
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorE2B)
	c, err := hostedResolveCredential(dir, v)
	if err != nil || c.Source != sandboxremote.SourceEnv || c.Endpoint != v.DefaultEndpoint {
		t.Fatalf("env credential: %v %v", c, err)
	}
	if err := sandboxremote.CheckBinding(c, v, "https://api.region-b.example"); !errors.Is(err, sandboxremote.ErrCredentialEndpointMismatch) || strings.Contains(err.Error(), fake) {
		t.Errorf("env credential to another region: %v", err)
	}
	if err := hostedConnectCredential(dir, v, map[string]string{"E2B_API_KEY": "e2b_FAKEKEY_stored_1234"}, "https://api.region-b.example", ""); err != nil {
		t.Fatal(err)
	}
	if hostedCredentialSource(dir, v) != sandboxremote.SourceKeystore {
		t.Error("connected marker not seen")
	}
	c, err = hostedResolveCredential(dir, v)
	if err != nil || c.Source != sandboxremote.SourceKeystore || c.Endpoint != "https://api.region-b.example" {
		t.Fatalf("keystore credential: %v %v", c, err)
	}
	for _, s := range []string{fmt.Sprintf("%v %+v %s", c, c, c)} {
		if strings.Contains(s, "FAKEKEY") {
			t.Errorf("a credential value printed: %s", s)
		}
	}
	if err := hostedDisconnectCredential(dir, v); err != nil {
		t.Fatal(err)
	}
	if len(keys.m) != 0 || hostedCredentialSource(dir, v) != sandboxremote.SourceEnv {
		t.Error("disconnect left the credential or the marker")
	}
	hostedTestEnv(t, nil)
	if _, err := hostedResolveCredential(dir, v); !errors.Is(err, sandboxremote.ErrCredentialMissing) {
		t.Errorf("no credential: %v", err)
	}
}

// TestHostedSpendLedgerAndRecords: the ledger counts reservations per
// provider per day, and a teardown record is removed only after the vendor
// confirmed, with its per-box secret.
func TestHostedSpendLedgerAndRecords(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	if err := hostedUpdateLedger(dir, now, func(l *sandboxremote.Ledger) error {
		l.Reserve(sandboxremote.VendorE2B, sandboxremote.DayOf(now), "r1", 60)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := hostedLedgerUsed(dir, sandboxremote.VendorE2B, now, 240); got != 60 {
		t.Errorf("used %d", got)
	}
	if fi, err := os.Stat(hostedLedgerPath(dir)); err != nil || (posixModes && fi.Mode().Perm() != 0o600) {
		t.Errorf("ledger mode %v %v", fi, err)
	}
	if err := os.WriteFile(hostedLedgerPath(dir), []byte("{bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := hostedLedgerUsed(dir, sandboxremote.VendorE2B, now, 240); got != 240 {
		t.Errorf("a broken ledger counts as the whole cap, got %d", got)
	}
	rec := sandboxremote.NewIntent("run9", sandboxremote.VendorE2B, "https://api.e2b.app", "us-west-1", "run9", now, time.Hour)
	secret, err := hostedSaveBoxSecret(dir, "run9", "envd-token")
	if err != nil {
		t.Fatal(err)
	}
	rec.SecretFiles = []string{secret}
	if err := hostedSaveRecord(dir, rec); err != nil {
		t.Fatal(err)
	}
	if err := hostedRemoveRecord(dir, rec); err == nil {
		t.Error("an intent record was removed before the vendor confirmed")
	}
	if got := hostedLoadRecords(dir); len(got) != 1 || got[0].RunID != "run9" {
		t.Fatalf("records %v", got)
	}
	rec.State = sandboxremote.StateGone
	if err := hostedRemoveRecord(dir, rec); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(secret); !os.IsNotExist(err) {
		t.Error("the per-box secret outlived its record")
	}
}

// TestHostedCreateRefusesByName walks Create's refusals that need no
// vendor: custody, tool delivery, consent and the spend cap.
func TestHostedCreateRefusesByName(t *testing.T) {
	skipDriverOffHost(t, "the hosted drivers")
	hostedTestEnv(t, map[string]string{"E2B_API_KEY": "e2b_FAKEKEY_000111"})
	t.Cleanup(func() { hostedListed.Store(false) })
	calls := 0
	cfg := hostedTestConfig(sandboxbackend.BackendE2B)
	d := hostedTestDriver(t, sandboxbackend.BackendE2B, cfg, &calls)
	_, err := d.Create(context.Background(), termsvc.PrepareRequest{Tool: "claude-code", ProjectRoot: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), sandboxselect.VerdictCustodyUnsatisfiable) {
		t.Errorf("home_relay with no proxy-added key: %v", err)
	}
	if err := hostedCustodyCheck(true, vocab.CustodyHomeRelay); err != nil {
		t.Errorf("home_relay with a key pool: %v", err)
	}
	if err := hostedCustodyCheck(false, vocab.CustodyInBoxOAuthSeed); err == nil {
		t.Error("in_box_oauth_seed accepted before the seed projection exists")
	}
	if _, err := hostedToolDelivery("claude-code", "", vocab.TierProxyOnly, ""); err == nil || !strings.Contains(err.Error(), sandboxselect.VerdictToolUnavailableInImage) {
		t.Errorf("no template on proxy_only: %v", err)
	}
	if argv, err := hostedToolDelivery("claude-code", "", vocab.TierInternet, ""); err != nil || len(argv) == 0 {
		t.Errorf("internet install: %v %v", argv, err)
	}
	if argv, err := hostedToolDelivery("claude-code", "observer-box", vocab.TierNone, ""); err != nil || argv != nil {
		t.Errorf("named template: %v %v", argv, err)
	}
	if calls != 0 {
		t.Errorf("client built %d times", calls)
	}
}

// TestHostedBoxMinutesPlanCap pins S13's timeout side: the box timeout is
// capped at the vendor's shortest documented plan cap.
func TestHostedBoxMinutesPlanCap(t *testing.T) {
	for _, tc := range []struct {
		vendor        string
		planned, want int
	}{
		{sandboxremote.VendorVercel, 60, 45},
		{sandboxremote.VendorVercel, 30, 30},
		{sandboxremote.VendorE2B, 240, 60},
		{sandboxremote.VendorModal, 240, 240},
	} {
		v, _ := sandboxremote.VendorFor(tc.vendor)
		if got := hostedBoxMinutes(v, tc.planned); got != tc.want {
			t.Errorf("%s %d: got %d, want %d", tc.vendor, tc.planned, got, tc.want)
		}
	}
}

// TestHostedPlanFileHoldsNoSecrets: the plan file names variables, never
// values.
func TestHostedPlanFileHoldsNoSecrets(t *testing.T) {
	dir := t.TempDir()
	p, err := writeHostedPlan(dir, hostedPlanFile{Version: hostedPlanVersion, RunID: "r1", Provider: sandboxremote.VendorE2B, Root: "/w/p", ForwardEnv: hostedForwardEnvNames})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if strings.Contains(string(b), "FAKEKEY") || !strings.Contains(string(b), "ANTHROPIC_API_KEY") {
		t.Errorf("plan %s", b)
	}
	plan, err := readHostedPlan(p)
	if err != nil || plan.RunID != "r1" {
		t.Fatalf("%v %v", plan, err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Error("the plan file outlived its read")
	}
}

// sandboxHostedSettingsInventory is the [terminal.sandbox.hosted] inventory:
// its node home is the Hosted sandboxes panel (SandboxHostedPanel.tsx).
var sandboxHostedSettingsInventory = map[string]adminHome{
	"min_session_minutes": {Pin: "terminal.sandbox.hosted.min_session_minutes"},
	"max_run_minutes":     {Pin: "terminal.sandbox.hosted.max_run_minutes"},
	"daily_box_minutes":   {Pin: "terminal.sandbox.hosted.daily_box_minutes"},
	"checkpoint_minutes":  {Pin: "terminal.sandbox.hosted.checkpoint_minutes"},
	"memory_images":       {Pin: "terminal.sandbox.hosted.memory_images"},
	"db_export":           {Pin: "terminal.sandbox.hosted.db_export"},
	// The org floor provider_key_injection removes provider_injected; the
	// other custody values are the developer's choice.
	"key_custody": {Floor: "provider_key_injection"},
	// The per-provider tables: region under the allowed_regions floor,
	// template data, box_binary a machine path.
	"e2b":    {Floor: "allowed_regions"},
	"modal":  {Floor: "allowed_regions"},
	"vercel": {Floor: "allowed_regions"},
}

// TestSandboxHostedSettingsInventory walks [terminal.sandbox.hosted]: every
// key has a row, a node home in the panel and an admin home in this build.
func TestSandboxHostedSettingsInventory(t *testing.T) {
	panel, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "components", "SandboxHostedPanel.tsx"))
	if err != nil {
		t.Fatal(err)
	}
	typ := reflect.TypeOf(config.TerminalSandboxHostedConfig{})
	for i := 0; i < typ.NumField(); i++ {
		key := strings.SplitN(typ.Field(i).Tag.Get("toml"), ",", 2)[0]
		home, ok := sandboxHostedSettingsInventory[key]
		if !ok {
			t.Errorf("[terminal.sandbox.hosted].%s has no inventory row", key)
			continue
		}
		if !strings.Contains(string(panel), key) {
			t.Errorf("[terminal.sandbox.hosted].%s has no node home in the panel", key)
		}
		switch {
		case home.Pin != "":
			if !nodegov.IsPinnableKey(home.Pin) {
				t.Errorf("%s: pin %q is not a settings.pin row", key, home.Pin)
			}
		case home.Floor != "":
			if _, ok := terminalsisolation.LookupFloorKey(home.Floor); !ok {
				t.Errorf("%s: floor %q is not a terminals.isolation key", key, home.Floor)
			}
		default:
			t.Errorf("%s has no admin home", key)
		}
	}
}

// TestHostedVercelTemplateRule (live run 2026-10-23, finding F6: Vercel's
// v3 create starts only a team-owned image, so a runtime name answered 404
// and none and proxy_only could not launch): a Vercel launch below the
// internet tier with no template is refused by name with what Vercel
// needs; the internet tier still installs at first start.
func TestHostedVercelTemplateRule(t *testing.T) {
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorVercel)
	if v.TemplateRule == "" {
		t.Fatal("Vercel names no template rule")
	}
	for _, tier := range []vocab.Tier{vocab.TierNone, vocab.TierProxyOnly} {
		_, err := hostedToolDelivery("claude-code", "", tier, v.TemplateRule)
		if err == nil || !strings.Contains(err.Error(), sandboxselect.VerdictToolUnavailableInImage) || !strings.Contains(err.Error(), "team owns") {
			t.Errorf("%s: %v", tier, err)
		}
	}
	if argv, err := hostedToolDelivery("claude-code", "", vocab.TierInternet, v.TemplateRule); err != nil || len(argv) == 0 {
		t.Errorf("internet: %v %v", argv, err)
	}
	e2b, _ := sandboxremote.VendorFor(sandboxremote.VendorE2B)
	if e2b.TemplateRule != "" {
		t.Errorf("E2B carries a template rule: %s", e2b.TemplateRule)
	}
}

// TestHostedProbeNamesAChangedCap (finding F12: a changed cap read as "no
// recorded consent"): a recorded consent whose cap no longer matches is
// reported as the changed cap, and selection says so.
func TestHostedProbeNamesAChangedCap(t *testing.T) {
	skipDriverOffHost(t, "the hosted drivers")
	hostedTestEnv(t, map[string]string{"E2B_API_KEY": "e2b_FAKEKEY_000111"})
	t.Cleanup(func() { hostedListed.Store(false) })
	calls := 0
	cfg := hostedTestConfig(sandboxbackend.BackendE2B)
	d := hostedTestDriver(t, sandboxbackend.BackendE2B, cfg, &calls)
	static, ok := d.consentFactsStatic()
	if !ok {
		t.Fatal("no static facts")
	}
	static.Tier, static.Capture, static.ScopeKey = "proxy_only", "full", "scope"
	if err := hostedSaveConsent(d.r.observerDir, sandboxremote.NewConsent(static, "2026-10-23T00:00:00Z")); err != nil {
		t.Fatal(err)
	}
	if p := d.probe(context.Background()); !p.ConsentRecorded {
		t.Fatalf("the matching consent was not seen: %+v", p)
	}
	d.cfg.MaxRunMinutes = 5
	p := d.probe(context.Background())
	if p.ConsentRecorded || p.ConsentChange != sandboxremote.ConsentChangedPrefix+"cap" {
		t.Fatalf("probe %+v", p)
	}
	if calls != 0 {
		t.Errorf("client built %d times", calls)
	}
}

// TestHostedRowsUseNoObserverGateway (finding F9: on E2B the metadata
// address answered inside the box): the traffic Observer carries for a
// hosted box never includes the egress gateway (only the hook stream and
// the model proxy), so nothing Observer forwards can reach a metadata
// address; the shared gateway policy refuses link-local and metadata
// addresses anyway; and E2B's row discloses what its own network did.
func TestHostedRowsUseNoObserverGateway(t *testing.T) {
	skipOnWindows(t, "the hosted drivers run their host services on a Linux or WSL2 daemon only")
	for _, tier := range []vocab.Tier{vocab.TierNone, vocab.TierProxyOnly, vocab.TierInternet} {
		if e := hostedHostEgress(tier); e != sandbox.Egress(vocab.TierNone) && e != sandbox.Egress(vocab.TierProxyOnly) {
			t.Errorf("%s: the home side builds %s", tier, e)
		}
		argv, err := sandbox.GuestArgv("/box/observer", sandbox.NetRequest{Egress: hostedHostEgress(tier), ProxyPort: 8820, HostSocketDir: "/tmp/x"})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.Join(argv, " "), "gateway") {
			t.Errorf("%s: the guest forwards a gateway: %v", tier, argv)
		}
	}
	for _, ip := range []string{"169.254.169.254", "169.254.0.1", "fe80::1", "fd00:ec2::254"} {
		if err := sandboxnet.DestinationAllowed(net.ParseIP(ip), nil); err == nil {
			t.Errorf("the gateway policy allows %s", ip)
		}
	}
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorE2B)
	scr := sandboxremote.BuildConsentScreen(v, sandboxremote.ConsentFacts{Provider: v.ID, Region: "us-west-1", Tier: "proxy_only"}, sandboxremote.Manifest{Root: "/w"}, v.EstimateCost(5))
	if !strings.Contains(fmt.Sprint(scr.Lines), "169.254.169.254") {
		t.Errorf("the E2B consent screen does not disclose the metadata address: %v", scr.Lines)
	}
	row, _ := sandboxbackend.Get(sandboxbackend.BackendE2B)
	if !strings.Contains(row.Note, "169.254.169.254") || row.Net.EgressSource[vocab.TierInternet] != vocab.SourceClaimed {
		t.Errorf("the E2B row does not disclose it: %s %v", row.Note, row.Net.EgressSource)
	}
}

// TestBoxRedialWhileTheRelayReopens (finding F7): inside a hosted box a hook
// that finds no relay to connect to tries again within its own budget (the
// home side re-opens the relay after a drop); a request the relay received
// is never repeated; without the hosted marker it fails at once; and the
// budget still ends in a refusal.
func TestBoxRedialWhileTheRelayReopens(t *testing.T) {
	old := boxRedialEvery
	boxRedialEvery = 5 * time.Millisecond
	t.Cleanup(func() { boxRedialEvery = old })
	connectErr := &sandboxrelay.HopError{Hop: sandboxrelay.HopBoxConnect, Detail: "no such file"}
	ctx := context.Background()
	n := 0
	resp, err := boxRedial(ctx, true, func(context.Context) (sandboxrelay.HookResponse, error) {
		if n++; n < 3 {
			return sandboxrelay.HookResponse{}, connectErr
		}
		return sandboxrelay.HookResponse{Exit: 7}, nil
	})
	if err != nil || resp.Exit != 7 || n != 3 {
		t.Errorf("redial: %v %v after %d tries", resp, err, n)
	}
	n = 0
	_, err = boxRedial(ctx, true, func(context.Context) (sandboxrelay.HookResponse, error) {
		n++
		return sandboxrelay.HookResponse{}, &sandboxrelay.HopError{Hop: sandboxrelay.HopBoxClosed}
	})
	if err == nil || n != 1 {
		t.Errorf("a sent request was repeated: %d tries, %v", n, err)
	}
	n = 0
	if _, err = boxRedial(ctx, false, func(context.Context) (sandboxrelay.HookResponse, error) {
		n++
		return sandboxrelay.HookResponse{}, connectErr
	}); err == nil || n != 1 {
		t.Errorf("redial outside a hosted box: %d tries", n)
	}
	tctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if _, err = boxRedial(tctx, true, func(context.Context) (sandboxrelay.HookResponse, error) {
		return sandboxrelay.HookResponse{}, connectErr
	}); err == nil {
		t.Error("a relay that never came back passed")
	}
}
