package superbased

// Go-side tests of the SDK-held credential file beyond the shared cases in
// quickstart_contract_test.go: the parts of the plan the cases leave to each
// SDK (a key never sent to another address, whole records, the expiry
// texts, diagnostics, the Windows rule's facts). Fakes only.

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	fakeHeldKey    = "00000000000000000000000000000001.FAKE-sdk-key-secret-for-contract-tests-only"
	fakeHeldSecret = "FAKE-sdk-key-secret-for-contract-tests-only"
	fakeHeldGW     = "https://u-k7x2.superbased.app"
)

func heldFile(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "superbased", "sdk-credential")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func heldBody(lines ...string) string {
	return strings.Join(append([]string{fakeHeldKey}, lines...), "\n") + "\n"
}

func skipOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("written with unix modes")
	}
}

func TestParseCredentialRecordExtras(t *testing.T) {
	for _, c := range []struct{ text, reason string }{
		{"id.s\nname=caf\xc3\xa9\n", reasonBadNameLine},
		{"id.caf\xc3\xa9\n", reasonBadKeyLine},
		{"id.s\x01\n", reasonBadKeyLine},
		{"\n", reasonBadKeyLine},
		{"id.s\ngateway_url=https://gw.example.com\n\n", reasonBadNameLine},
	} {
		if r, p, reason := parseCredentialRecord([]byte(c.text)); p == "" || r.key != "" || reason != c.reason {
			t.Errorf("%q: (%q, %s), want %s", c.text, p, reason, c.reason)
		}
	}
	if r, _, _ := parseCredentialRecord([]byte(heldBody("destination=ONLINE"))); r.destination != DestinationOnline {
		t.Fatalf("destination case: %+v", r.destination)
	}
	if r, _, _ := parseCredentialRecord([]byte(heldBody("gateway_url="+fakeHeldGW+"/", "dashboard_url=https://u-k7x2.superbased.app/"))); r.gateway != fakeHeldGW || r.dashboardURL != fakeHeldGW {
		t.Fatalf("a trailing slash: %q %q", r.gateway, r.dashboardURL)
	}
	for _, bad := range []string{"id.s\n", "nodot\n", "id.s\ngateway_url=https://gw\nx\n"} {
		_, p, _ := parseCredentialRecord([]byte(bad))
		if strings.Contains(p, "id.s") {
			t.Fatalf("a refusal names the key: %q", p)
		}
	}
}

func TestReadSDKHeldExpiry(t *testing.T) {
	skipOnWindows(t)
	now := time.Date(2027, 4, 1, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		expires string
		expired bool
		want    string
	}{
		{"2027-06-01T00:00:00Z", false, ""},
		{"2027-04-10T00:00:00Z", false, "your SDK key expires on 2027-04-10; run setup again"},
		{"2027-03-01T00:00:00Z", true, "expired on 2027-03-01, so it is not used: run setup again"},
	} {
		p := heldFile(t, heldBody("gateway_url="+fakeHeldGW, "expires_at="+c.expires), 0o600)
		h := readSDKHeld(p, "", now)
		got := strings.Join(h.warnings, "|")
		if !h.ok || h.expired != c.expired || h.usable() == c.expired || (c.want == "" && got != "") || (c.want != "" && !strings.Contains(got, c.want)) {
			t.Errorf("%s: ok=%t expired=%t warnings %q", c.expires, h.ok, h.expired, got)
		}
	}
}

func TestUnderWindowsDir(t *testing.T) {
	base := `C:\Users\me\AppData\Local`
	for _, c := range []struct {
		file string
		want bool
	}{
		{`\\?\C:\Users\me\AppData\Local\superbased\sdk-credential`, true},
		{`c:\users\ME\appdata\local\superbased\sdk-credential`, true},
		{`C:/Users/me/AppData/Local/superbased/sdk-credential`, true},
		{`C:\Users\me\AppData\LocalLow\sdk-credential`, false},
		{`C:\Users\me\AppData\Local`, false},
		{`C:\Users\me\AppData\Local\`, false},
		{`C:\Users\someone\AppData\Local\superbased\sdk-credential`, false},
		{`D:\keys\sdk-credential`, false},
	} {
		if got := underWindowsDir(c.file, base); got != c.want {
			t.Errorf("%s: %t", c.file, got)
		}
	}
	if underWindowsDir(`C:\x`, "") {
		t.Fatal("an empty base contains everything")
	}
}

func TestWindowsFileRule(t *testing.T) {
	if p, r := windowsFileProblem(windowsFacts{insideRoot: true, ownerIsUser: true}); p != "" || r != "" {
		t.Fatalf("ok: %q %q", p, r)
	}
	for _, c := range []struct {
		f      windowsFacts
		reason string
	}{
		{windowsFacts{reparsePoint: true, insideRoot: true, ownerIsUser: true}, reasonReparsePoint},
		{windowsFacts{reparsePoint: true}, reasonReparsePoint},
		{windowsFacts{directory: true, insideRoot: true, ownerIsUser: true}, reasonNotRegular},
		{windowsFacts{ownerIsUser: true}, reasonOutsideLocalAppData},
		{windowsFacts{insideRoot: true}, reasonOwner},
		{windowsFacts{insideRoot: true, ownerError: "cannot read the SDK credential file's owner; refused"}, reasonOwner},
	} {
		if p, r := windowsFileProblem(c.f); p == "" || r != c.reason {
			t.Errorf("%+v: (%q, %s), want %s", c.f, p, r, c.reason)
		}
	}
}

// heldPlan resolves a plan with the SDK-held file at path and, when machine
// is not nil, a machine answering discovery with it.
func heldPlan(t *testing.T, path string, env map[string]string, machine map[string]any, ex explicitInputs) *plan {
	t.Helper()
	setup(t)
	e := map[string]string{EnvCredentialFile: path, "SUPERBASED_DISCOVER": "1", "SUPERBASED_NODE_URL": "http://127.0.0.1:9"}
	for k, v := range env {
		e[k] = v
	}
	real := discover
	discover = func(string) (map[string]any, string) {
		if machine == nil {
			return nil, "no machine (test)"
		}
		return machine, ""
	}
	t.Cleanup(func() { discover = real })
	s, err := resolveSettings(mapEnv(e), Options{APIKey: ex.apiKey, Destination: ex.destination})
	if err != nil {
		t.Fatal(err)
	}
	return resolvePlan(s, mapEnv(e), ex)
}

func machineAnswer(dest string, signedIn bool, credFile string) map[string]any {
	online := map[string]any{}
	if credFile != "" {
		online = map[string]any{"credential_present": true, "credential_file": credFile, "dashboard_url": "https://acme.superbased.app"}
	}
	return map[string]any{
		"api_version": 1, "destination": dest, "signed_in": signedIn,
		"local": map[string]any{"enabled": true}, "online": online, "warnings": []any{},
	}
}

func TestPlanSDKFileRecords(t *testing.T) {
	skipOnWindows(t)
	online := heldBody("gateway_url="+fakeHeldGW, "destination=online", "dashboard_url=https://u-k7x2.superbased.app")

	t.Run("the file's record whole: key, gateway, dashboard, targets", func(t *testing.T) {
		p := heldPlan(t, heldFile(t, online, 0o600), nil, nil, explicitInputs{})
		if p.key != fakeHeldKey || p.gatewayURL != fakeHeldGW || p.onlineDashboard != fakeHeldGW || p.localDashboard != "" {
			t.Fatalf("%s %s %s", p.gatewayURL, p.onlineDashboard, p.localDashboard)
		}
		if len(p.exporters) != 1 || p.exporters[0].endpoint != fakeHeldGW+tracesPath || p.admitURL != fakeHeldGW+sdkAdmitPath {
			t.Fatalf("targets %+v %s", p.exporters, p.admitURL)
		}
	})
	t.Run("the machine's file refused: the SDK-held record is used", func(t *testing.T) {
		mf := writeCred(t, "ik_9a.s3cr3t\ngateway_url=https://gw.example.com\n", 0o644)
		p := heldPlan(t, heldFile(t, online, 0o600), nil, machineAnswer("both", true, mf), explicitInputs{})
		if p.key != fakeHeldKey || p.gatewayURL != fakeHeldGW || p.credentialFrom != sourceSDKFile || p.sdkFile.State != sdkFileUsed {
			t.Fatalf("%s %s %s", p.gatewayURL, p.credentialFrom, p.sdkFile.State)
		}
	})
	t.Run("the machine's key with no gateway line is never paired with the file's gateway", func(t *testing.T) {
		mf := writeCred(t, "ik_9a.s3cr3t\n", 0o600)
		p := heldPlan(t, heldFile(t, online, 0o600), nil, machineAnswer("both", true, mf), explicitInputs{})
		if p.onlineReady || p.gatewayURL != "" || p.credentialFrom != "file" || p.degraded == "" {
			t.Fatalf("%s %s %t", p.gatewayURL, p.credentialFrom, p.onlineReady)
		}
	})
	t.Run("the machine's key wins: discovery's dashboard", func(t *testing.T) {
		mf := writeCred(t, "ik_9a.s3cr3t\ngateway_url=https://gw.example.com\n", 0o600)
		p := heldPlan(t, heldFile(t, online, 0o600), nil, machineAnswer("both", true, mf), explicitInputs{})
		if p.onlineDashboard != "https://acme.superbased.app" || p.localDashboard == "" {
			t.Fatalf("%q %q", p.onlineDashboard, p.localDashboard)
		}
	})
	t.Run("an explicit key takes the file's gateway line, never its dashboard", func(t *testing.T) {
		p := heldPlan(t, heldFile(t, online, 0o600), map[string]string{"SUPERBASED_API_KEY": "ik_env.secret"}, nil, explicitInputs{})
		if p.key != "ik_env.secret" || p.gatewayURL != fakeHeldGW || p.credentialFrom != "env" || p.sdkFile.State != sdkFileUnused || p.onlineDashboard != "" {
			t.Fatalf("%s %s %s %q", p.gatewayURL, p.credentialFrom, p.sdkFile.State, p.onlineDashboard)
		}
	})
	t.Run("the file's key never goes to another named address", func(t *testing.T) {
		p := heldPlan(t, heldFile(t, online, 0o600), map[string]string{"SUPERBASED_ORG_URL": "https://other.example.com"}, nil, explicitInputs{})
		if p.key != "" || p.onlineReady || p.credentialFrom != "" || p.sdkFile.State != sdkFileUnused {
			t.Fatalf("key sent elsewhere: %s %s", p.gatewayURL, p.credentialFrom)
		}
		for _, x := range p.exporters {
			if strings.Contains(x.key(), fakeHeldSecret) {
				t.Fatal("an exporter carries the key")
			}
		}
		if w := strings.Join(p.warnings, "|"); !strings.Contains(w, "not sent there") {
			t.Fatalf("warnings %q", w)
		}
	})
	t.Run("the same named address takes the file's key", func(t *testing.T) {
		p := heldPlan(t, heldFile(t, online, 0o600), map[string]string{"SUPERBASED_ORG_URL": fakeHeldGW + "/"}, nil, explicitInputs{})
		if p.key != fakeHeldKey || !p.onlineReady {
			t.Fatalf("%s %s", p.gatewayURL, p.credentialFrom)
		}
	})
	t.Run("a file with no gateway_url: no gateway, the fix is setup", func(t *testing.T) {
		p := heldPlan(t, heldFile(t, heldBody("destination=online"), 0o600), nil, nil, explicitInputs{})
		if p.destination != DestinationOnline || p.source != sourceSDKFile || p.onlineReady || !strings.Contains(p.degraded, "setup") || !strings.Contains(p.degraded, "gateway address") {
			t.Fatalf("%s %s %q", p.destination, p.source, p.degraded)
		}
	})
	t.Run("a file key never makes the inferred rung", func(t *testing.T) {
		p := heldPlan(t, heldFile(t, heldBody("gateway_url="+fakeHeldGW), 0o600), nil, nil, explicitInputs{})
		if p.destination != DestinationLocal || p.source != "default" || p.key != "" {
			t.Fatalf("%s %s", p.destination, p.source)
		}
	})
	t.Run("diagnostics carry the file, never the key", func(t *testing.T) {
		setup(t)
		path := heldFile(t, online, 0o600)
		t.Setenv(EnvCredentialFile, path)
		memInit(t, Options{Destination: DestinationOnline})
		d := GetDiagnostics()
		if d.CredentialSource != sourceSDKFile || d.SDKFile != (SDKFileInfo{Path: path, State: sdkFileUsed}) || d.DestinationSource != "argument" {
			t.Fatalf("%+v", d)
		}
		memInit(t, Options{Destination: DestinationLocal})
		if d := GetDiagnostics(); d.SDKFile.State != sdkFileNotRead || d.SDKFile.Path != path {
			t.Fatalf("explicit local: %+v", d.SDKFile)
		}
		if strings.Contains(strings.Join(append(d.Warnings, d.Degraded, d.LastError, d.GatewayURL), " "), fakeHeldSecret) {
			t.Fatal("diagnostics carry the key")
		}
	})
	t.Run("a refused file's diagnostics name the rule", func(t *testing.T) {
		p := heldPlan(t, heldFile(t, online, 0o640), nil, nil, explicitInputs{})
		if p.sdkFile.State != sdkFileRefused || p.sdkFile.Reason != reasonMode {
			t.Fatalf("%+v", p.sdkFile)
		}
	})
}

// TestAIGatewayFromTheSDKFile pins SDKQS-10 end to end: the SDK-held file is
// one more source of the org address, and with no SUPERBASED_AI_GATEWAY_KEY
// the client key rule answers no_key, so the SDK key never goes to the AI
// gateway.
func TestAIGatewayFromTheSDKFile(t *testing.T) {
	skipOnWindows(t)
	setup(t)
	t.Setenv(EnvCredentialFile, heldFile(t, heldBody("gateway_url="+fakeHeldGW, "destination=online"), 0o600))
	ep, err := ResolveGateway(GatewayProviderOpenAI, GatewayOptions{})
	if err != nil || ep.Source != GatewaySourceOrg || ep.BaseURL != fakeHeldGW+"/ai/openai/v1" {
		t.Fatalf("%+v %v", ep, err)
	}
	key, err := ep.APIKey()
	var ae *GatewayAddressError
	if key != "" || err == nil || !errors.As(err, &ae) || ae.Problem != GatewayProblemNoKey {
		t.Fatalf("key %q %v", key, err)
	}
	if strings.Contains(err.Error(), fakeHeldSecret) {
		t.Fatal("the refusal names the SDK key")
	}
}
