package sandboxmxc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

func samplePlan() RunPlan {
	return RunPlan{
		RunID: "r1abc",
		// The run's tool (claude-code) needs user32.dll (NeedsWin32k).
		NeedsWin32k: true,
		Argv:        []string{`C:\Program Files\Observer\observer.exe`, "claude"},
		Cwd:         `C:\Users\dev\proj`,
		Env:         []string{"PATH=C:\\Windows\\System32", "OBSERVER_SANDBOX=1"},
		ReadWrite:   []string{`C:\Users\dev\proj`, `C:\Users\dev\.claude`, `c:\users\dev\PROJ`},
		ReadOnly:    []string{`C:\Program Files\Observer`},
		Denied:      []string{`C:\Users\dev\.observer`},
		ProxyPort:   50123,
		// The host's real SystemRoot; LOCALAPPDATA in the run's own box
		// directory.
		SystemRoot:   `C:\Windows`,
		LocalAppData: `C:\t\observer-sbx-r1abc\localappdata`,
	}
}

// TestDocumentContract pins the milestone 1 document: contract 1.0.0, the
// processcontainer containment, allowDaclMutation false spelled out, egress
// and private-network ingress denied, host loopback allowed only with a
// port, no runtime proxy (finding L1), telemetry off.
func TestDocumentContract(t *testing.T) {
	t.Parallel()
	d, err := BuildDocument(samplePlan())
	if err != nil {
		t.Fatal(err)
	}
	b, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["version"] != "1.0.0" || m["containment"] != "processcontainer" || m["containerId"] != "observer-r1abc" {
		t.Fatalf("contract fields: %v", m)
	}
	if !strings.Contains(string(b), `"fallback":{"allowDaclMutation":false}`) {
		t.Fatalf("allowDaclMutation must be spelled false: %s", b)
	}
	net := m["network"].(map[string]any)
	if net["egress"].(map[string]any)["default"] != "deny" || net["ingress"].(map[string]any)["hostLoopback"] != "allow" || net["ingress"].(map[string]any)["default"] != "deny" {
		t.Fatalf("network: %v", net)
	}
	if _, ok := m["runtimeConfig"]; ok {
		t.Fatalf("a runtime proxy was declared: %v", m["runtimeConfig"])
	}
	if m["telemetry"].(map[string]any)["enabled"] != false || m["lifecycle"].(map[string]any)["destroyOnExit"] != true {
		t.Fatalf("telemetry/lifecycle: %v", m)
	}
	proc := m["process"].(map[string]any)
	if proc["inheritDefaultEnv"] != false || !strings.HasPrefix(proc["commandLine"].(string), `"C:\Program Files\Observer\observer.exe" claude`) {
		t.Fatalf("process: %v", proc)
	}
	if rw := m["filesystem"].(map[string]any)["readwritePaths"].([]any); len(rw) != 2 {
		t.Fatalf("case-insensitive dedup: %v", rw)
	}

	// No proxy port: no runtime proxy, host loopback denied.
	p := samplePlan()
	p.ProxyPort = 0
	d, _ = BuildDocument(p)
	if d.RuntimeConfig != nil || d.Network.Ingress.HostLoopback != "deny" {
		t.Fatalf("no port: %+v", d)
	}
	// A hand-built document allowing DACL mutation is never encoded.
	d.Fallback.AllowDaclMutation = true
	if _, err := d.Encode(); !errors.Is(err, ErrDaclMutation) {
		t.Fatalf("a DACL-mutating document was encoded: %v", err)
	}
}

// laptopRejected is the network half of the request the lane's driver sent
// and MXC 1.0.1 rejected on the 2026-10-22 laptop run (Windows 11 Home
// 25H2, build 26200.9711): "malformed_request: Configuration parse error:
// ProcessContainer runtimeConfig.networkProxy requires
// network.ingress.default='allow'" (finding L1).
const laptopRejected = `{"version":"1.0.0","containment":"processcontainer","containerId":"observer-probe","fallback":{"allowDaclMutation":false},"filesystem":{},"network":{"egress":{"default":"deny"},"ingress":{"default":"deny","hostLoopback":"allow"}},"runtimeConfig":{"networkProxy":"http://127.0.0.1:9"},"process":{"commandLine":"C:\\Windows\\System32\\cmd.exe /d /c \"exit 0\"","cwd":"C:\\Windows","env":[],"inheritDefaultEnv":false},"lifecycle":{"destroyOnExit":true},"telemetry":{"enabled":false}}`

// TestValidatorRefusesWhatMXCRejected: the combination MXC 1.0.1 rejected
// is refused before it reaches MXC, by its own name, and so is the only
// way MXC would take a proxy (private-network ingress open, beyond every
// tier of the plan).
func TestValidatorRefusesWhatMXCRejected(t *testing.T) {
	t.Parallel()
	var rejected Document
	if err := json.Unmarshal([]byte(laptopRejected), &rejected); err != nil {
		t.Fatal(err)
	}
	if err := rejected.Validate(); !errors.Is(err, ErrNetworkProxy) {
		t.Fatalf("the laptop's rejected request validates: %v", err)
	}
	if _, err := rejected.Encode(); !errors.Is(err, ErrNetworkProxy) {
		t.Fatalf("the laptop's rejected request encodes: %v", err)
	}
	opened := rejected
	opened.Network.Ingress.Default = NetworkActionAllow
	if err := opened.Validate(); !errors.Is(err, ErrNetworkProxy) {
		t.Fatalf("a proxy with open ingress validates: %v", err)
	}
	opened.RuntimeConfig = nil
	if err := opened.Validate(); !errors.Is(err, ErrIngressOpen) {
		t.Fatalf("open private-network ingress validates: %v", err)
	}
	egress := rejected
	egress.RuntimeConfig = nil
	egress.Network.Egress.Default = NetworkActionAllow
	if err := egress.Validate(); !errors.Is(err, ErrEgressOpen) {
		t.Fatalf("open egress validates: %v", err)
	}
	for _, p := range []RunPlan{samplePlan(), {RunID: "probe", Argv: []string{`C:\Windows\System32\cmd.exe`}, ProxyPort: 9, SystemRoot: `C:\Windows`, LocalAppData: probeLAD}} {
		d, err := BuildDocument(p)
		if err != nil || d.Validate() != nil {
			t.Fatalf("a built document is refused: %v", err)
		}
	}
}

// recordedRun, recordedRequestProbe and recordedCheck are the exact
// documents this build sends to MXC: a run (samplePlan), the request probe
// and the create-and-close check (the helper's mxcProbeDocs). They are the
// documents the laptop re-run of psec-probe, create-close and launch-echo
// must see accepted (register WIN-4); until then MXC's acceptance of them
// is owed, and any change to them is a deliberate change of this pin.
//
// The create-and-close document with an empty process.env was refused by
// MXC 1.0.1 on the laptop re-run of 2026-10-22 (WIN-4: Windows 11 Home
// offers the base-container ProcessContainer, the request probe passed):
// "policy_validation: The supplied `process.env` cannot launch a Windows
// process container because it is missing the required variable(s):
// SYSTEMROOT, LOCALAPPDATA". Every document now carries both (the host's
// SystemRoot, and LOCALAPPDATA in the run's own box directory), with
// inheritDefaultEnv still false.
const (
	recordedRun          = `{"version":"1.0.0","containment":"processcontainer","containerId":"observer-r1abc","fallback":{"allowDaclMutation":false},"filesystem":{"readwritePaths":["C:\\Users\\dev\\proj","C:\\Users\\dev\\.claude"],"readonlyPaths":["C:\\Program Files\\Observer"],"deniedPaths":["C:\\Users\\dev\\.observer"]},"processContainer":{"ui":{"isolation":"container","desktopSystemControl":false,"systemSettings":"none","ime":false}},"network":{"egress":{"default":"deny"},"ingress":{"default":"deny","hostLoopback":"allow"}},"process":{"commandLine":"\"C:\\Program Files\\Observer\\observer.exe\" claude","cwd":"C:\\Users\\dev\\proj","env":["PATH=C:\\Windows\\System32","OBSERVER_SANDBOX=1","SYSTEMROOT=C:\\Windows","LOCALAPPDATA=C:\\t\\observer-sbx-r1abc\\localappdata"],"inheritDefaultEnv":false},"ui":{"disable":false,"clipboard":"none","injection":false},"lifecycle":{"destroyOnExit":true},"telemetry":{"enabled":false}}`
	recordedRequestProbe = `{"version":"1.0.0","containment":"processcontainer","containerId":"observer-probe","fallback":{"allowDaclMutation":false},"filesystem":{},"processContainer":{"ui":{"isolation":"container","desktopSystemControl":false,"systemSettings":"none","ime":false}},"network":{"egress":{"default":"deny"},"ingress":{"default":"deny","hostLoopback":"allow"}},"process":{"commandLine":"C:\\Windows\\System32\\cmd.exe /d /c \"exit 0\"","cwd":"C:\\Windows","env":["SYSTEMROOT=C:\\Windows","LOCALAPPDATA=C:\\t\\observer-sbx-probe\\localappdata"],"inheritDefaultEnv":false},"ui":{"disable":true,"clipboard":"none","injection":false},"lifecycle":{"destroyOnExit":true},"telemetry":{"enabled":false}}`
	recordedCheck        = `{"version":"1.0.0","containment":"processcontainer","containerId":"observer-probe","fallback":{"allowDaclMutation":false},"filesystem":{},"processContainer":{"ui":{"isolation":"container","desktopSystemControl":false,"systemSettings":"none","ime":false}},"network":{"egress":{"default":"deny"},"ingress":{"default":"deny","hostLoopback":"deny"}},"process":{"commandLine":"C:\\Windows\\System32\\cmd.exe /d /c \"exit 0\"","cwd":"C:\\Windows","env":["SYSTEMROOT=C:\\Windows","LOCALAPPDATA=C:\\t\\observer-sbx-probe\\localappdata"],"inheritDefaultEnv":false},"ui":{"disable":true,"clipboard":"none","injection":false},"lifecycle":{"destroyOnExit":true},"telemetry":{"enabled":false}}`
	// probeLAD is the probes' LOCALAPPDATA in these pins.
	probeLAD = `C:\t\observer-sbx-probe\localappdata`
)

func TestRecordedRequestDocuments(t *testing.T) {
	t.Parallel()
	enc := func(p RunPlan) string {
		t.Helper()
		d, err := BuildDocument(p)
		if err != nil {
			t.Fatal(err)
		}
		b, err := d.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	cmdExe := `C:\Windows\System32\cmd.exe`
	check, err := ProbeDocument(cmdExe, `C:\Windows`, probeLAD)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := check.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, got, want string }{
		{"run", enc(samplePlan()), recordedRun},
		{"request probe", enc(RunPlan{RunID: "probe", Argv: []string{cmdExe, "/d", "/c", "exit 0"}, Cwd: `C:\Windows`, ProxyPort: 9, SystemRoot: `C:\Windows`, LocalAppData: probeLAD}), recordedRequestProbe},
		{"create-and-close", string(cb), recordedCheck},
	} {
		if c.got != c.want {
			t.Errorf("%s document changed\n got %s\nwant %s", c.name, c.got, c.want)
		}
		if strings.Contains(c.got, "runtimeConfig") || strings.Contains(c.got, `"ingress":{"default":"allow"`) {
			t.Errorf("%s document carries what MXC 1.0.1 rejected or what the plan forbids: %s", c.name, c.got)
		}
	}
}

func TestDocumentRefusals(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		mut  func(*RunPlan)
		want error
	}{
		{"empty argv", func(p *RunPlan) { p.Argv = nil }, ErrEmptyCommand},
		{"bad run id", func(p *RunPlan) { p.RunID = "a/b" }, ErrBadRunID},
		{"relative path", func(p *RunPlan) { p.ReadWrite = []string{`proj`} }, ErrBadPath},
		{"unc path", func(p *RunPlan) { p.ReadOnly = []string{`\\server\share`} }, ErrBadPath},
		{"device path", func(p *RunPlan) { p.ReadOnly = []string{`\\?\C:\x`} }, ErrBadPath},
		{"parent walk", func(p *RunPlan) { p.ReadWrite = []string{`C:\Users\dev\..\elsewhere`} }, ErrBadPath},
		{"stream syntax", func(p *RunPlan) { p.ReadWrite = []string{`C:\a:b`} }, ErrBadPath},
		{"bad cwd", func(p *RunPlan) { p.Cwd = `proj` }, ErrBadPath},
		{"bad env", func(p *RunPlan) { p.Env = []string{"NOEQUALS"} }, ErrBadEnv},
		{"bad port", func(p *RunPlan) { p.ProxyPort = 70000 }, ErrBadPort},
		{"no system root", func(p *RunPlan) { p.SystemRoot = "" }, ErrNoWindowsEnv},
		{"no local app data", func(p *RunPlan) { p.LocalAppData = "" }, ErrNoWindowsEnv},
		{"relative local app data", func(p *RunPlan) { p.LocalAppData = `box\localappdata` }, ErrNoWindowsEnv},
	}
	for _, c := range cases {
		p := samplePlan()
		c.mut(&p)
		if _, err := BuildDocument(p); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}

func TestCommandLineQuoting(t *testing.T) {
	t.Parallel()
	cases := []struct {
		argv []string
		want string
	}{
		{[]string{"a", "b"}, `a b`},
		{[]string{"a b"}, `"a b"`},
		{[]string{""}, `""`},
		{[]string{`a"b`}, `"a\"b"`},
		{[]string{`a\"b`}, `"a\\\"b"`},
		{[]string{`C:\dir with space\`}, `"C:\dir with space\\"`},
		{[]string{`C:\no\space\`}, `C:\no\space\`},
	}
	for _, c := range cases {
		if got := CommandLine(c.argv); got != c.want {
			t.Errorf("%q: got %s, want %s", c.argv, got, c.want)
		}
	}
}

func TestCheckVersion(t *testing.T) {
	t.Parallel()
	cases := map[string]VersionStatus{
		"1.0.0": VersionTested, "1.0.1": VersionTested, "v1.0.1": VersionTested,
		"1.0.3": VersionBeta, "1.1.0": VersionBeta, "2.0.0": VersionBeta,
		"0.9.9": VersionUntested, "": VersionUntested, "1.0": VersionUntested, "x.y.z": VersionUntested,
		"1.0.1-rc1": VersionTested,
	}
	for v, want := range cases {
		if got := CheckVersion(v, Pins); got != want {
			t.Errorf("%q: got %s, want %s", v, got, want)
		}
	}
}

func TestCheckBuild(t *testing.T) {
	t.Parallel()
	cases := []struct {
		build, ubr int
		ok         bool
	}{
		{0, 0, false},
		{22631, 4000, false},
		{26100, 9277, false},
		{26100, 9278, true},
		{26200, 9168, false},
		{26200, 9278, true},
		{26200, 9711, true},
		{26150, 9999, false},
		{26300, 9549, false},
		{26300, 9550, true},
		{27000, 1, false},
		{28000, 2803, false},
		{28000, 2804, true},
		{29000, 1, true},
	}
	for _, c := range cases {
		v := CheckBuild(c.build, c.ubr)
		if v.OK() != c.ok {
			t.Errorf("%d.%d: got %v", c.build, c.ubr, v)
		}
		if !v.OK() && v.Code != VerdictPSECBuildTooOld {
			t.Errorf("%d.%d: code %s", c.build, c.ubr, v.Code)
		}
	}
}

// goodFacts is a host where every row passes.
func goodFacts() HostFacts {
	f := HostFacts{Windows: true, Active: true, Build: 26200, UBR: 9711, LibraryVersion: "1.0.1"}
	for _, bf := range ManifestX64.Files {
		f.Files = append(f.Files, FileFact{Name: bf.Name, Present: true, SHA256: bf.SHA256, SignatureChecked: true, Signed: true})
	}
	f.ProbeJSON = `{"tier":"base-container","needsDaclAugmentation":false,"warnings":[],"probes":{"baseContainerApiPresent":true,"baseContainerSupportsDenyPaths":true,"baseContainerSupportsIngressHostLoopbackAllow":true,"baseContainerSupportsIdentitylessLoopbackProxy":true,"uiCapabilities":{}}}`
	f.CreateClose = &CreateClose{Ran: true}
	return f
}

// TestProbeLadder is the milestone 1 refusal table: one case per row, each
// with its named verdict.
func TestProbeLadder(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		mut  func(*HostFacts)
		code string
		rule string
	}{
		{"available", func(*HostFacts) {}, VerdictAvailable, "available"},
		{"not windows", func(f *HostFacts) { f.Windows = false }, VerdictUnsupportedPlatform, "platform"},
		{"inactive", func(f *HostFacts) { f.Active = false }, VerdictDisabledByConfig, "active"},
		{"below the floor (the laptop before servicing)", func(f *HostFacts) { f.UBR = 9168 }, VerdictPSECBuildTooOld, "build"},
		{"missing dll", func(f *HostFacts) { f.Files[0].Present = false }, VerdictArtifactMissing, "files_present"},
		{"missing exec", func(f *HostFacts) { f.Files = f.Files[:1] }, VerdictArtifactMissing, "files_present"},
		{"hash mismatch", func(f *HostFacts) { f.Files[0].SHA256 = strings.Repeat("0", 64) }, VerdictArtifactUnverified, "files_hash"},
		{"unsigned dll", func(f *HostFacts) { f.Files[0].Signed = false; f.Files[0].SignatureError = "TRUST_E_NOSIGNATURE" }, VerdictArtifactUnverified, "files_signed"},
		{"signature unchecked", func(f *HostFacts) { f.Files[1].SignatureChecked = false }, VerdictArtifactUnverified, "files_signed"},
		{"library load failed", func(f *HostFacts) { f.LibraryError = "LoadLibraryEx: 126" }, VerdictProbeFailed, "library"},
		{"version below the minimum", func(f *HostFacts) { f.LibraryVersion = "0.9.0" }, VerdictBackendVersionUntested, "version"},
		{"contract mismatch", func(f *HostFacts) { f.ProbeError = "malformed_request: unsupported version \"1.0.0\"" }, VerdictBackendVersionUntested, "request_probe"},
		{"probe native error", func(f *HostFacts) { f.ProbeError = "backend_unavailable" }, VerdictPSECUnavailable, "request_probe"},
		// Live check 2026-10-22 (finding L2): MXC rejected the request this
		// build sent; that is never reported as a missing platform feature.
		{"request rejected", func(f *HostFacts) {
			f.ProbeError = "malformed_request: Configuration parse error: ProcessContainer runtimeConfig.networkProxy requires network.ingress.default='allow'"
		}, VerdictRequestRejected, "request_probe"},
		// A real absence that mentions a version stays psec_unavailable.
		{"absence naming a version", func(f *HostFacts) { f.ProbeError = "backend_unavailable: unsupported on this Windows version" }, VerdictPSECUnavailable, "request_probe"},
		{"probe garbage", func(f *HostFacts) { f.ProbeJSON = "{" }, VerdictProbeFailed, "request_probe"},
		{"psec not offered (Home)", func(f *HostFacts) {
			f.ProbeJSON = `{"tier":"appcontainer-dacl","needsDaclAugmentation":true,"warnings":["no BaseContainer"],"probes":{}}`
		}, VerdictPSECUnavailable, "request_probe"},
		{"no tier at all", func(f *HostFacts) {
			f.ProbeJSON = `{"warnings":[],"probes":{},"error":"BaseContainer API absent"}`
		}, VerdictPSECUnavailable, "request_probe"},
		{"needs dacl", func(f *HostFacts) {
			f.ProbeJSON = strings.Replace(f.ProbeJSON, `"needsDaclAugmentation":false`, `"needsDaclAugmentation":true`, 1)
		}, VerdictPSECUnavailable, "request_probe"},
		{"no host loopback allow", func(f *HostFacts) {
			f.ProbeJSON = strings.Replace(f.ProbeJSON, `"baseContainerSupportsIngressHostLoopbackAllow":true`, `"baseContainerSupportsIngressHostLoopbackAllow":false`, 1)
		}, VerdictPSECUnavailable, "request_probe"},
		{"create-and-close not run", func(f *HostFacts) { f.CreateClose = nil }, VerdictProbeFailed, "create_close"},
		{"create-and-close failed", func(f *HostFacts) { f.CreateClose = &CreateClose{Ran: true, Status: 4, Error: "backend_unavailable"} }, VerdictPSECUnavailable, "create_close"},
		{"create-and-close rejected", func(f *HostFacts) {
			f.CreateClose = &CreateClose{Ran: true, Status: 1, Error: "malformed_request: Configuration parse error"}
		}, VerdictRequestRejected, "create_close"},
		{"create-and-close policy validation", func(f *HostFacts) {
			f.CreateClose = &CreateClose{Ran: true, Status: 11, Error: laptopPolicyValidation}
		}, VerdictRequestRejected, "create_close"},
		{"create-and-close exit", func(f *HostFacts) { f.CreateClose = &CreateClose{Ran: true, ExitCode: 1} }, VerdictPSECUnavailable, "create_close"},
	}
	seen := map[string]bool{}
	for _, c := range cases {
		f := goodFacts()
		c.mut(&f)
		r := Probe(f, ManifestX64)
		if r.Verdict.Code != c.code || r.Rule != c.rule {
			t.Errorf("%s: got %s at %s (%s), want %s at %s", c.name, r.Verdict.Code, r.Rule, r.Verdict.Reason, c.code, c.rule)
		}
		if !r.Verdict.OK() && r.Verdict.Reason == "" {
			t.Errorf("%s: a refusal without a reason", c.name)
		}
		seen[r.Rule] = true
	}
	for _, rule := range LadderRules() {
		if !seen[rule] {
			t.Errorf("ladder row %s has no case", rule)
		}
	}
	// A beta library version is usable and says so.
	f := goodFacts()
	f.LibraryVersion = "1.0.3"
	if r := Probe(f, ManifestX64); !r.Verdict.OK() || r.VersionStatus != VersionBeta {
		t.Fatalf("beta: %+v", r)
	}
	// The run reaches its port through host loopback, not MXC's proxy: no
	// identity-less proxy is needed (finding L1).
	f = goodFacts()
	f.ProbeJSON = strings.Replace(f.ProbeJSON, `"baseContainerSupportsIdentitylessLoopbackProxy":true`, `"baseContainerSupportsIdentitylessLoopbackProxy":false`, 1)
	if r := Probe(f, ManifestX64); !r.Verdict.OK() || !r.DenyPaths {
		t.Fatalf("no identity-less proxy: %+v", r)
	}
}

// TestProbeThroughStage: a staged live check judges only its stage (finding
// L3): the version stage read mxc_version() and nothing else, so it reports
// the version, not a missing probe answer.
func TestProbeThroughStage(t *testing.T) {
	t.Parallel()
	f := goodFacts()
	f.ProbeJSON, f.CreateClose = "", nil
	r := ProbeThrough(f, ManifestX64, "version")
	if !r.Verdict.OK() || r.Rule != "through:version" || r.Version != "1.0.1" || r.VersionStatus != VersionTested {
		t.Fatalf("version stage: %+v", r)
	}
	if r := Probe(f, ManifestX64); r.Verdict.Code != VerdictProbeFailed || r.Rule != "request_probe" {
		t.Fatalf("the full ladder over the same facts: %+v", r)
	}
	// A failure before the stage's last row still decides.
	f.LibraryVersion = "0.9.0"
	if r := ProbeThrough(f, ManifestX64, "version"); r.Verdict.Code != VerdictBackendVersionUntested || r.Rule != "version" {
		t.Fatalf("old library at the version stage: %+v", r)
	}
	// The request stage ends at the request probe (no create-and-close).
	f = goodFacts()
	f.CreateClose = nil
	if r := ProbeThrough(f, ManifestX64, "request_probe"); !r.Verdict.OK() || r.Rule != "through:request_probe" || r.Tier != TierBaseContainer {
		t.Fatalf("request stage: %+v", r)
	}
}

// TestRunPolicyDenyPaths: a plan that hides a path is refused on a
// BaseContainer that cannot deny paths (finding F4); one that hides nothing
// is not.
func TestRunPolicyDenyPaths(t *testing.T) {
	t.Parallel()
	d, err := BuildDocument(samplePlan())
	if err != nil {
		t.Fatal(err)
	}
	no := false
	po := ProbeOutput{Tier: TierBaseContainer, NeedsDaclAugmentation: &no, Warnings: []string{}}
	if v := CheckRunPolicy(d, po); v.Code != VerdictDenyPathsUnsupported || v.Reason == "" {
		t.Fatalf("hidden paths without deny support: %+v", v)
	}
	po.Probes.BaseContainerSupportsDenyPaths = true
	if v := CheckRunPolicy(d, po); !v.OK() {
		t.Fatalf("with deny support: %+v", v)
	}
	p := samplePlan()
	p.Denied = nil
	d, _ = BuildDocument(p)
	po.Probes.BaseContainerSupportsDenyPaths = false
	if v := CheckRunPolicy(d, po); !v.OK() {
		t.Fatalf("nothing hidden: %+v", v)
	}
	po.Tier = "appcontainer-bfs"
	if v := CheckRunPolicy(d, po); v.Code != VerdictPSECUnavailable {
		t.Fatalf("weaker tier: %+v", v)
	}
	yes := true
	po.Tier, po.NeedsDaclAugmentation = TierBaseContainer, &yes
	if v := CheckRunPolicy(d, po); v.Code != VerdictPSECUnavailable {
		t.Fatalf("dacl augmentation: %+v", v)
	}
	if v := DenyPathsVerdict(0, false); !v.OK() {
		t.Fatal("no hidden path refused")
	}
	// The ladder records the fact for the daemon's early refusal.
	f := goodFacts()
	f.ProbeJSON = strings.Replace(f.ProbeJSON, `"baseContainerSupportsDenyPaths":true`, `"baseContainerSupportsDenyPaths":false`, 1)
	if r := Probe(f, ManifestX64); !r.Verdict.OK() || r.DenyPaths {
		t.Fatalf("deny paths fact: %+v", r)
	}
}

func TestParseProbeOutputStrict(t *testing.T) {
	t.Parallel()
	bad := []string{
		``, `[]`, `{"probes":{}}`,
		`{"tier":"base-container","warnings":[],"probes":{}}`,
		`{"tier":"other","needsDaclAugmentation":false,"warnings":[],"probes":{}}`,
		`{"tier":"base-container","needsDaclAugmentation":false,"warnings":[],"probes":{},"error":"x"}`,
		`{"warnings":[],"probes":{}}`,
		`{"warnings":[],"probes":{},"error":"x","needsDaclAugmentation":true}`,
	}
	for _, b := range bad {
		if _, err := ParseProbeOutput([]byte(b)); err == nil {
			t.Errorf("accepted %s", b)
		}
	}
	if _, err := ParseProbeOutput([]byte(strings.Repeat(" ", maxProbeJSON+1))); err == nil {
		t.Error("accepted an oversized answer")
	}
}

func TestManifestPins(t *testing.T) {
	t.Parallel()
	m, ok := ManifestFor("amd64")
	if !ok || len(m.Files) != 2 || m.Version != "1.0.1" || m.Signer != "Microsoft Corporation" {
		t.Fatalf("manifest: %+v", m)
	}
	for _, f := range m.Files {
		if len(f.SHA256) != 64 || f.Size <= 0 || !strings.HasPrefix(f.PackagePath, "package/bin/x64/") {
			t.Errorf("pin %+v", f)
		}
	}
	if _, ok := ManifestFor("arm64"); ok {
		t.Error("no arm64 set is pinned")
	}
}

func token(t *testing.T) string {
	t.Helper()
	tok, err := EncodeToken([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func basic(tok string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(ProxyUser+":"+tok))
}

// TestPortRouting is the shared-port table (milestone 3, WIN-2's unit
// half): a none token opens no proxy, a proxy_only token no gateway, and a
// wrong token opens nothing.
func TestPortRouting(t *testing.T) {
	t.Parallel()
	tok := token(t)
	other, _ := EncodeToken([]byte(strings.Repeat("z", 32)))
	relay := Request{Method: "GET", RequestURI: "/relay/" + tok, Upgrade: UpgradeRelay}
	oob := Request{Method: "GET", RequestURI: "/oob/" + tok, Upgrade: UpgradeOOB}
	proxy := Request{Method: "POST", RequestURI: "/t/" + tok + "/v1/messages?beta=true"}
	connect := Request{Method: "CONNECT", RequestURI: "example.com:443", ProxyAuthorization: basic(tok)}
	absolute := Request{Method: "GET", RequestURI: "http://example.com/", ProxyAuthorization: basic(tok)}
	cases := []struct {
		name   string
		req    Request
		tier   vocab.Tier
		stream Stream
		status int
	}{
		{"relay on none", relay, vocab.TierNone, StreamRelay, 0},
		{"oob on none", oob, vocab.TierNone, StreamOOB, 0},
		{"proxy on none", proxy, vocab.TierNone, "", 403},
		{"proxy on proxy_only", proxy, vocab.TierProxyOnly, StreamProxy, 0},
		{"gateway on proxy_only", connect, vocab.TierProxyOnly, "", 403},
		{"gateway on internet", connect, vocab.TierInternet, StreamGateway, 0},
		{"absolute form on internet", absolute, vocab.TierInternet, StreamGateway, 0},
		{"host tier opens nothing", relay, vocab.TierHost, "", 403},
		{"gateway without credentials", Request{Method: "CONNECT", RequestURI: "example.com:443"}, vocab.TierInternet, "", 407},
		{"gateway with another token", Request{Method: "CONNECT", RequestURI: "example.com:443", ProxyAuthorization: basic(other)}, vocab.TierInternet, "", 407},
		{"gateway with another user", Request{Method: "CONNECT", RequestURI: "x:443", ProxyAuthorization: "Basic " + base64.StdEncoding.EncodeToString([]byte("root:"+tok))}, vocab.TierInternet, "", 407},
		{"proxy with another token", Request{Method: "POST", RequestURI: "/t/" + other + "/v1/messages"}, vocab.TierInternet, "", 403},
		{"relay with another token", Request{Method: "GET", RequestURI: "/relay/" + other, Upgrade: UpgradeRelay}, vocab.TierInternet, "", 403},
		{"relay without upgrade", Request{Method: "GET", RequestURI: "/relay/" + tok}, vocab.TierInternet, "", 426},
		{"relay with the oob upgrade", Request{Method: "GET", RequestURI: "/relay/" + tok, Upgrade: UpgradeOOB}, vocab.TierInternet, "", 426},
		{"relay by POST", Request{Method: "POST", RequestURI: "/relay/" + tok, Upgrade: UpgradeRelay}, vocab.TierInternet, "", 400},
		{"origin form elsewhere", Request{Method: "GET", RequestURI: "/v1/messages"}, vocab.TierInternet, "", 404},
	}
	for _, c := range cases {
		r := Classify(c.req, tok, c.tier)
		if r.Stream != c.stream || r.Status != c.status {
			t.Errorf("%s: got %+v", c.name, r)
		}
	}
	if r := Classify(proxy, tok, vocab.TierProxyOnly); r.Path != "/v1/messages?beta=true" {
		t.Fatalf("prefix strip: %q", r.Path)
	}
	if r := Classify(relay, "", vocab.TierNone); !r.Refused() {
		t.Fatal("a run with no token opened a stream")
	}
	for _, tier := range Tiers() {
		if !Grants(tier, StreamRelay) {
			t.Errorf("%s does not carry the relay", tier)
		}
	}
	if !strings.HasSuffix(BaseURL(5, tok), "/t/"+tok) || !strings.Contains(GatewayURL(5, tok), ProxyUser+":"+tok+"@127.0.0.1:5") {
		t.Fatal("urls")
	}
	if _, err := EncodeToken([]byte("short")); err == nil {
		t.Fatal("short token")
	}
}

func TestVerdictVocabulary(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, v := range Verdicts() {
		if seen[v] || v == "" {
			t.Fatalf("verdict %q repeated or empty", v)
		}
		seen[v] = true
	}
	if (Verdict{Code: VerdictPSECUnavailable, Reason: "x"}).Error() != "psec_unavailable: x" {
		t.Fatal("error text")
	}
}

// TestManifestMatchesReleaseScript keeps the pins the release job fetches
// and bundles by (scripts/mxc-files.sh) equal to the pins the helper
// checks before it loads anything.
func TestManifestMatchesReleaseScript(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile(filepath.Join("..", "..", "scripts", "mxc-files.sh"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	m := ManifestX64
	for _, want := range []string{
		`MXC_UPSTREAM="` + m.Upstream + `"`, `MXC_VERSION="` + m.Version + `"`,
		`MXC_PKG_URL="` + m.PackageURL + `"`, `MXC_PKG_SHA256="` + m.PackageSHA256 + `"`,
		`MXC_SIGNER="` + m.Signer + `"`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("scripts/mxc-files.sh lacks %s", want)
		}
	}
	for _, f := range m.Files {
		row := fmt.Sprintf(`"%s|%s|%s|%d"`, f.Name, f.PackagePath, f.SHA256, f.Size)
		if !strings.Contains(src, row) {
			t.Errorf("scripts/mxc-files.sh lacks the pin row %s", row)
		}
	}
	if strings.Count(src, "|package/bin/") != len(m.Files) {
		t.Errorf("scripts/mxc-files.sh pins a different file set")
	}
}

// laptopPolicyValidation is MXC 1.0.1's create answer on the laptop re-run
// of 2026-10-22 for a document whose process.env was empty (status 11),
// as the native error renders it (code name, then MXC's message).
const laptopPolicyValidation = "policy_validation: The supplied `process.env` cannot launch a Windows process container because it is missing the required variable(s): SYSTEMROOT, LOCALAPPDATA. MXC uses your `process.env` (an empty environment) verbatim when `process.inheritDefaultEnv` is false ... add the missing variable(s) to `process.env` (any value will do because the Windows requirement is presence-only) or omit `process.env`"

// TestPolicyValidationIsRequestRejected: MXC's policy_validation at create
// is a fault in this build's document, reported request_rejected with
// MXC's own message, never psec_unavailable.
func TestPolicyValidationIsRequestRejected(t *testing.T) {
	t.Parallel()
	f := goodFacts()
	f.CreateClose = &CreateClose{Ran: true, Status: 11, Error: laptopPolicyValidation}
	r := Probe(f, ManifestX64)
	if r.Verdict.Code != VerdictRequestRejected || r.Rule != "create_close" {
		t.Fatalf("got %s at %s", r.Verdict.Code, r.Rule)
	}
	if !strings.Contains(r.Verdict.Reason, "missing the required variable(s): SYSTEMROOT, LOCALAPPDATA") {
		t.Fatalf("the reason does not name MXC's message: %s", r.Verdict.Reason)
	}
}

// TestDocumentWindowsEnv: every document carries SYSTEMROOT (the host's)
// and LOCALAPPDATA (the run's own box directory) with inheritDefaultEnv
// false; a host LOCALAPPDATA or SystemRoot in the plan's environment is
// replaced, never passed on; the validator refuses a document missing
// either and one that inherits the host's environment.
func TestDocumentWindowsEnv(t *testing.T) {
	t.Parallel()
	p := samplePlan()
	p.Env = append(p.Env, `LocalAppData=C:\Users\dev\AppData\Local`, `SystemRoot=D:\Elsewhere`)
	d, err := BuildDocument(p)
	if err != nil {
		t.Fatal(err)
	}
	env := strings.Join(d.Process.Env, "|")
	if strings.Contains(env, `C:\Users\dev\AppData\Local`) || strings.Contains(env, `D:\Elsewhere`) {
		t.Fatalf("a host value reached the box: %s", env)
	}
	if !strings.Contains(env, `SYSTEMROOT=C:\Windows`) || !strings.Contains(env, `LOCALAPPDATA=C:\t\observer-sbx-r1abc\localappdata`) || d.Process.InheritDefaultEnv {
		t.Fatalf("env %s inherit %v", env, d.Process.InheritDefaultEnv)
	}
	for _, drop := range []string{EnvSystemRoot, EnvLocalAppData} {
		bad := d
		bad.Process.Env = nil
		for _, kv := range d.Process.Env {
			if k, _, _ := strings.Cut(kv, "="); k != drop {
				bad.Process.Env = append(bad.Process.Env, kv)
			}
		}
		if err := bad.Validate(); !errors.Is(err, ErrEnvMissing) || !strings.Contains(err.Error(), drop) {
			t.Fatalf("a document without %s validates: %v", drop, err)
		}
		if _, err := bad.Encode(); !errors.Is(err, ErrEnvMissing) {
			t.Fatalf("a document without %s encodes: %v", drop, err)
		}
	}
	inherit := d
	inherit.Process.InheritDefaultEnv = true
	if err := inherit.Validate(); !errors.Is(err, ErrInheritEnv) {
		t.Fatalf("a document inheriting the host environment validates: %v", err)
	}
	var empty Document
	if err := json.Unmarshal([]byte(recordedCheck), &empty); err != nil {
		t.Fatal(err)
	}
	empty.Process.Env = []string{}
	if err := empty.Validate(); !errors.Is(err, ErrEnvMissing) {
		t.Fatalf("the document MXC refused on the laptop (empty process.env) validates: %v", err)
	}
}

// TestBuildDocumentSkipsHiddenWindowsEnv (Windows 11 Pro live run
// 2026-10-22): a process started from cmd or PowerShell carries hidden
// "=C:" and "=ExitCode" entries; the document leaves them out instead of
// refusing the run, and still refuses an entry that is not KEY=VALUE.
func TestBuildDocumentSkipsHiddenWindowsEnv(t *testing.T) {
	t.Parallel()
	p := samplePlan()
	p.Env = append([]string{`=C:=C:\Users\dev\proj`, "=ExitCode=00000001", `=::=::\`}, p.Env...)
	d, err := BuildDocument(p)
	if err != nil {
		t.Fatalf("a shell's environment was refused: %v", err)
	}
	for _, kv := range d.Process.Env {
		if HiddenEnvEntry(kv) {
			t.Errorf("the box's environment keeps %q", kv)
		}
	}
	if !HiddenEnvEntry("=C:=C:\\x") || HiddenEnvEntry("PATH=C:\\x") || HiddenEnvEntry("") {
		t.Fatal("HiddenEnvEntry misjudges an entry")
	}
	p.Env = append(p.Env, "NOEQUALS")
	if _, err := BuildDocument(p); !errors.Is(err, ErrBadEnv) {
		t.Fatalf("an entry that is not KEY=VALUE: %v", err)
	}
}
