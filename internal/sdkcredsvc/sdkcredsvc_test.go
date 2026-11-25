package sdkcredsvc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

type fakeMinter struct {
	minted  orgcontract.SDKCredentialMinted
	err     error
	revoked int
	// mintReq and revokeReq record what the machine named (R-B05).
	mintReq, revokeReq []orgcontract.SDKCredentialRequest
}

func (f *fakeMinter) MintSDKCredential(_ context.Context, in orgcontract.SDKCredentialRequest) (orgcontract.SDKCredentialMinted, error) {
	f.mintReq = append(f.mintReq, in)
	return f.minted, f.err
}

func (f *fakeMinter) RevokeSDKCredential(_ context.Context, in orgcontract.SDKCredentialRequest) (orgcontract.SDKCredentialRevoked, error) {
	f.revoked++
	f.revokeReq = append(f.revokeReq, in)
	return orgcontract.SDKCredentialRevoked{Revoked: 1}, f.err
}

func newSvc(t *testing.T) Service {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("no hardened file store on windows")
	}
	return Service{Dir: filepath.Join(t.TempDir(), "sdk")}
}

const secret = "ik_abc.s3cr3tValue"

func TestSignInStoresAHardenedFileAndDescribesItWithoutTheKey(t *testing.T) {
	s := newSvc(t)
	m := &fakeMinter{minted: orgcontract.SDKCredentialMinted{
		CredID: "c1", KeyID: "ik_abc", Credential: secret, OrgID: "o1", WorkspaceID: "default",
		Scopes: []string{"admit"}, Signals: []string{"traces"}, GatewayURL: "https://gw.example.com:4318",
	}}
	st, err := s.SignIn(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if !st.SignedIn || st.CredID != "c1" || st.CredentialFile == "" {
		t.Fatalf("status = %+v", st)
	}
	fi, err := os.Lstat(st.CredentialFile)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("delivery file mode: %v %v", fi, err)
	}
	di, _ := os.Stat(s.Dir)
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %o", di.Mode().Perm())
	}
	body, _ := os.ReadFile(st.CredentialFile)
	if string(body) != secret+"\ngateway_url=https://gw.example.com:4318\n" {
		t.Fatalf("delivery file = %q", body)
	}
	raw, _ := json.Marshal(st)
	if strings.Contains(string(raw), "s3cr3t") {
		t.Fatal("the status must never carry the key")
	}
	cfg := config.Default()
	cfg.Observability.Enabled = true
	d := BuildDiscovery(cfg, st, "http://127.0.0.1:8081")
	raw, _ = json.Marshal(d)
	if strings.Contains(string(raw), "s3cr3t") {
		t.Fatal("the discovery body must never carry the key")
	}
	if d.Destination != "both" || d.Source != "default_signed_in" || d.Online.GatewayURLSource != "credential_file" || !d.Online.CredentialPresent || len(d.Warnings) != 0 {
		t.Fatalf("discovery = %+v", d)
	}
	if d.Local.OTLPTracesURL != "http://127.0.0.1:4318/v1/traces" || d.Local.AdmissionURL != "http://127.0.0.1:8081/api/obs/admission/check" {
		t.Fatalf("local = %+v", d.Local)
	}

	// A loosened file mode stops reading as signed in.
	if err := os.Chmod(st.CredentialFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := s.Status(); got.SignedIn || got.Problem == "" {
		t.Fatalf("a group-readable key file is not a usable sign-in: %+v", got)
	}
	_ = os.Chmod(st.CredentialFile, 0o600)

	n, err := s.SignOut(context.Background(), m, false)
	if err != nil || n != 1 || m.revoked != 1 {
		t.Fatalf("sign-out: %d %v", n, err)
	}
	if _, err := os.Stat(st.CredentialFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("sign-out removes the delivery file")
	}
	if s.Status().SignedIn {
		t.Fatal("signed out")
	}
}

func TestSignInRefusesAMalformedKeyAndStoresNothing(t *testing.T) {
	s := newSvc(t)
	for _, bad := range []string{"", "nodot", "a.b c", ".x", "x."} {
		_, err := s.SignIn(context.Background(), &fakeMinter{minted: orgcontract.SDKCredentialMinted{Credential: bad}})
		if err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	if _, err := os.Stat(s.CredentialFile()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("nothing is stored for a malformed key")
	}
	if _, err := s.SignIn(context.Background(), &fakeMinter{err: errors.New("org down")}); err == nil {
		t.Fatal("an org error is returned")
	}
}

func TestSignOutRemovesLocalCopiesEvenWhenTheOrgFails(t *testing.T) {
	s := newSvc(t)
	if _, err := s.SignIn(context.Background(), &fakeMinter{minted: orgcontract.SDKCredentialMinted{KeyID: "ik_abc", Credential: secret}}); err != nil {
		t.Fatal(err)
	}
	_, err := s.SignOut(context.Background(), &fakeMinter{err: errors.New("unreachable")}, false)
	if err == nil || !strings.Contains(err.Error(), "local copies are removed") {
		t.Fatalf("err = %v", err)
	}
	if s.Status().CredID != "" || s.Status().SignedIn {
		t.Fatal("local copies removed")
	}
}

func TestDiscoveryTable(t *testing.T) {
	cfg := config.Default()
	cases := []struct {
		name        string
		configured  string
		gateway     string
		obsOn       bool
		notBuilt    bool
		signedIn    bool
		destination string
		source      string
		warnings    int
	}{
		{"not signed in defaults local", "", "", true, false, false, "local", "default_not_signed_in", 0},
		{"local with obs off warns", "", "", false, false, false, "local", "default_not_signed_in", 1},
		{"explicit online without a key warns twice", "online", "", true, false, false, "online", "config", 2},
		{"explicit online with a configured gateway, no key", "online", "https://gw.example.com", true, false, false, "online", "config", 1},
		// E-29: a build without AI Apps refuses an app's spans whatever the
		// config says, and says so once (not also "turn it on").
		{"not in this build, obs on in config", "", "", true, true, false, "local", "default_not_signed_in", 1},
		{"not in this build, obs off in config", "", "", false, true, false, "local", "default_not_signed_in", 1},
		{"not in this build, online only: no local warning", "online", "https://gw.example.com", true, true, false, "online", "config", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg.Observability.Enabled = c.obsOn
			cfg.Observability.SDK = config.ObservabilitySDKConfig{Destination: c.configured, GatewayURL: c.gateway}
			old := obsCompiledIn
			obsCompiledIn = func() bool { return !c.notBuilt }
			defer func() { obsCompiledIn = old }()
			d := BuildDiscovery(cfg, Status{SignedIn: c.signedIn, CredentialFile: "/x"}, "http://127.0.0.1:8081")
			if d.Destination != c.destination || d.Source != c.source || len(d.Warnings) != c.warnings || d.APIVersion != 1 {
				t.Fatalf("discovery = %+v", d)
			}
			if d.Local.Compiled != !c.notBuilt || d.Local.Enabled != (c.obsOn && !c.notBuilt) {
				t.Fatalf("local = %+v", d.Local)
			}
			if c.gateway != "" && d.Online.GatewayURLSource != "config" {
				t.Fatalf("gateway source = %q", d.Online.GatewayURLSource)
			}
		})
	}
}

// TestSignInAndOutNameOnlyThisMachinesKey pins review finding R-B05: a
// second sign-in names the key this machine holds, so the org replaces only
// it; a sign-out revokes only it. A first sign-in names none.
func TestSignInAndOutNameOnlyThisMachinesKey(t *testing.T) {
	svc := newSvc(t)
	m := &fakeMinter{minted: orgcontract.SDKCredentialMinted{CredID: "c1", KeyID: "ik_abc", Credential: secret, OrgID: "o"}}
	if _, err := svc.SignIn(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	m.minted = orgcontract.SDKCredentialMinted{CredID: "c2", KeyID: "ik_def", Credential: "ik_def.s3cr3tTwo", OrgID: "o"}
	if _, err := svc.SignIn(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if len(m.mintReq) != 2 || m.mintReq[0].KeyID != "" || m.mintReq[1].KeyID != "ik_abc" {
		t.Fatalf("mint requests = %+v, want none then ik_abc", m.mintReq)
	}
	if _, err := svc.SignOut(context.Background(), m, false); err != nil {
		t.Fatal(err)
	}
	if len(m.revokeReq) != 1 || m.revokeReq[0].KeyID != "ik_def" {
		t.Fatalf("revoke requests = %+v, want only ik_def", m.revokeReq)
	}
}

// TestNoKeyFilePlatformSaysSo pins review finding R-B06's stated limit: on a
// platform with no hardened file store the status and the discovery body say
// that sign-in does not apply, rather than reading as merely signed out.
func TestNoKeyFilePlatformSaysSo(t *testing.T) {
	if runtime.GOOS != "windows" {
		st := Service{Dir: ""}.Status()
		if st.Problem != "" {
			t.Fatalf("an unconfigured directory is not the platform limit: %q", st.Problem)
		}
		return
	}
	st := Service{Dir: t.TempDir()}.Status()
	if st.Problem != NoKeyFileProblem || st.SignedIn {
		t.Fatalf("status %+v", st)
	}
}

// TestSignInValidatesTheOrgGatewayURL pins review E-58: the gateway address
// the organization returns is checked like the config override, and plain
// http is refused unless it names this machine; nothing is stored on a
// refusal.
func TestSignInValidatesTheOrgGatewayURL(t *testing.T) {
	for _, tc := range []struct {
		url string
		ok  bool
	}{
		{"", true},
		{"https://gw.example.com:4318", true},
		{"http://127.0.0.1:4318", true},
		{"http://localhost:4318/", true},
		{"http://[::1]:4318", true},
		{"http://gw.example.com:4318", false},
		{"https://user:pw@gw.example.com", false},
		{"https://gw.example.com/v1/traces", false},
		{"https://gw.example.com/?k=v", false},
		{"ftp://gw.example.com", false},
		{"not a url", false},
	} {
		s := newSvc(t)
		_, err := s.SignIn(context.Background(), &fakeMinter{minted: orgcontract.SDKCredentialMinted{
			CredID: "c1", KeyID: "ik_abc", Credential: secret, OrgID: "o1", GatewayURL: tc.url,
		}})
		if (err == nil) != tc.ok {
			t.Errorf("gateway %q: err = %v, want ok=%v", tc.url, err, tc.ok)
		}
		if !tc.ok {
			if _, serr := os.Stat(s.CredentialFile()); !errors.Is(serr, os.ErrNotExist) {
				t.Errorf("gateway %q: a key was stored on a refused sign-in", tc.url)
			}
		}
	}
}

// TestSignOutWithNoHeldKeyRevokesNothingAtTheOrg pins review E-28 (ruling
// D29): a machine that holds no described key never sends an empty key id
// (which used to end every key of the member); only an explicit all does.
func TestSignOutWithNoHeldKeyRevokesNothingAtTheOrg(t *testing.T) {
	s := newSvc(t)
	m := &fakeMinter{}
	n, err := s.SignOut(context.Background(), m, false)
	if !errors.Is(err, ErrNoHeldKey) || n != 0 || len(m.revokeReq) != 0 {
		t.Fatalf("sign-out with no key: n=%d err=%v requests=%+v", n, err, m.revokeReq)
	}
	n, err = s.SignOut(context.Background(), m, true)
	if err != nil || n != 1 || len(m.revokeReq) != 1 || !m.revokeReq[0].All || m.revokeReq[0].KeyID != "" {
		t.Fatalf("sign-out --all: n=%d err=%v requests=%+v", n, err, m.revokeReq)
	}
	// A held key with all still asks for all (never only the held key).
	if _, err := s.SignIn(context.Background(), &fakeMinter{minted: orgcontract.SDKCredentialMinted{KeyID: "ik_abc", Credential: secret}}); err != nil {
		t.Fatal(err)
	}
	if !s.HoldsKey() {
		t.Fatal("holds the key after sign-in")
	}
	m = &fakeMinter{}
	if _, err := s.SignOut(context.Background(), m, true); err != nil || len(m.revokeReq) != 1 || !m.revokeReq[0].All {
		t.Fatalf("sign-out --all with a held key: %v %+v", err, m.revokeReq)
	}
}

// TestKeyFileCarriesTheGatewayAddress pins review E-04 (ruling D29): the
// address the SDKs send the key to is written into the owner-only key file
// (the machine override when set, else the organization's), and discovery
// reports that address and warns when the override changed after sign-in.
func TestKeyFileCarriesTheGatewayAddress(t *testing.T) {
	s := newSvc(t)
	s.GatewayOverride = "https://override.example.com:4318/"
	m := &fakeMinter{minted: orgcontract.SDKCredentialMinted{KeyID: "ik_abc", Credential: secret, GatewayURL: "https://gw.example.com:4318"}}
	st, err := s.SignIn(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(st.CredentialFile)
	if string(body) != secret+"\ngateway_url=https://override.example.com:4318\n" {
		t.Fatalf("key file = %q", body)
	}
	if st.KeyGatewayURL != "https://override.example.com:4318" {
		t.Fatalf("status gateway = %q", st.KeyGatewayURL)
	}
	cfg := config.Default()
	cfg.Observability.Enabled = true
	cfg.Observability.SDK.GatewayURL = "https://other.example.com"
	d := BuildDiscovery(cfg, st, "http://127.0.0.1:8081")
	if d.Online.GatewayURL != "https://override.example.com:4318" || d.Online.GatewayURLSource != GatewaySourceCredentialFile {
		t.Fatalf("online = %+v", d.Online)
	}
	if !anyContains(d.Warnings, "differs from the address stored with the SDK key") {
		t.Fatalf("warnings = %q", d.Warnings)
	}
	// A plain-http remote override is refused for the key, as the org's is.
	s2 := newSvc(t)
	s2.GatewayOverride = "http://gw.example.com:4318"
	if _, err := s2.SignIn(context.Background(), m); err == nil {
		t.Fatal("a plain-http remote override must not be stored with the key")
	}
	// No address known: the file has the key line only, and discovery says
	// apps cannot send online.
	s3 := newSvc(t)
	st3, err := s3.SignIn(context.Background(), &fakeMinter{minted: orgcontract.SDKCredentialMinted{KeyID: "ik_abc", Credential: secret}})
	if err != nil {
		t.Fatal(err)
	}
	if body, _ := os.ReadFile(st3.CredentialFile); string(body) != secret+"\n" {
		t.Fatalf("key file = %q", body)
	}
	cfg.Observability.SDK.GatewayURL = ""
	if d := BuildDiscovery(cfg, st3, "http://127.0.0.1:8081"); !anyContains(d.Warnings, "stored without a gateway address") {
		t.Fatalf("warnings = %q", d.Warnings)
	}
}

func TestParseDeliveryFile(t *testing.T) {
	for _, tc := range []struct {
		in, gw string
		ok     bool
	}{
		{secret, "", true},
		{secret + "\n", "", true},
		{secret + "\ngateway_url=https://gw.example.com\n", "https://gw.example.com", true},
		{secret + "\nfuture_field=x\ngateway_url=https://gw\n", "https://gw", true},
		{secret + "\nnot a field\n", "", false},
		{"not a key\n", "", false},
		{secret + "\n\n", "", false},
	} {
		_, gw, ok := parseDeliveryFile([]byte(tc.in))
		if ok != tc.ok || gw != tc.gw {
			t.Errorf("%q: gw=%q ok=%v, want %q %v", tc.in, gw, ok, tc.gw, tc.ok)
		}
	}
}

// TestExpiryKeepsBothAndWarns pins review E-59 (ruling D29): an expired key
// keeps the machine signed in (destination both, with a degraded warning)
// but is not offered to the SDKs; 14 days before expiry the machine warns,
// and the doctor row says the same.
func TestExpiryKeepsBothAndWarns(t *testing.T) {
	s := newSvc(t)
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return now }
	m := &fakeMinter{minted: orgcontract.SDKCredentialMinted{KeyID: "ik_abc", Credential: secret, GatewayURL: "https://gw.example.com", ExpiresAt: now.Add(10 * 24 * time.Hour).Format(time.RFC3339)}}
	if _, err := s.SignIn(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Observability.Enabled = true

	st := s.Status()
	if !st.SignedIn || st.Expired || !st.ExpiresSoon || !strings.Contains(st.Notice, "2026-11-30 (in 10 days)") {
		t.Fatalf("soon: %+v", st)
	}
	d := BuildDiscovery(cfg, st, "http://127.0.0.1:8081")
	if d.Destination != "both" || !d.Online.CredentialPresent || !anyContains(d.Warnings, "expires on 2026-11-30") {
		t.Fatalf("soon discovery: %+v", d)
	}
	if c := DoctorCheck(st); c.Level != "warn" || !strings.Contains(c.Message, "expires on") {
		t.Fatalf("soon doctor: %+v", c)
	}

	// 20 days out: no warning.
	s.Now = func() time.Time { return now.Add(-10 * 24 * time.Hour) }
	if st := s.Status(); st.ExpiresSoon || st.Notice != "" || DoctorCheck(st).Level != "ok" {
		t.Fatalf("far: %+v", st)
	}

	// Past expiry: still signed in, destination both, key not offered.
	s.Now = func() time.Time { return now.Add(11 * 24 * time.Hour) }
	st = s.Status()
	if !st.SignedIn || !st.Expired || st.Usable() || !strings.Contains(st.Problem, "expired on 2026-11-30") {
		t.Fatalf("expired: %+v", st)
	}
	d = BuildDiscovery(cfg, st, "http://127.0.0.1:8081")
	if d.Destination != "both" || d.Source != "default_signed_in" || d.Online.CredentialPresent || !anyContains(d.Warnings, "expired on") {
		t.Fatalf("expired discovery: %+v", d)
	}
	if c := DoctorCheck(st); c.Level != "fail" {
		t.Fatalf("expired doctor: %+v", c)
	}
}

// TestSignedInDefaultIsOnlineWithoutLocalObservability pins review E-32
// (ruling D29): a signed-in machine that cannot receive app data itself
// (observability off, or not in the build) defaults to online, not both.
func TestSignedInDefaultIsOnlineWithoutLocalObservability(t *testing.T) {
	st := Status{SignedIn: true, CredentialFile: "/x", KeyGatewayURL: "https://gw.example.com"}
	cases := []struct {
		name               string
		compiled, enabled  bool
		configured         string
		destination        string
		source             string
		localEnabled       bool
		wantWarn, wantNone string
	}{
		{"on and built", true, true, "", "both", "default_signed_in", true, "", "does not include"},
		{"off", true, false, "", "online", "default_signed_in_no_local", false, "sends online only", "observability is off on this machine"},
		{"not built", false, true, "", "online", "default_signed_in_no_local", false, "sends online only", "turn it on in Settings"},
		{"not built, explicit both", false, true, "both", "both", "config", false, "does not include AI Apps observability", "turn it on in Settings"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			old := obsCompiledIn
			obsCompiledIn = func() bool { return c.compiled }
			defer func() { obsCompiledIn = old }()
			cfg := config.Default()
			cfg.Observability.Enabled = c.enabled
			cfg.Observability.SDK.Destination = c.configured
			d := BuildDiscovery(cfg, st, "http://127.0.0.1:8081")
			if d.Destination != c.destination || d.Source != c.source || d.Local.Enabled != c.localEnabled {
				t.Fatalf("discovery = %+v", d)
			}
			if c.wantWarn != "" && !anyContains(d.Warnings, c.wantWarn) {
				t.Fatalf("warnings %q lack %q", d.Warnings, c.wantWarn)
			}
			if anyContains(d.Warnings, c.wantNone) {
				t.Fatalf("warnings %q carry %q", d.Warnings, c.wantNone)
			}
		})
	}
	// Not signed in stays local whatever the build.
	old := obsCompiledIn
	obsCompiledIn = func() bool { return false }
	defer func() { obsCompiledIn = old }()
	if d := BuildDiscovery(config.Default(), Status{}, "http://127.0.0.1:8081"); d.Destination != "local" {
		t.Fatalf("not signed in: %+v", d)
	}
}

func anyContains(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// TestSignInKeepsTheWorkspaceCaptureLevel pins review L-23: the capture
// level the org reports at sign-in is kept with the key's description, shown
// by discovery, named in plain words, and an L0 workspace is a warning while
// data goes online.
func TestSignInKeepsTheWorkspaceCaptureLevel(t *testing.T) {
	s := newSvc(t)
	old := obsCompiledIn
	obsCompiledIn = func() bool { return true }
	defer func() { obsCompiledIn = old }()
	m := &fakeMinter{minted: orgcontract.SDKCredentialMinted{
		CredID: "c1", KeyID: "ik_abc", Credential: secret, OrgID: "o", WorkspaceID: "default",
		GatewayURL: "https://gw.example.com", CaptureLevel: CaptureMetadataOnly,
	}}
	st, err := s.SignIn(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if st.CaptureLevel != CaptureMetadataOnly || s.Status().CaptureLevel != CaptureMetadataOnly {
		t.Fatalf("status = %+v", st)
	}
	cfg := config.Default()
	cfg.Observability.Enabled = true
	d := BuildDiscovery(cfg, st, "http://127.0.0.1:8081")
	if d.Online.CaptureLevel != CaptureMetadataOnly || d.Online.WorkspaceID != "default" {
		t.Fatalf("online = %+v", d.Online)
	}
	if len(d.Warnings) != 1 || !strings.Contains(d.Warnings[0], "only metadata for workspace default") {
		t.Fatalf("warnings = %q", d.Warnings)
	}
	cfg.Observability.SDK.Destination = "local"
	if d := BuildDiscovery(cfg, st, "http://127.0.0.1:8081"); len(d.Warnings) != 0 {
		t.Fatalf("a local destination sends nothing online, so no level warning: %q", d.Warnings)
	}
	for level, want := range map[string]string{
		CaptureMetadataOnly: "L0", CaptureClassifiedSafe: "L1", CaptureFullRedacted: "L2", "": "not reported", "weird": "not reported",
	} {
		if got := CaptureLevelText(level); !strings.HasPrefix(got, want) {
			t.Errorf("CaptureLevelText(%q) = %q, want prefix %q", level, got, want)
		}
	}
}

// TestBuildDiscoveryAdvertisesAppLanes pins the destination advertisement of
// the local app lanes (hosted AI gateway plan L7, S5): each lane's client
// base URL, never its upstream; none while the proxy is off.
func TestBuildDiscoveryAdvertisesAppLanes(t *testing.T) {
	cfg := config.Default()
	cfg.Proxy.Enabled = true
	cfg.Proxy.Port = 8820
	cfg.Proxy.Upstreams = map[string]string{"openai": "https://api.openai.com", "anthropic": "https://api.anthropic.com"}
	d := BuildDiscovery(cfg, Status{}, "http://127.0.0.1:8081")
	if len(d.Local.AppLanes) != 2 {
		t.Fatalf("lanes = %+v", d.Local.AppLanes)
	}
	got := map[string]DiscoveryAppLane{}
	for _, l := range d.Local.AppLanes {
		got[l.ID] = l
	}
	if got["openai"].ClientBaseURL != "http://127.0.0.1:8820/up/openai/v1" || got["openai"].Kind != "openai" {
		t.Fatalf("openai lane = %+v", got["openai"])
	}
	if got["anthropic"].ClientBaseURL != "http://127.0.0.1:8820/up/anthropic" {
		t.Fatalf("anthropic lane = %+v", got["anthropic"])
	}
	cfg.Proxy.Enabled = false
	if d := BuildDiscovery(cfg, Status{}, "http://127.0.0.1:8081"); d.Local.AppLanes == nil || len(d.Local.AppLanes) != 0 {
		t.Fatalf("proxy off: lanes = %#v, want an empty list", d.Local.AppLanes)
	}
}
