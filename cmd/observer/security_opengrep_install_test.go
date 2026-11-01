//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/secengine"
	"github.com/marmutapp/superbased-observer/internal/secscan/opengrep/opengrepnet"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// security_opengrep_install_test.go is lane SEC-G2 milestone 1: the guided
// install, each step against a fake release server through the real egress
// client.

// selectedCodeConfig writes a config whose [components] block selects the
// code rules, with a private HOME and user cache directory.
func selectedCodeConfig(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the user cache directory is pinned through XDG_CACHE_HOME (linux)")
	}
	setTestHome(t, t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	body := "[observer]\ndb_path = \"" + filepath.ToSlash(filepath.Join(dir, "observer.db")) + "\"\n\n[components]\nadd = [\"security.scan.opengrep\"]\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// codeTestKeys stands in a vendor key for the content channel.
func codeTestKeys(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(nil)
	prev := codeRulesTrust
	codeRulesTrust = func() contentchan.Trust {
		return contentchan.Trust{VendorKeys: []ed25519.PublicKey{priv.Public().(ed25519.PublicKey)}}
	}
	t.Cleanup(func() { codeRulesTrust = prev })
	return priv
}

// engineEntry is a verified-online engine entry for this platform.
func engineEntry(version string, body []byte) content.Entry {
	sum := sha256.Sum256(body)
	return content.Entry{
		Name: "opengrep_test_" + runtime.GOOS + "_" + runtime.GOARCH, Version: version, OS: runtime.GOOS, Arch: runtime.GOARCH,
		SizeBytes: int64(len(body)), SHA256: hex.EncodeToString(sum[:]), License: "LGPL-2.1",
		Upstream: content.UpstreamCheck{
			Method: content.UpstreamCosignKeylessOnline, Identity: secengine.Identity(version), Issuer: secengine.Issuer,
			VerifiedAt: time.Now().UTC().Format(time.RFC3339), VerifiedWhere: "release_pipeline",
		},
	}
}

// signEngine signs an engine manifest with priv at version mv.
func signEngine(t *testing.T, priv ed25519.PrivateKey, mv int64, entries []content.Entry, revoked ...string) []byte {
	t.Helper()
	now := time.Now().UTC()
	m := content.Manifest{
		Schema: content.SchemaV1, Kind: content.Engine, ManifestVersion: mv, Epoch: mv,
		IssuedAt: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(60 * 24 * time.Hour).Format(time.RFC3339),
		Entries: entries,
	}
	for _, r := range revoked {
		m.Revoked = append(m.Revoked, content.Revocation{SHA256: r, Reason: "test"})
	}
	env, err := content.Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := content.EncodeEnvelope(env)
	return b
}

// fakeRelease serves body at every release path through the real egress
// client, counting requests.
func fakeRelease(t *testing.T, body []byte) *atomic.Int32 {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		if strings.HasPrefix(r.URL.Path, "/opengrep/opengrep/releases/download/") {
			http.Redirect(w, r, "https://"+opengrepnet.AssetsHost+"/asset"+r.URL.Path, http.StatusFound)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/asset/") {
			_, _ = w.Write(body)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	eps := map[string]string{}
	for _, h := range opengrepnet.AllowedHosts() {
		eps[h] = srv.URL
	}
	prev := codeInstallNet
	codeInstallNet = func() codeDownloader {
		return opengrepnet.New(opengrepnet.Options{Transport: srv.Client().Transport, Endpoints: eps})
	}
	t.Cleanup(func() { codeInstallNet = prev })
	return &n
}

// openSelected opens the env of a selected config with an accepted engine
// manifest pinning body for this platform.
func openSelected(t *testing.T, priv ed25519.PrivateKey, body []byte) *codeEnv {
	t.Helper()
	cfg := selectedCodeConfig(t)
	e, err := openCodeEnv(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.cleanup)
	if body != nil {
		env := signEngine(t, priv, 1, []content.Entry{engineEntry("1.30.1", body)})
		cs := codeRulesStore(e.resolved)
		src := filepath.Join(t.TempDir(), "bin")
		if err := os.WriteFile(src, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := cs.InstallFiles(content.Engine, env, map[string]string{engineEntry("1.30.1", body).Name: src}, codeRulesTrust()); err != nil {
			t.Fatal(err)
		}
		e.manifest = loadEngineManifest(cs, codeRulesTrust())
		if e.manifest == nil {
			t.Fatal("the test engine manifest did not load")
		}
	}
	return e
}

func TestGuidedInstallStatesSizesAndWaitsForConsent(t *testing.T) {
	priv := codeTestKeys(t)
	body := bytes.Repeat([]byte("opengrep"), 4096)
	hits := fakeRelease(t, body)
	e := openSelected(t, priv, body)
	var out bytes.Buffer
	if err := runCodeInstall(context.Background(), &out, strings.NewReader(""), e, false, false, false); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"download: less than 1 MB", "unpacked on first run", "Nothing downloaded", "sha256: " + engineEntry("1.30.1", body).SHA256} {
		if !strings.Contains(text, want) {
			t.Errorf("plan lacks %q:\n%s", want, text)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("%d requests before the consent", hits.Load())
	}
	if _, err := os.Stat(filepath.Join(e.secDir, codeInstallConsentFile)); err == nil {
		t.Fatal("a consent was recorded without a yes")
	}
	if _, err := os.Stat(codeInstalledPath()); err == nil {
		t.Fatal("something was installed")
	}
	// The seam refuses too, before any request.
	if _, err := e.installEngine(context.Background(), codeSurfaceCLI, false); !errors.Is(err, errCodeConsentNeeded) {
		t.Fatalf("install without consent: %v", err)
	}
	// --plan prints and writes nothing, even with --yes.
	out.Reset()
	if err := runCodeInstall(context.Background(), &out, strings.NewReader("y\n"), e, true, true, true); err != nil || hits.Load() != 0 {
		t.Fatalf("--plan: %v, %d requests", err, hits.Load())
	}
}

func TestGuidedInstallDownloadsChecksAndRenames(t *testing.T) {
	priv := codeTestKeys(t)
	body := bytes.Repeat([]byte("opengrep"), 4096)
	fakeRelease(t, body)
	e := openSelected(t, priv, body)
	var out bytes.Buffer
	if err := runCodeInstall(context.Background(), &out, strings.NewReader("yes\n"), e, false, false, true); err != nil {
		t.Fatalf("install: %v\n%s", err, out.String())
	}
	got, err := os.ReadFile(codeInstalledPath())
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("installed bytes: %v", err)
	}
	fi, _ := os.Stat(codeInstalledPath())
	if fi.Mode().Perm()&0o100 == 0 {
		t.Errorf("the engine is not executable: %v", fi.Mode())
	}
	ents, _ := os.ReadDir(filepath.Dir(codeInstalledPath()))
	if len(ents) != 1 {
		t.Errorf("leftover files beside the engine: %v", ents)
	}
	c := readCodeInstallConsent(e.secDir)
	if !c.Verified || c.Surface != codeSurfaceCLI || c.PinSHA256 != engineEntry("1.30.1", body).SHA256 {
		t.Fatalf("consent %+v", c)
	}
	// Installed: a second run asks nothing and downloads nothing.
	p := secengine.PlanInstall(e.installInput(context.Background()))
	if !p.Installed || p.NeedsConsent {
		t.Fatalf("plan after install %+v", p)
	}
}

func TestGuidedInstallRefusesAWrongDownload(t *testing.T) {
	priv := codeTestKeys(t)
	body := bytes.Repeat([]byte("opengrep"), 4096)
	tampered := append(append([]byte(nil), body[:len(body)-1]...), 'X')
	fakeRelease(t, tampered)
	e := openSelected(t, priv, body)
	if _, err := e.installEngine(context.Background(), codeSurfaceCLI, true); !errors.Is(err, secengine.ErrInstallRefused) {
		t.Fatalf("a tampered download: %v", err)
	}
	if _, err := os.Stat(codeInstalledPath()); err == nil {
		t.Fatal("a tampered download reached the install path")
	}
	ents, _ := os.ReadDir(filepath.Dir(codeInstalledPath()))
	if len(ents) != 0 {
		t.Errorf("a temporary download was left behind: %v", ents)
	}
}

func TestGuidedInstallConsentIsSignedAndPinBound(t *testing.T) {
	priv := codeTestKeys(t)
	body := bytes.Repeat([]byte("opengrep"), 4096)
	e := openSelected(t, priv, body)
	p := secengine.PlanInstall(e.installInput(context.Background()))
	c, err := secengine.NewInstallConsent(p, codeSurfaceDashboard, "dev", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recordCodeInstallConsent(e.secDir, c); err != nil {
		t.Fatal(err)
	}
	if !readCodeInstallConsent(e.secDir).Covers(p) {
		t.Fatal("the recorded consent does not cover its pin")
	}
	// A hand-edited record (what an agent could write) reads not given.
	path := filepath.Join(e.secDir, codeInstallConsentFile)
	b, _ := os.ReadFile(path)
	if err := os.WriteFile(path, bytes.Replace(b, []byte(`"dev"`), []byte(`"agent"`), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if readCodeInstallConsent(e.secDir).Covers(p) {
		t.Fatal("an edited record still covers")
	}
	if _, err := recordCodeInstallConsent(e.secDir, c); err != nil {
		t.Fatal(err)
	}
	// A new pin asks again.
	other := bytes.Repeat([]byte("newer"), 100)
	cs := codeRulesStore(e.resolved)
	src := filepath.Join(t.TempDir(), "b")
	_ = os.WriteFile(src, other, 0o600)
	if _, err := cs.InstallFiles(content.Engine, signEngine(t, priv, 2, []content.Entry{engineEntry("1.31.0", other)}), map[string]string{engineEntry("1.31.0", other).Name: src}, codeRulesTrust()); err != nil {
		t.Fatal(err)
	}
	e.manifest = loadEngineManifest(cs, codeRulesTrust())
	q := secengine.PlanInstall(e.installInput(context.Background()))
	if q.Pin.Version != "1.31.0" || readCodeInstallConsent(e.secDir).Covers(q) {
		t.Fatalf("a changed pin is still consented: %+v", q.Pin)
	}
}

// fakeMirror installs the engine kind from in-memory content, as the org
// mirror's fetch would.
type fakeMirror struct {
	env   []byte
	files map[string][]byte
	calls int
}

func (m *fakeMirror) InstallSecurityContent(_ context.Context, st contentchan.Store, kind content.Kind, tr contentchan.Trust) (orgclient.SecurityContentResult, error) {
	m.calls++
	if kind != content.Engine || m.env == nil {
		return orgclient.SecurityContentResult{Kind: kind}, orgclient.ErrSecurityContentNotMirrored
	}
	paths := map[string]string{}
	for name, b := range m.files {
		p := filepath.Join(st.Root, ".incoming-"+name)
		_ = os.MkdirAll(st.Root, 0o700)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			return orgclient.SecurityContentResult{}, err
		}
		paths[name] = p
	}
	s, err := st.InstallFiles(kind, m.env, paths, tr)
	return orgclient.SecurityContentResult{Kind: kind, State: s}, err
}

func TestGuidedInstallManagedUsesTheMirrorOnly(t *testing.T) {
	priv := codeTestKeys(t)
	body := bytes.Repeat([]byte("mirrored"), 2048)
	hits := fakeRelease(t, body)
	e := openSelected(t, priv, nil)
	e.managed = true
	mirror := &fakeMirror{env: signEngine(t, priv, 1, []content.Entry{engineEntry("1.30.1", body)}), files: map[string][]byte{engineEntry("1.30.1", body).Name: body}}
	prevOrg, prevNamed := codeOrgMirror, codeMirrorNamedFor
	t.Cleanup(func() { codeOrgMirror, codeMirrorNamedFor = prevOrg, prevNamed })
	codeOrgMirror = func(context.Context, string) (codeMirrorInstaller, func(), error) { return mirror, func() {}, nil }

	// The managed pull does not name the mirror: blocked, nothing fetched.
	codeMirrorNamedFor = func(context.Context, config.Config, *store.Store) bool { return false }
	if _, err := e.installEngine(context.Background(), codeSurfaceCLI, true); err == nil || mirror.calls != 0 {
		t.Fatalf("installed without the mirror named: %v, %d mirror calls", err, mirror.calls)
	}
	codeMirrorNamedFor = func(context.Context, config.Config, *store.Store) bool { return true }
	if _, err := e.installEngine(context.Background(), codeSurfaceCLI, false); err != nil {
		t.Fatalf("managed install: %v", err)
	}
	got, err := os.ReadFile(codeInstalledPath())
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("installed bytes: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("a managed node reached the public release: %d requests", hits.Load())
	}
	if _, err := os.Stat(filepath.Join(e.secDir, codeInstallConsentFile)); err == nil {
		t.Error("a managed node recorded a consent it never asks for")
	}
}

// failingMirror is an org mirror whose every fetch fails.
type failingMirror struct{ calls int }

func (m *failingMirror) InstallSecurityContent(_ context.Context, _ contentchan.Store, kind content.Kind, _ contentchan.Trust) (orgclient.SecurityContentResult, error) {
	m.calls++
	return orgclient.SecurityContentResult{Kind: kind}, errors.New("dial tcp: connection refused")
}

// TestGuidedInstallManagedRefusesWhenTheMirrorFetchFails: lane SEC-G2
// audit finding 6. A managed node holding an earlier accepted manifest (and
// its bytes in the content store) that pins this platform still refuses
// the install, with a named reason, when the mirror fetch fails.
func TestGuidedInstallManagedRefusesWhenTheMirrorFetchFails(t *testing.T) {
	priv := codeTestKeys(t)
	body := bytes.Repeat([]byte("earlier"), 2048)
	hits := fakeRelease(t, body)
	e := openSelected(t, priv, body)
	e.managed = true
	mirror := &failingMirror{}
	prevOrg, prevNamed := codeOrgMirror, codeMirrorNamedFor
	t.Cleanup(func() { codeOrgMirror, codeMirrorNamedFor = prevOrg, prevNamed })
	codeOrgMirror = func(context.Context, string) (codeMirrorInstaller, func(), error) { return mirror, func() {}, nil }
	codeMirrorNamedFor = func(context.Context, config.Config, *store.Store) bool { return true }
	plan, err := e.installEngine(context.Background(), codeSurfaceCLI, false)
	if err == nil || !strings.Contains(err.Error(), codeBlockMirrorFetch) || plan.Blocked != codeBlockMirrorFetch {
		t.Fatalf("install with the mirror down: %v (blocked %q)", err, plan.Blocked)
	}
	if mirror.calls == 0 {
		t.Fatal("the mirror was not asked")
	}
	if _, err := os.Stat(codeInstalledPath()); err == nil {
		t.Fatal("an engine was installed from the local content store")
	}
	if hits.Load() != 0 {
		t.Fatalf("a managed node reached the public release: %d requests", hits.Load())
	}
}

func TestGuidedInstallDashboardSeam(t *testing.T) {
	priv := codeTestKeys(t)
	body := bytes.Repeat([]byte("opengrep"), 4096)
	fakeRelease(t, body)
	e := openSelected(t, priv, body)
	st0 := e.dashStatus(context.Background())
	if !st0.Selected || st0.Installed || st0.Consented || st0.ConsentText == "" || st0.DownloadBytes != int64(len(body)) {
		t.Fatalf("status before %+v", st0)
	}
	// Audit finding 3: the accept carries the pin the dialog showed; any
	// other (or none) is refused with the current pin, and nothing is
	// recorded or downloaded.
	for _, seen := range []string{"", strings.Repeat("0", 64)} {
		err := startCodeInstallJob(context.Background(), e, seen)
		var changed *dashapi.OpengrepPinChanged
		if !errors.As(err, &changed) || changed.SHA256 != st0.SHA256 {
			t.Fatalf("accept of pin %q: %v, want pin_changed with %s", seen, err, st0.SHA256)
		}
		if _, err := os.Stat(filepath.Join(e.secDir, codeInstallConsentFile)); err == nil {
			t.Fatal("a consent was recorded for a pin the dialog did not show")
		}
	}
	if err := startCodeInstallJob(context.Background(), e, strings.ToUpper(st0.SHA256)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		codeInstallJob.mu.Lock()
		running, lastErr := codeInstallJob.running, codeInstallJob.lastErr
		codeInstallJob.mu.Unlock()
		if !running {
			if lastErr != "" {
				t.Fatalf("job: %s", lastErr)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the install job did not finish")
		}
		time.Sleep(20 * time.Millisecond)
	}
	st := e.dashStatus(context.Background())
	if !st.Installed || !st.Consented || st.ConsentedOn != codeSurfaceDashboard {
		t.Fatalf("status after %+v", st)
	}
}

// TestCodeDoctorAndStatusRows: the doctor and `code status` name the
// guided install's state, the pack's freshness, the triggers and that none
// runs in a hook, and start nothing.
func TestCodeDoctorAndStatusRows(t *testing.T) {
	codeTestKeys(t)
	cfg := selectedCodeConfig(t)
	e, err := openCodeEnv(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer e.cleanup()
	var out bytes.Buffer
	if err := writeCodeStatus(context.Background(), &out, e); err != nil {
		t.Fatal(err)
	}
	c := securityCodeDoctorCheck(context.Background(), cfg)
	joined := strings.Join(c.Details, "\n")
	for _, text := range []string{out.String(), joined} {
		for _, want := range []string{"guided install:", "rule pack freshness: embedded", "triggers: post-write on, commit diff on, schedule off", "never"} {
			if want == "never" {
				want = "none runs in a hook"
			}
			if !strings.Contains(text, want) {
				t.Errorf("lacks %q:\n%s", want, text)
			}
		}
	}
}
