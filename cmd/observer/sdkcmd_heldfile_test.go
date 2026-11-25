package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/sdkcredsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// fakeHeldKey stands in for the key a real SDK setup would write; only a
// fake ever appears in tests.
const fakeHeldKey = "ik_held.fakeHeldSecretValue"

// runSDKStatus runs `observer sdk status` over cfgPath and returns stdout.
func runSDKStatus(t *testing.T, cfgPath string, args ...string) string {
	t.Helper()
	cmd := newSDKStatusCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(append([]string{"--config", cfgPath}, args...))
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("sdk status: %v\n%s", err, out.String())
	}
	if strings.Contains(out.String(), "fakeHeldSecretValue") || strings.Contains(out.String(), "machineSecretValue") {
		t.Fatalf("sdk status printed a key:\n%s", out.String())
	}
	return out.String()
}

// TestSDKStatusNamesTheSDKHeldFile pins SDK quickstart plan 3.4 and ruling
// R10: `observer sdk status` names the SDK-held file from a stat of it,
// never its key, and says it is present but unused once this machine's own
// key wins.
func TestSDKStatusNamesTheSDKHeldFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the SDK-held file's Windows rule and the machine's key file are not exercised here")
	}
	tmp := t.TempDir()
	xdg := filepath.Join(tmp, "xdg")
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Setenv(sdkcredsvc.SDKHeldFileEnv, "")
	dbPath := filepath.Join(tmp, "obs", "observer.db")
	cfgPath := filepath.Join(tmp, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(dbPath)+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	held := filepath.Join(xdg, "superbased", "sdk-credential")

	if got := runSDKStatus(t, cfgPath); !strings.Contains(got, "SDK file:    "+held+": none") {
		t.Fatalf("no file:\n%s", got)
	}
	if err := os.MkdirAll(filepath.Dir(held), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(held, []byte(fakeHeldKey+"\ngateway_url=https://u-sam.superbased.app\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := runSDKStatus(t, cfgPath); !strings.Contains(got, "refused by the SDKs: other users can read it") {
		t.Fatalf("open file:\n%s", got)
	}
	// os.WriteFile keeps an existing file's mode: make it 0600 first.
	if err := os.Chmod(held, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(held, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := runSDKStatus(t, cfgPath); !strings.Contains(got, "refused by the SDKs: it is empty") {
		t.Fatalf("empty file:\n%s", got)
	}
	if err := os.WriteFile(held, []byte(fakeHeldKey+"\ngateway_url=https://u-sam.superbased.app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := runSDKStatus(t, cfgPath); !strings.Contains(got, held+": present: an app that sets no key of its own") {
		t.Fatalf("present:\n%s", got)
	}

	// This machine signs in: its record wins the credential (R10).
	cfg, err := loadConfigFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	svc := sdkCredentialService(cfg, nil)
	svc.Keychain = nil
	if _, err := svc.SignIn(context.Background(), doctorMinter{orgcontract.SDKCredentialMinted{
		KeyID: "ik_m", OrgID: "o1", Credential: "ik_m.machineSecretValue", GatewayURL: "https://u-sam.superbased.app",
	}}); err != nil {
		t.Fatal(err)
	}
	if got := runSDKStatus(t, cfgPath); !strings.Contains(got, held+": present but unused: this machine's own SDK key wins") {
		t.Fatalf("unused:\n%s", got)
	}

	// --json: the discovery body plus the file's state beside it, and the
	// enrolment's dashboard for the key's organization.
	_, database, cleanup, err := openNodeDB(context.Background(), cfg, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.New(database).WriteEnrolment(context.Background(), store.Enrolment{OrgID: "o1", OrgServerURL: "https://u-sam.superbased.app", UserID: "u1", BearerKeyID: "k"}); err != nil {
		t.Fatal(err)
	}
	cleanup()
	var body struct {
		APIVersion int `json:"api_version"`
		Online     struct {
			DashboardURL string `json:"dashboard_url"`
			KeyID        string `json:"key_id"`
		} `json:"online"`
		SDKHeldFile sdkcredsvc.HeldFile `json:"sdk_held_file"`
	}
	raw := runSDKStatus(t, cfgPath, "--json")
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("json: %v\n%s", err, raw)
	}
	if body.APIVersion != 1 || body.Online.KeyID != "ik_m" || body.Online.DashboardURL != "https://u-sam.superbased.app" {
		t.Fatalf("discovery: %+v", body)
	}
	if body.SDKHeldFile.Path != held || body.SDKHeldFile.State != sdkcredsvc.HeldFileUnused || body.SDKHeldFile.Source != sdkcredsvc.HeldFileSourceXDG {
		t.Fatalf("held file: %+v", body.SDKHeldFile)
	}
}

// TestSDKStatusHeldFileEnvReplacesThePath: SUPERBASED_CREDENTIAL_FILE names
// the file instead of the ladder, and a symlink there is reported refused
// without being followed.
func TestSDKStatusHeldFileEnvReplacesThePath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on windows")
	}
	tmp := t.TempDir()
	target := filepath.Join(tmp, "real")
	if err := os.WriteFile(target, []byte(fakeHeldKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tmp, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv(sdkcredsvc.SDKHeldFileEnv, link)
	h := sdkHeldFile(false)
	if h.Path != link || h.Source != sdkcredsvc.HeldFileSourceEnv || h.State != sdkcredsvc.HeldFileRefused || h.Reason != "symlink" || !strings.Contains(h.Text, "symbolic link") {
		t.Fatalf("held file: %+v", h)
	}
}
