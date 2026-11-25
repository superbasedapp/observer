package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/sdkcredsvc"
)

// fakeUseKey is an obviously fake admin-issued key; no test output may
// carry its secret half.
const fakeUseKey = "ik_lane.fakeUseKeySecret"

// useKeyConfig writes a config whose observer directory is a temp dir.
func useKeyConfig(t *testing.T) (cfgPath, dbPath string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("no SDK key file on windows")
	}
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "observer.db")
	cfgPath = filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(dbPath)+"\"\n\n[observability]\nenabled = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, dbPath
}

// runSDKCmd runs `observer sdk <args>` with stdin and returns stdout,
// stderr and the error.
func runSDKCmd(t *testing.T, stdin string, args ...string) (string, string, error) {
	t.Helper()
	cmd := newSDKCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), errOut.String(), err
}

// TestSDKUseKeyInstallsFromStdin: the key piped on stdin is installed in the
// hardened delivery file with its gateway line, the machine default becomes
// both (online only in an edition that does not compile the machine's AI Apps
// observability: the no_obs, minimal and managed builds), status names the
// key's origin, and the key is in no output.
func TestSDKUseKeyInstallsFromStdin(t *testing.T) {
	cfgPath, dbPath := useKeyConfig(t)
	wantDest := "online"
	if slices.Contains(components.Compiled(components.BinaryNode), "obs") {
		wantDest = "both"
	}
	out, errOut, err := runSDKCmd(t, fakeUseKey+"\n", "use-key", "--config", cfgPath, "--gateway-url", "https://acme.superbased.app/")
	if err != nil {
		t.Fatalf("use-key: %v\n%s%s", err, out, errOut)
	}
	for _, want := range []string{"installed: SDK key ik_lane", "issued by an admin", "apps send it only to: https://acme.superbased.app", "now sends to: " + wantDest, "does not revoke it"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out+errOut, "fakeUseKeySecret") {
		t.Fatalf("the key reached the output:\n%s%s", out, errOut)
	}
	file := sdkcredsvc.Service{Dir: sdkcredsvc.DefaultDir(filepath.Dir(dbPath))}.CredentialFile()
	body, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("delivery file: %v", err)
	}
	if string(body) != fakeUseKey+"\ngateway_url=https://acme.superbased.app\n" {
		t.Fatalf("delivery file = %q", body)
	}
	if fi, _ := os.Lstat(file); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}

	out, _, err = runSDKCmd(t, "", "status", "--config", cfgPath, "--json")
	if err != nil {
		t.Fatal(err)
	}
	var d sdkcredsvc.Discovery
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("status --json: %v\n%s", err, out)
	}
	if !d.SignedIn || !d.Online.CredentialPresent || d.Destination != wantDest || d.Online.KeyOrigin != sdkcredsvc.KeyOriginAdminIssued || d.Online.GatewayURL != "https://acme.superbased.app" {
		t.Fatalf("discovery = %+v", d)
	}
	out, _, err = runSDKCmd(t, "", "status", "--config", cfgPath)
	if err != nil || !strings.Contains(out, "SDK key:     ik_lane (issued by an admin, installed with `observer sdk use-key`)") || !strings.Contains(out, "Machine identities") {
		t.Fatalf("status: %v\n%s", err, out)
	}
}

// TestSDKUseKeyRefusals: what the command refuses, each before anything is
// stored, and none of them repeating the key.
func TestSDKUseKeyRefusals(t *testing.T) {
	cases := []struct {
		name  string
		stdin string
		args  []string
		want  string
	}{
		{"the key as an argument", "", []string{"use-key", "--gateway-url", "https://gw.example.com", fakeUseKey}, "reads the key from stdin only"},
		{"no gateway", fakeUseKey + "\n", []string{"use-key"}, "--gateway-url"},
		{"plain http to a remote host", fakeUseKey + "\n", []string{"use-key", "--gateway-url", "http://gw.example.com"}, "unencrypted"},
		{"nothing on stdin", "", []string{"use-key", "--gateway-url", "https://gw.example.com"}, "no SDK key on stdin"},
		{"white space only on stdin", "  \n", []string{"use-key", "--gateway-url", "https://gw.example.com"}, "no SDK key on stdin"},
		{"not a key", "ik_lane fakeUseKeySecret\n", []string{"use-key", "--gateway-url", "https://gw.example.com"}, "not an SDK key"},
		{"a pasted export line", "export SUPERBASED_API_KEY=" + fakeUseKey + "\n", []string{"use-key", "--gateway-url", "https://gw.example.com"}, "not an SDK key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath, dbPath := useKeyConfig(t)
			out, errOut, err := runSDKCmd(t, tc.stdin, append(tc.args, "--config", cfgPath)...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if strings.Contains(err.Error()+out+errOut, "fakeUseKeySecret") {
				t.Fatalf("a refusal repeated the key: %v\n%s%s", err, out, errOut)
			}
			if _, statErr := os.Stat(sdkcredsvc.DefaultDir(filepath.Dir(dbPath))); statErr == nil {
				entries, _ := os.ReadDir(sdkcredsvc.DefaultDir(filepath.Dir(dbPath)))
				for _, e := range entries {
					if strings.Contains(e.Name(), sdkcredsvc.RecordCredential) {
						t.Fatalf("a refusal stored %s", e.Name())
					}
				}
			}
		})
	}
}

// TestSDKSignOutOfAnInstalledKeyRemovesWithoutRevoking: sign-out of an
// admin-issued key needs no organization (it asks none) and says the key was
// removed, not revoked.
func TestSDKSignOutOfAnInstalledKeyRemovesWithoutRevoking(t *testing.T) {
	cfgPath, _ := useKeyConfig(t)
	if _, _, err := runSDKCmd(t, fakeUseKey+"\n", "use-key", "--config", cfgPath, "--gateway-url", "https://gw.example.com"); err != nil {
		t.Fatal(err)
	}
	// The machine is not enrolled: a sign-in key's revoke would fail with
	// "not enrolled"; an admin-issued key is never sent, so sign-out is clean.
	out, errOut, err := runSDKCmd(t, "", "sign-out", "--config", cfgPath)
	if err != nil {
		t.Fatalf("sign-out: %v\n%s%s", err, out, errOut)
	}
	if !strings.Contains(out, "removed: the SDK key on this machine was issued by an admin") || !strings.Contains(out, "not revoked") || strings.Contains(out, "revoked on your organization") {
		t.Fatalf("sign-out output:\n%s", out)
	}
	out, _, _ = runSDKCmd(t, "", "status", "--config", cfgPath, "--json")
	if strings.Contains(out, `"signed_in":true`) {
		t.Fatalf("still signed in:\n%s", out)
	}
}

// TestSDKReadPastedAsksAgain: the terminal read asks again while a read
// brings only a paste's wrappers, up to sdkPasteTries.
func TestSDKReadPastedAsksAgain(t *testing.T) {
	reads := []string{"\x1b[200~\x1b[201~", "", fakeUseKey}
	i := 0
	var prompt bytes.Buffer
	got, err := sdkReadPasted(&prompt, func() ([]byte, error) {
		b := reads[i]
		i++
		return []byte(b), nil
	})
	if err != nil || got != fakeUseKey || i != 3 {
		t.Fatalf("got %q after %d reads, err %v", got, i, err)
	}
	if strings.Count(prompt.String(), "Paste the SDK key") != 3 || strings.Contains(prompt.String(), "fakeUseKeySecret") {
		t.Fatalf("prompts:\n%s", prompt.String())
	}
	_, err = sdkReadPasted(&prompt, func() ([]byte, error) { return nil, errors.New("tty gone") })
	if err == nil {
		t.Fatal("a read error is returned")
	}
}

// TestSDKSignInRefusalNamesUseKey pins SR-9's sign-in refusal: an
// organization that issues no member keys sends the member to an admin and
// to the two ways to use the key the admin gives.
func TestSDKSignInRefusalNamesUseKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no SDK key file on windows")
	}
	_, err := sdkSignIn(context.Background(), sdkcredsvc.Service{Dir: filepath.Join(t.TempDir(), "sdk")}, notSupportedMinter{})
	if err == nil {
		t.Fatal("sign-in succeeded")
	}
	for _, want := range []string{"ask an admin", "Machine identities", "observer sdk use-key --gateway-url <address>", "stdin", "SUPERBASED_API_KEY", "SUPERBASED_ORG_URL", "SUPERBASED_DESTINATION=both"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal lacks %q: %v", want, err)
		}
	}
}

// TestWithoutErr: the printed notice is taken out of an errors.Join tree and
// everything else is kept.
func TestWithoutErr(t *testing.T) {
	other := errors.New("remove sdk-credential: busy")
	cases := []struct {
		name string
		in   error
		want error
	}{
		{"nil", nil, nil},
		{"the notice alone", sdkcredsvc.ErrAdminIssuedKeyKept, nil},
		{"the notice joined alone", errors.Join(sdkcredsvc.ErrAdminIssuedKeyKept), nil},
		{"another error", other, other},
	}
	for _, tc := range cases {
		if got := withoutErr(tc.in, sdkcredsvc.ErrAdminIssuedKeyKept); !errors.Is(got, tc.want) || (tc.want == nil) != (got == nil) {
			t.Errorf("%s: got %v", tc.name, got)
		}
	}
	got := withoutErr(errors.Join(other, sdkcredsvc.ErrAdminIssuedKeyKept), sdkcredsvc.ErrAdminIssuedKeyKept)
	if !errors.Is(got, other) || errors.Is(got, sdkcredsvc.ErrAdminIssuedKeyKept) {
		t.Fatalf("joined: %v", got)
	}
}

type notSupportedMinter struct{ doctorMinter }

func (notSupportedMinter) MintSDKCredential(context.Context, orgcontract.SDKCredentialRequest) (orgcontract.SDKCredentialMinted, error) {
	return orgcontract.SDKCredentialMinted{}, orgclient.ErrSDKCredentialNotSupported
}
