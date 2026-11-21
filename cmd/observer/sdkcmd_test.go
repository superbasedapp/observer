package main

import (
	"bytes"
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestSDKSignOutAllAsksFirst pins review E-28 (ruling D29): `observer sdk
// sign-out --all` revokes every key only after a confirmation (or --yes); an
// unconfirmed run stops before it opens the database or calls the org.
func TestSDKSignOutAllAsksFirst(t *testing.T) {
	cmd := newSDKSignOutCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetIn(strings.NewReader("n\n"))
	cmd.SetArgs([]string{"--all", "--config", filepath.Join(t.TempDir(), "missing.toml")})
	err := cmd.ExecuteContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not confirmed; nothing was revoked") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(out.String(), "Revoke every SDK key you have") {
		t.Fatalf("no question asked: %q", out.String())
	}
}

type doctorMinter struct {
	minted orgcontract.SDKCredentialMinted
}

func (d doctorMinter) MintSDKCredential(context.Context, orgcontract.SDKCredentialRequest) (orgcontract.SDKCredentialMinted, error) {
	return d.minted, nil
}

func (d doctorMinter) RevokeSDKCredential(context.Context, orgcontract.SDKCredentialRequest) (orgcontract.SDKCredentialRevoked, error) {
	return orgcontract.SDKCredentialRevoked{}, nil
}

// TestSDKKeyDoctorRow pins review E-59: the sdk.key doctor row is OK with
// no key, WARN within 14 days of expiry.
func TestSDKKeyDoctorRow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no SDK key file on windows")
	}
	cfg := config.Default()
	cfg.Observer.DBPath = filepath.Join(t.TempDir(), "observer.db")
	if c := sdkKeyDoctorCheck(cfg); c.Name != sdkKeyCheckName || c.Status != diag.StatusOK {
		t.Fatalf("no key: %+v", c)
	}
	svc := sdkCredentialService(cfg, nil)
	svc.Keychain = nil
	exp := time.Now().Add(5 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if _, err := svc.SignIn(context.Background(), doctorMinter{orgcontract.SDKCredentialMinted{
		KeyID: "ik_a", Credential: "ik_a.secretValue", GatewayURL: "https://gw.example.com", ExpiresAt: exp,
	}}); err != nil {
		t.Fatal(err)
	}
	if c := sdkKeyDoctorCheck(cfg); c.Status != diag.StatusWarn || !strings.Contains(c.Message, "expires on") {
		t.Fatalf("expiring: %+v", c)
	}
}
