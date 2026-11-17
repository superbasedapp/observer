package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/signerd"
)

func TestResolveOIDCSignerConfig(t *testing.T) {
	t.Parallel()
	const iss = "https://app.superbased.app/oauth2"
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	cases := []struct {
		name                    string
		issuer, socket, uid     string
		keys                    []string
		env                     map[string]string
		wantErr                 string
		wantSocket, wantKeyPath string
	}{
		{name: "flags", issuer: iss, uid: "1001", keys: []string{"/k.pem"}, wantSocket: defaultOIDCSignerSocket, wantKeyPath: "/k.pem"},
		{name: "env", env: map[string]string{
			"SBCI_OIDC_ISSUER": iss, "SBCI_OIDC_SIGNER_ALLOW_UID": "1001",
			"SBCI_OIDC_SIGNER_KEY": "/a.pem, /b.pem", "SBCI_OIDC_SIGNER_SOCKET": "/run/x.sock",
		}, wantSocket: "/run/x.sock", wantKeyPath: "/a.pem"},
		{
			name: "systemd credential", issuer: iss, uid: "1001", env: map[string]string{"CREDENTIALS_DIRECTORY": "/run/credentials/sig"},
			wantSocket: defaultOIDCSignerSocket, wantKeyPath: filepath.Join("/run/credentials/sig", "oidc-signing-key"),
		},
		{name: "no issuer", uid: "1001", keys: []string{"/k.pem"}, wantErr: "SBCI_OIDC_ISSUER"},
		{name: "issuer off the issuer path", issuer: "https://app.superbased.app", uid: "1001", keys: []string{"/k.pem"}, wantErr: "SBCI_OIDC_ISSUER"},
		{name: "no uid", issuer: iss, keys: []string{"/k.pem"}, wantErr: "allow-uid"},
		{name: "root uid", issuer: iss, uid: "0", keys: []string{"/k.pem"}, wantErr: "uid 0"},
		{name: "no key", issuer: iss, uid: "1001", wantErr: "no key"},
	}
	for _, tc := range cases {
		c, err := resolveOIDCSignerConfig(tc.issuer, tc.socket, tc.uid, tc.keys, env(tc.env))
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%s: err = %v, want %q", tc.name, err, tc.wantErr)
			}
			continue
		}
		if err != nil || c.socket != tc.wantSocket || len(c.keyPaths) == 0 || c.keyPaths[0] != tc.wantKeyPath || c.allowUID != 1001 {
			t.Errorf("%s: %+v, %v", tc.name, c, err)
		}
	}
}

func runSigner(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newSignerCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestSignerOIDCKeygenPublicKeyAndServe(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	key := filepath.Join(dir, "oidc.pem")
	out, err := runSigner(t, "oidc", "keygen", "--out", key)
	if err != nil {
		t.Fatalf("keygen: %v (%s)", err, out)
	}
	k, err := signerd.LoadPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	kid := oidcissuer.Thumbprint(&k.PublicKey)
	if !strings.Contains(out, "kid "+kid) {
		t.Errorf("keygen output %q does not name kid %s", out, kid)
	}
	if out, err := runSigner(t, "oidc", "keygen", "--out", key); err == nil {
		t.Errorf("keygen overwrote a key: %s", out)
	}
	out, err = runSigner(t, "oidc", "public-key", "--key", key)
	if err != nil {
		t.Fatal(err)
	}
	var jwk oidcissuer.JWK
	if err := json.Unmarshal([]byte(out), &jwk); err != nil || jwk.Kid != kid || jwk.Alg != "RS256" {
		t.Fatalf("public-key = %s (%v)", out, err)
	}

	// serve: off Linux there is no SO_PEERCRED, so it refuses to start.
	if runtime.GOOS != "linux" {
		_, err := runSigner(t, "oidc", "serve", "--issuer", "https://app.superbased.app/oauth2", "--allow-uid", "1001",
			"--key", key, "--socket", filepath.Join(dir, "s.sock"))
		if err == nil || !strings.Contains(err.Error(), "SO_PEERCRED") {
			t.Fatalf("serve off Linux = %v, want the SO_PEERCRED refusal", err)
		}
	}
}
