package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/signerd"
)

func TestResolveDocSignerConfig(t *testing.T) {
	t.Parallel()
	creds := t.TempDir()
	// Only the two required credentials exist in this directory.
	for _, name := range []string{signerd.EntitlementsKeyCredential, signerd.AvailabilityKeyCredential} {
		if err := os.WriteFile(filepath.Join(creds, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name     string
		uid      string
		flags    map[signerd.Purpose][]string
		env      map[string]string
		wantErr  string
		wantKeys map[signerd.Purpose][]string
		wantSock string
	}{
		{
			name: "env keys and defaults", uid: "1002",
			env: map[string]string{
				"SBCI_DOC_SIGNER_ENTITLEMENTS_KEY": "/e1.pem, /e2.pem", "SBCI_DOC_SIGNER_AVAILABILITY_KEY": "/a.pem",
			},
			wantKeys: map[signerd.Purpose][]string{
				signerd.PurposeEntitlements: {"/e1.pem", "/e2.pem"}, signerd.PurposeAvailability: {"/a.pem"}, signerd.PurposeHostAPI: nil,
			},
			wantSock: defaultDocSignerSocket,
		},
		{
			name: "flags win over env", uid: "1002",
			flags: map[signerd.Purpose][]string{signerd.PurposeEntitlements: {"/flag.pem"}, signerd.PurposeAvailability: {"/fa.pem"}, signerd.PurposeHostAPI: {"/h.pem"}},
			env:   map[string]string{"SBCI_DOC_SIGNER_ENTITLEMENTS_KEY": "/env.pem", "SBCI_DOC_SIGNER_SOCKET": "/run/d.sock"},
			wantKeys: map[signerd.Purpose][]string{
				signerd.PurposeEntitlements: {"/flag.pem"}, signerd.PurposeAvailability: {"/fa.pem"}, signerd.PurposeHostAPI: {"/h.pem"},
			},
			wantSock: "/run/d.sock",
		},
		{
			name: "systemd credentials; the optional host-API one absent", uid: "1002",
			env: map[string]string{"CREDENTIALS_DIRECTORY": creds},
			wantKeys: map[signerd.Purpose][]string{
				signerd.PurposeEntitlements: {filepath.Join(creds, signerd.EntitlementsKeyCredential)},
				signerd.PurposeAvailability: {filepath.Join(creds, signerd.AvailabilityKeyCredential)},
				signerd.PurposeHostAPI:      nil,
			},
			wantSock: defaultDocSignerSocket,
		},
		{name: "no availability key", uid: "1002", env: map[string]string{"SBCI_DOC_SIGNER_ENTITLEMENTS_KEY": "/e.pem"}, wantErr: "no availability key"},
		{name: "uid 0", uid: "0", env: map[string]string{"SBCI_DOC_SIGNER_ENTITLEMENTS_KEY": "/e.pem"}, wantErr: "uid 0"},
		{name: "uid missing", env: map[string]string{}, wantErr: "SBCI_DOC_SIGNER_ALLOW_UID"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveDocSignerConfig("", "", tc.uid, tc.flags, envMap(tc.env))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.keyPaths, tc.wantKeys) || got.socket != tc.wantSock || got.state != defaultDocSignerState {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

// TestSignerDocumentIsRegistered pins that `signer document` is reachable.
func TestSignerDocumentIsRegistered(t *testing.T) {
	t.Parallel()
	for _, c := range newSignerCmd().Commands() {
		if c.Name() == "document" {
			for _, sub := range []string{"serve", "keygen", "public-key"} {
				if found, _, err := c.Find([]string{sub}); err != nil || found.Name() != sub {
					t.Errorf("signer document %s is not registered", sub)
				}
			}
			return
		}
	}
	t.Fatal("observer-cloud signer has no `document` subcommand")
}
