package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadSDKKeyGrantKey: the SDK key grant key loads by the attach grant
// key's rules, and the attach grant's own key is refused for it.
func TestLoadSDKKeyGrantKey(t *testing.T) {
	dir := t.TempDir()
	seed := func() []byte {
		b := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	sdkSeed, attachSeed := seed(), seed()
	good := write("sdk", hex.EncodeToString(sdkSeed)+"\n")
	attachFile := write("attach", hex.EncodeToString(attachSeed))
	attach := ed25519.NewKeyFromSeed(attachSeed)
	cases := []struct {
		name    string
		path    string
		attach  ed25519.PrivateKey
		wantKey bool
		wantErr bool
	}{
		{name: "unset is no key", path: ""},
		{name: "a hex seed", path: good, attach: attach, wantKey: true},
		{name: "no attach key", path: good, wantKey: true},
		{name: "the attach grant's own key", path: attachFile, attach: attach, wantErr: true},
		{name: "missing file", path: filepath.Join(dir, "absent"), wantErr: true},
		{name: "not hex", path: write("bad", "not-a-seed"), wantErr: true},
		{name: "a directory", path: dir, wantErr: true},
		{name: "oversized", path: write("big", strings.Repeat("a", maxAttachGrantKeyFile+1)), wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k, err := loadSDKKeyGrantKey(tc.path, tc.attach)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), envSDKKeyGrantKeyFile) {
				t.Fatalf("the error does not name %s: %v", envSDKKeyGrantKeyFile, err)
			}
			if (k != nil) != tc.wantKey {
				t.Fatalf("key present = %v, want %v", k != nil, tc.wantKey)
			}
		})
	}
	if _, err := loadSDKKeyGrantKey(attachFile, attach); !errors.Is(err, errSameGrantKey) {
		t.Fatalf("same key: %v", err)
	}
	k, err := loadSDKKeyGrantKey(good, attach)
	if err != nil {
		t.Fatal(err)
	}
	if !k.Equal(ed25519.NewKeyFromSeed(sdkSeed)) || len(sdkKeyGrantKeyID(k)) != 43 || sdkKeyGrantKeyID(k) == attachGrantKeyID(attach) {
		t.Fatal("the loaded key is not the seed's key")
	}
}
