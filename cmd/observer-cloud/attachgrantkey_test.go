package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAttachGrantKey(t *testing.T) {
	dir := t.TempDir()
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := write("good", hex.EncodeToString(seed)+"\n")
	cases := []struct {
		name    string
		path    string
		wantKey bool
		wantErr bool
	}{
		{name: "unset is no key", path: ""},
		{name: "a hex seed", path: good, wantKey: true},
		{name: "missing file", path: filepath.Join(dir, "absent"), wantErr: true},
		{name: "not hex", path: write("bad", "not-a-seed"), wantErr: true},
		{name: "short seed", path: write("short", hex.EncodeToString(seed[:16])), wantErr: true},
		{name: "a directory", path: dir, wantErr: true},
		{name: "oversized", path: write("big", strings.Repeat("a", maxAttachGrantKeyFile+1)), wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k, err := loadAttachGrantKey(tc.path)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if (k != nil) != tc.wantKey {
				t.Fatalf("key present = %v, want %v", k != nil, tc.wantKey)
			}
		})
	}
	k, err := loadAttachGrantKey(good)
	if err != nil {
		t.Fatal(err)
	}
	if !k.Equal(ed25519.NewKeyFromSeed(seed)) || len(attachGrantKeyID(k)) != 43 {
		t.Fatal("the loaded key is not the seed's key")
	}
}
