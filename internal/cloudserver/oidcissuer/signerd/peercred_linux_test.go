//go:build linux

package signerd_test

import (
	"context"
	"crypto/rsa"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/oidctest"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/signerd"
)

// TestSignerPeerCredOverUnixSocket runs the real listener and the real
// SO_PEERCRED check: our own uid is served, any other configured uid is
// refused.
func TestSignerPeerCredOverUnixSocket(t *testing.T) {
	t.Parallel()
	key := oidctest.NewKey(t)
	local, err := oidcissuer.NewLocalSigner(testIssuer, []*rsa.PrivateKey{key}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		allow int
		ok    bool
	}{
		{"own uid", os.Getuid(), true},
		{"other uid", os.Getuid() + 1, false},
	} {
		path := filepath.Join(t.TempDir(), "signer.sock")
		ln, err := signerd.ListenUnix(path)
		if err != nil {
			t.Fatalf("%s: ListenUnix: %v", tc.name, err)
		}
		fi, err := os.Stat(path)
		if err != nil || fi.Mode().Perm() != 0o660 {
			t.Errorf("%s: socket mode %v (%v), want 0660", tc.name, fi.Mode().Perm(), err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		srv := &signerd.Server{Signer: local, AllowUID: tc.allow, Logger: quiet()}
		done := make(chan error, 1)
		go func() { done <- srv.Serve(ctx, ln) }()
		_, err = signerd.NewUnixClient(path).PublicKeys(context.Background())
		if tc.ok && err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		if !tc.ok && !errors.Is(err, signerd.ErrPeerRefused) {
			t.Errorf("%s: err = %v, want ErrPeerRefused", tc.name, err)
		}
		cancel()
		if err := <-done; err != nil {
			t.Errorf("%s: Serve: %v", tc.name, err)
		}
	}
}
