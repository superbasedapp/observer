//go:build !linux

package signerd_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/signerd"
)

// TestSignerRefusesToStartWithoutPeerCred: off Linux there is no SO_PEERCRED,
// so the socket listener refuses to start.
func TestSignerRefusesToStartWithoutPeerCred(t *testing.T) {
	t.Parallel()
	if _, err := signerd.ListenUnix(filepath.Join(t.TempDir(), "s.sock")); !errors.Is(err, signerd.ErrPeerCredUnsupported) {
		t.Fatalf("ListenUnix = %v, want ErrPeerCredUnsupported", err)
	}
	if _, err := signerd.PeerCredUID(nil); !errors.Is(err, signerd.ErrPeerCredUnsupported) {
		t.Fatalf("PeerCredUID = %v", err)
	}
}
