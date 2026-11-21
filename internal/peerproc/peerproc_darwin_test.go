//go:build darwin

package peerproc

import (
	"os"
	"testing"
)

// TestStartTokenDarwin (callerid fixes-1, L2): stable for one process,
// absent for a pid that is gone.
func TestStartTokenDarwin(t *testing.T) {
	a, ok := StartToken(os.Getpid())
	b, ok2 := StartToken(os.Getpid())
	if !ok || !ok2 || a == "" || a != b {
		t.Fatalf("tokens %q %q (%v %v)", a, b, ok, ok2)
	}
	if _, ok := StartToken(1 << 30); ok {
		t.Fatal("a pid that cannot exist has a token")
	}
}
