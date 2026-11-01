package sandboxrelay

import (
	"errors"
	"io"
	"net"
	"testing"
)

// TestAcceptNoHello: a peer that hangs up before its hello, before or after
// reading the preamble (the CLI's relay readiness check, Windows 11 Pro run
// 4), is ErrNoHello, not a refused handshake; a peer that sends a bad hello
// is still a refused handshake.
func TestAcceptNoHello(t *testing.T) {
	t.Parallel()
	lookup := func(string) ([]byte, error) { return testSecret, nil }

	a, b := net.Pipe()
	_ = b.Close()
	if _, err := Accept(a, testParams(PurposeLink), lookup); !errors.Is(err, ErrNoHello) || errors.Is(err, ErrHandshake) {
		t.Fatalf("closed before the preamble: %v", err)
	}
	_ = a.Close()

	a, b = net.Pipe()
	go func() {
		buf := make([]byte, preambleSize)
		_, _ = io.ReadFull(b, buf)
		_ = b.Close()
	}()
	if _, err := Accept(a, testParams(PurposeLink), lookup); !errors.Is(err, ErrNoHello) {
		t.Fatalf("closed after the preamble: %v", err)
	}
	_ = a.Close()

	a, b = net.Pipe()
	go func() {
		buf := make([]byte, preambleSize)
		_, _ = io.ReadFull(b, buf)
		_, _ = b.Write([]byte("XXXX\x01\x01\x02"))
	}()
	if _, err := Accept(a, testParams(PurposeLink), lookup); errors.Is(err, ErrNoHello) || !errors.Is(err, ErrHandshake) {
		t.Fatalf("a malformed hello: %v", err)
	}
	_ = a.Close()
	_ = b.Close()
}
