package listenhandover

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func TestClaimFrom(t *testing.T) {
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	cases := []struct {
		name    string
		env     map[string]string
		fileOK  bool
		want    bool
		unsetOK bool
	}{
		{"no hand-over", map[string]string{}, true, false, false},
		{"a hand-over", map[string]string{EnvFD: "7", EnvAddr: "127.0.0.1:8820"}, true, true, true},
		{"a descriptor that is not open", map[string]string{EnvFD: "7", EnvAddr: "127.0.0.1:8820"}, false, false, true},
		{"no address", map[string]string{EnvFD: "7"}, true, false, true},
		{"a number that does not parse", map[string]string{EnvFD: "x", EnvAddr: "127.0.0.1:8820"}, true, false, true},
		{"stdin, stdout or stderr is never a socket of ours", map[string]string{EnvFD: "2", EnvAddr: "127.0.0.1:8820"}, true, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := map[string]string{}
			for k, v := range c.env {
				env[k] = v
			}
			in := claimFrom(claimEnv{
				getenv:   func(k string) string { return env[k] },
				unsetenv: func(k string) error { delete(env, k); return nil },
				file: func(int) *os.File {
					if c.fileOK {
						return devnull
					}
					return nil
				},
			})
			if (in != nil) != c.want {
				t.Fatalf("claim = %+v, want claimed=%v", in, c.want)
			}
			if c.unsetOK && (env[EnvFD] != "" || env[EnvAddr] != "") {
				t.Fatalf("the hand-over variables were left for a child to see: %v", env)
			}
			if in != nil && in.Addr != "127.0.0.1:8820" {
				t.Fatalf("addr = %q", in.Addr)
			}
		})
	}
}

func TestSameAddr(t *testing.T) {
	cases := []struct {
		want, got string
		same      bool
	}{
		{"127.0.0.1:8820", "127.0.0.1:8820", true},
		{"localhost:8820", "127.0.0.1:8820", true},
		{":8820", "[::]:8820", true},
		{"0.0.0.0:8820", "0.0.0.0:8820", true},
		{"127.0.0.1:8820", "127.0.0.1:8821", false},
		{"127.0.0.1:8820", "192.168.1.5:8820", false},
		{"bad", "127.0.0.1:8820", false},
	}
	for _, c := range cases {
		if got := SameAddr(c.want, c.got); got != c.same {
			t.Errorf("SameAddr(%q, %q) = %v, want %v", c.want, c.got, got, c.same)
		}
	}
}

// TestListenAdoptsOnlyAMatchingSocket: the inherited socket serves only the
// address the proxy is configured for; a mismatch is closed and the proxy
// binds as before.
func TestListenAdoptsOnlyAMatchingSocket(t *testing.T) {
	if !Supported() {
		t.Skip("no hand-over on this OS")
	}
	old, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := old.Addr().String()
	f, err := Prepare(NewPausable(old))
	if err != nil {
		t.Fatal(err)
	}
	_ = old.Close()

	ln, adopted, err := Listen(&Inherited{file: f, Addr: addr}, addr)
	if err != nil || !adopted {
		t.Fatalf("Listen = %v adopted=%v", err, adopted)
	}
	if ln.Addr().String() != addr {
		t.Fatalf("adopted %s, want %s", ln.Addr(), addr)
	}
	// Hand it over again, to a proxy now configured for another port.
	f2, err := Prepare(ln)
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
	ln2, adopted, err := Listen(&Inherited{file: f2, Addr: addr}, "127.0.0.1:0")
	if err != nil || adopted {
		t.Fatalf("Listen on another port = %v adopted=%v, want a fresh bind", err, adopted)
	}
	defer ln2.Close()
	// The mismatched socket was closed: its port no longer accepts.
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		_ = c.Close()
		t.Fatal("the socket the new image did not adopt still listens")
	}
	if ln, adopted, err := Listen(nil, "127.0.0.1:0"); err != nil || adopted {
		t.Fatalf("Listen with nothing inherited = %v adopted=%v", err, adopted)
	} else {
		_ = ln.Close()
	}
}

func TestPausableWaitsForClose(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := NewPausable(raw)
	p.Pause()
	done := make(chan error, 1)
	go func() {
		c, err := p.Accept()
		if c != nil {
			_ = c.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("a paused Accept returned %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	_ = p.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept after Close = %v, want net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a paused Accept did not end on Close")
	}
}

func TestWithVarsReplaces(t *testing.T) {
	env := WithVars([]string{"A=1", EnvFD + "=9", EnvAddr + "=x"}, 5, "127.0.0.1:8820")
	want := []string{"A=1", EnvFD + "=5", EnvAddr + "=127.0.0.1:8820"}
	if len(env) != len(want) {
		t.Fatalf("env = %v", env)
	}
	for i := range want {
		if env[i] != want[i] {
			t.Fatalf("env = %v, want %v", env, want)
		}
	}
}
