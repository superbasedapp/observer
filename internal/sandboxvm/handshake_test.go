package sandboxvm

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

func TestConnectRequest(t *testing.T) {
	b, err := ConnectRequest(1024)
	if err != nil || string(b) != "CONNECT 1024\n" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := ConnectRequest(0); err == nil {
		t.Fatal("port 0 accepted")
	}
}

// TestReadConnectAnswer is one case per answer shape the VMM can give.
func TestReadConnectAnswer(t *testing.T) {
	cases := []struct {
		in   string
		port uint32
		err  error
	}{
		{"OK 1073741824\n", 1 << 30, nil},
		{"OK 1073741825\nSBM1...", 1<<30 + 1, nil},
		{"", 0, ErrVsockRefused},
		{"OK 10737", 0, ErrVsockRefused},
		{"OK 1023\n", 0, ErrVsockMalformed},
		{"ok 1073741824\n", 0, ErrVsockMalformed},
		{"OK\n", 0, ErrVsockMalformed},
		{"OK 01073741824\n", 0, ErrVsockMalformed},
		{"OK 99999999999\n", 0, ErrVsockMalformed},
		{"OK 1073741824 \n", 0, ErrVsockMalformed},
		{"ERR\n", 0, ErrVsockMalformed},
		{"OKOKOKOKOKOKOKOKOKOKOKOKOKOKOKOKOKOK", 0, ErrVsockMalformed},
	}
	for _, tc := range cases {
		port, err := ReadConnectAnswer(bytes.NewReader([]byte(tc.in)))
		if port != tc.port || !errors.Is(err, tc.err) && !(err == nil && tc.err == nil) {
			t.Errorf("%q: %d %v, want %d %v", tc.in, port, err, tc.port, tc.err)
		}
	}
}

// TestReadConnectAnswerStopsAtTheNewline: the relay mux's first bytes after
// the answer stay unread, even fed one byte per read.
func TestReadConnectAnswerStopsAtTheNewline(t *testing.T) {
	r := bytes.NewReader([]byte("OK 1073741900\nREST"))
	if _, err := ReadConnectAnswer(iotest.OneByteReader(r)); err != nil {
		t.Fatal(err)
	}
	rest, _ := io.ReadAll(r)
	if string(rest) != "REST" {
		t.Fatalf("left %q", rest)
	}
}

// FuzzConnectAnswer: no input crashes the reader; an accepted answer is
// always OK <port>\n with port at or above HostPortMin.
func FuzzConnectAnswer(f *testing.F) {
	for _, s := range []string{"OK 1073741824\n", "", "OK 1\n", "OK 4294967295\n", "OK 4294967296\n", "ok 1073741824\n", "CONNECT 5\n", "OK 1073741824", "\n", "OK \n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		port, err := ReadConnectAnswer(bytes.NewReader(b))
		if err != nil {
			if port != 0 {
				t.Fatalf("error with port %d", port)
			}
			return
		}
		if port < HostPortMin {
			t.Fatalf("accepted port %d", port)
		}
		i := bytes.IndexByte(b, '\n')
		if i < 0 || !bytes.HasPrefix(b, []byte("OK ")) {
			t.Fatalf("accepted %q", b)
		}
	})
}
