//go:build unix

package sandboxnet

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestStampHopHalfClose (tracker row F-010, audit N3-A4): a box client that
// shuts down its write side after sending the request still reads the
// whole response through the hop, slow upstream included, as it does
// through the raw pipe the hop replaces.
func TestStampHopHalfClose(t *testing.T) {
	for _, tc := range []struct {
		name  string
		delay time.Duration
	}{
		{"prompt answer", 0},
		{"slow answer", 300 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newStampRig(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				time.Sleep(tc.delay)
				w.Header().Set("Content-Type", "text/plain")
				_, _ = io.WriteString(w, "whole-answer:"+r.Header.Get(tRunHeader))
			})
			c, err := net.DialTimeout("tcp", rig.boxAddr, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			req := "POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:8820\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
			if _, err := io.WriteString(c, req); err != nil {
				t.Fatal(err)
			}
			if err := c.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			b, err := io.ReadAll(c)
			if err != nil {
				t.Fatalf("read after half-close: %v (got %q)", err, b)
			}
			if !strings.HasPrefix(string(b), "HTTP/1.1 200") || !strings.Contains(string(b), "whole-answer:run-A") {
				t.Fatalf("response after half-close: %q", b)
			}
		})
	}
}

// TestStampHopBoxGoneEndsTheStream: the half-close fix must not keep a
// stream alive for a box that is really gone. A box that closes its whole
// connection mid-stream ends the upstream request at the next write.
func TestStampHopBoxGoneEndsTheStream(t *testing.T) {
	ended := make(chan struct{})
	rig := newStampRig(t, func(w http.ResponseWriter, r *http.Request) {
		defer close(ended)
		fl := w.(http.Flusher)
		for {
			if _, err := io.WriteString(w, "data: tick\n\n"); err != nil {
				return
			}
			fl.Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	})
	c, err := net.DialTimeout("tcp", rig.boxAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, "GET /v1/stream HTTP/1.1\r\nHost: 127.0.0.1:8820\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	if _, err := c.Read(buf); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the upstream stream outlived the box's connection")
	}
}

// TestStampHopCloseEndsRequests: closing the hop ends a request it is
// still serving.
func TestStampHopCloseEndsRequests(t *testing.T) {
	started, ended := make(chan struct{}), make(chan struct{})
	rig := newStampRig(t, func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(ended)
	})
	c, err := net.DialTimeout("tcp", rig.boxAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := io.WriteString(c, "GET /v1/wait HTTP/1.1\r\nHost: 127.0.0.1:8820\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	<-started
	_ = rig.hop.Close()
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("a request outlived the hop")
	}
}
