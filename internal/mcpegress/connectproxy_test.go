package mcpegress

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/netpolicy"
)

// connectVia opens a CONNECT tunnel to target through the proxy at proxyAddr
// and returns the status line the proxy answered with plus the tunnel.
func connectVia(t *testing.T, proxyAddr, target string) (string, net.Conn) {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.ReadAll(resp.Body) // an error answer carries a bounded body; a 200 opens the tunnel
	}
	return resp.Status, c
}

func TestConnectProxyPolicyTable(t *testing.T) {
	// An upstream on loopback: refused by the default policy, admitted by
	// the exact-authority allow-list, admitted by an unlocked policy; a
	// metadata address is refused under every posture; a rebinding name is
	// checked per resolved address.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("hi")) }))
	defer upstream.Close()
	upHost := strings.TrimPrefix(upstream.URL, "http://")
	resolver := func(_ context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "meta.example":
			return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
		case "rebind.example":
			return []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("127.0.0.1")}, nil
		case "nx.example":
			return nil, errors.New("nxdomain")
		}
		return net.DefaultResolver.LookupNetIP(context.Background(), "ip", host)
	}
	cases := []struct {
		name   string
		opts   ConnectProxyOptions
		target string
		want   string // status prefix
		tunnel bool
	}{
		{"loopback refused by default", ConnectProxyOptions{Resolver: resolver}, upHost, "403", false},
		{"loopback allow-listed", ConnectProxyOptions{Resolver: resolver, Allow: []string{upHost}}, upHost, "200", true},
		{"loopback unlocked policy", ConnectProxyOptions{Resolver: resolver, Policy: netpolicy.DialPolicy{AllowLoopback: true, AllowPrivate: true}}, upHost, "200", true},
		{"metadata never, even allow-listed", ConnectProxyOptions{Resolver: resolver, Allow: []string{"meta.example:80"}, Policy: netpolicy.DialPolicy{AllowLoopback: true, AllowPrivate: true}}, "meta.example:80", "403", false},
		{"rebinding answer checked per address", ConnectProxyOptions{Resolver: resolver}, "rebind.example:80", "403", false},
		{"resolve failure", ConnectProxyOptions{Resolver: resolver}, "nx.example:80", "502", false},
		{"bad authority", ConnectProxyOptions{Resolver: resolver}, "no-port", "403", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := NewConnectProxy(tc.opts)
			srv := httptest.NewServer(p)
			defer srv.Close()
			status, c := connectVia(t, strings.TrimPrefix(srv.URL, "http://"), tc.target)
			defer c.Close()
			if !strings.HasPrefix(status, tc.want) {
				t.Fatalf("status %q, want prefix %q", status, tc.want)
			}
			if tc.tunnel {
				fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", tc.target)
				body, _ := io.ReadAll(c)
				if !strings.Contains(string(body), "hi") {
					t.Fatalf("tunnel body %q", body)
				}
			}
			logs := p.Recent()
			if len(logs) != 1 || logs[0].Allowed != tc.tunnel || logs[0].Target != tc.target {
				t.Fatalf("log = %+v", logs)
			}
			if tc.tunnel && logs[0].Dialed == "" {
				t.Fatal("allowed attempt recorded no dialed address")
			}
			attempts, refused := p.Stats()
			if attempts != 1 || (refused == 0) != tc.tunnel {
				t.Fatalf("stats attempts=%d refused=%d", attempts, refused)
			}
		})
	}
}

func TestConnectProxyRefusesNonConnect(t *testing.T) {
	p := NewConnectProxy(ConnectProxyOptions{})
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET through the egress proxy = %d", rr.Code)
	}
}

func TestConnectProxyCheckDialsTheCheckedLiteral(t *testing.T) {
	p := NewConnectProxy(ConnectProxyOptions{Resolver: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}})
	dial, resolved, err := p.Check(context.Background(), "example.com:443")
	if err != nil || dial != "93.184.216.34:443" || len(resolved) != 1 {
		t.Fatalf("dial=%q resolved=%v err=%v", dial, resolved, err)
	}
	if _, _, err := p.Check(context.Background(), "10.0.0.8:443"); !errors.Is(err, ErrEgressRefused) {
		t.Fatalf("private literal: %v", err)
	}
}
