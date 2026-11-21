package netguard

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/netpolicy"
)

// TestPolicyCheckIP is the deny/allow table: metadata, link-local, multicast
// and unspecified are refused under every policy; loopback and private only
// when a class or an allow-listed CIDR admits them; public always passes.
func TestPolicyCheckIP(t *testing.T) {
	allow10, _ := ParseCIDRs([]string{"10.1.0.0/16", "127.0.0.1"})
	cases := []struct {
		name   string
		ip     string
		policy Policy
		ok     bool
	}{
		{"public v4", "8.8.8.8", Policy{}, true},
		{"public v6", "2606:4700::1111", Policy{}, true},
		{"cloud metadata", "169.254.169.254", Policy{}, false},
		{"metadata even with every class", "169.254.169.254", Policy{Classes: netpolicy.DialPolicy{AllowLoopback: true, AllowPrivate: true}}, false},
		{"metadata via NAT64", "64:ff9b::a9fe:a9fe", Policy{}, false},
		{"metadata via v4-mapped", "::ffff:169.254.169.254", Policy{}, false},
		{"link-local v6", "fe80::1", Policy{}, false},
		{"multicast", "224.0.0.1", Policy{}, false},
		{"unspecified", "0.0.0.0", Policy{}, false},
		{"loopback denied by default", "127.0.0.1", Policy{}, false},
		{"loopback v6 denied by default", "::1", Policy{}, false},
		{"rfc1918 denied by default", "10.1.2.3", Policy{}, false},
		{"v4-mapped rfc1918 denied", "::ffff:10.1.2.3", Policy{}, false},
		{"cgnat denied by default", "100.64.0.1", Policy{}, false},
		{"ula denied by default", "fd00::1", Policy{}, false},
		{"rfc1918 inside an allowed cidr", "10.1.2.3", Policy{AllowCIDRs: allow10}, true},
		{"v4-mapped inside an allowed cidr", "::ffff:10.1.2.3", Policy{AllowCIDRs: allow10}, true},
		{"rfc1918 outside the allowed cidr", "10.2.0.1", Policy{AllowCIDRs: allow10}, false},
		{"allowed loopback address", "127.0.0.1", Policy{AllowCIDRs: allow10}, true},
		{"private class unlock", "192.168.1.1", Policy{Classes: netpolicy.DialPolicy{AllowPrivate: true}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.policy.CheckIP(tc.ip, net.ParseIP(tc.ip))
			if (err == nil) != tc.ok {
				t.Fatalf("CheckIP(%s) = %v, want ok=%v", tc.ip, err, tc.ok)
			}
			if err != nil && (!errors.Is(err, ErrRefused) || !errors.Is(err, netpolicy.ErrDialRefused)) {
				t.Errorf("refusal %v does not wrap ErrRefused and netpolicy.ErrDialRefused", err)
			}
		})
	}
}

// TestParseCIDRs: only loopback or private ranges can be allow-listed.
func TestParseCIDRs(t *testing.T) {
	cases := []struct {
		in []string
		ok bool
	}{
		{[]string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8", "127.0.0.1", ""}, true},
		{[]string{"169.254.0.0/16"}, false},
		{[]string{"0.0.0.0/0"}, false},
		{[]string{"8.8.8.0/24"}, false},
		{[]string{"not-a-cidr"}, false},
	}
	for _, tc := range cases {
		t.Run(strings.Join(tc.in, ","), func(t *testing.T) {
			_, err := ParseCIDRs(tc.in)
			if (err == nil) != tc.ok {
				t.Fatalf("ParseCIDRs(%v) = %v, want ok=%v", tc.in, err, tc.ok)
			}
		})
	}
}

// TestControlFailsClosed pins the dial hook's edges.
func TestControlFailsClosed(t *testing.T) {
	hook := Control(Policy{}.CheckIP)
	for _, tc := range []struct{ name, network, address, want string }{
		{"udp refused", "udp", "8.8.8.8:53", "non-TCP"},
		{"no port", "tcp", "8.8.8.8", "unparseable"},
		{"not a literal", "tcp", "example.com:443", "not an IP literal"},
		{"metadata refused", "tcp", "169.254.169.254:80", "never permitted"},
		{"public allowed", "tcp", "8.8.8.8:443", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := hook(tc.network, tc.address, nil)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("unexpected refusal: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) || !errors.Is(err, ErrRefused) {
				t.Fatalf("err = %v, want ErrRefused containing %q", err, tc.want)
			}
		})
	}
}

// loopbackPolicy admits the httptest server's loopback address the way an
// operator's allow-list would.
func loopbackPolicy(t *testing.T) Policy {
	t.Helper()
	p, err := ParseCIDRs([]string{"127.0.0.0/8", "::1"})
	if err != nil {
		t.Fatal(err)
	}
	return Policy{AllowCIDRs: p}
}

// TestDialTimeCheckRefusesLoopbackByDefault: the guard runs at dial time, on
// the resolved address, for a hostname the pre-flight never saw.
func TestDialTimeCheckRefusesLoopbackByDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	url := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	cases := []struct {
		name   string
		policy Policy
		ok     bool
	}{
		{"default policy refuses loopback", Policy{}, false},
		{"allow-listed loopback reaches it", loopbackPolicy(t), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := NewClient(Options{Policy: tc.policy}).Get(url)
			if resp != nil {
				_ = resp.Body.Close()
			}
			if (err == nil) != tc.ok {
				t.Fatalf("GET = %v, want ok=%v", err, tc.ok)
			}
			if err != nil && !errors.Is(err, ErrRefused) {
				t.Errorf("err %v does not wrap ErrRefused", err)
			}
		})
	}
}

// TestRedirectRule: a redirect to a metadata IP is refused even from an
// allowed origin, as is a downgrade, a non-http scheme and an endless chain.
func TestRedirectRule(t *testing.T) {
	cases := []struct {
		name     string
		location string
		max      int
		wantErr  string
	}{
		{"redirect to cloud metadata", "http://169.254.169.254/latest/meta-data/", 0, "never permitted"},
		{"redirect to v6 link-local", "http://[fe80::1]/", 0, "never permitted"},
		{"redirect to a private literal", "http://10.0.0.5/", 0, "outside this upstream"},
		{"redirect to file scheme", "file:///etc/passwd", 0, "scheme"},
		{"redirects refused outright", "/next", -1, "refusing redirect"},
		{"endless chain stops", "/loop", 0, "stopped after"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, tc.location, http.StatusFound)
			}))
			defer srv.Close()
			c := NewClient(Options{Policy: loopbackPolicy(t), MaxRedirects: tc.max, Timeout: 5 * time.Second})
			resp, err := c.Get(srv.URL)
			if resp != nil {
				_ = resp.Body.Close()
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("GET err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
	// A downgrade is judged from the chain's first hop.
	rule := redirectRule(0, Policy{}.CheckIP)
	first := &http.Request{URL: mustURL(t, "https://hooks.example.com/a")}
	next := &http.Request{URL: mustURL(t, "http://hooks.example.com/b")}
	if err := rule(next, []*http.Request{first}); err == nil || !strings.Contains(err.Error(), "https to http") {
		t.Fatalf("downgrade err = %v", err)
	}
}

// TestDefaultClient: the process client has a non-zero timeout, honours the
// configured allow-list, and Configure refuses a bad range without changing
// the list in force.
func TestDefaultClient(t *testing.T) {
	t.Cleanup(func() { _ = Configure(nil) })
	if c := Client(0); c.Timeout <= 0 {
		t.Fatalf("default client timeout = %v", c.Timeout)
	}
	if c := Client(7 * time.Second); c.Timeout != 7*time.Second {
		t.Fatalf("timeout = %v", c.Timeout)
	}
	first, second := Client(7*time.Second), Client(7*time.Second)
	if first != second {
		t.Fatal("repeated calls built separate clients")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	get := func() error {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
		resp, err := Client(5 * time.Second).Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		return err
	}
	if err := get(); err == nil || !strings.Contains(err.Error(), "allow_private_cidrs") {
		t.Fatalf("unlisted loopback GET = %v, want a refusal naming the knob", err)
	}
	if err := Configure([]string{"127.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	if err := get(); err != nil {
		t.Fatalf("allow-listed loopback GET = %v", err)
	}
	if err := Configure([]string{"169.254.169.254"}); err == nil {
		t.Fatal("a metadata range was accepted")
	}
	if err := get(); err != nil {
		t.Fatalf("a refused Configure changed the list in force: %v", err)
	}
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
