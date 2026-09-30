package mcpegress

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/netpolicy"
)

// recordingProxy is a forward proxy stand-in that counts every request it
// sees (absolute-form GETs and CONNECTs alike) and answers 200 "via-proxy".
func recordingProxy(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		_, _ = w.Write([]byte("via-proxy"))
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func setProxyEnv(t *testing.T, proxyURL string) {
	t.Helper()
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(k, proxyURL)
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
}

func transportOf(t *testing.T, c *http.Client) *http.Transport {
	t.Helper()
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T", c.Transport)
	}
	return tr
}

// TestAmbientProxyIgnored is the Sol fold 5 finding 1 regression: with the
// proxy environment pointing at a reachable recording proxy (the policy
// admits loopback, so the proxy dial itself would pass), a guarded client
// to a forbidden destination (cloud metadata, never unlockable) is refused
// AT THE DIAL and the proxy sees zero requests - for an env-derived proxy,
// a Base transport's proxy and a pooled client alike.
func TestAmbientProxyIgnored(t *testing.T) {
	proxy, seen := recordingProxy(t)
	setProxyEnv(t, proxy.URL)
	proxyURL, _ := url.Parse(proxy.URL)
	permissive := netpolicy.DialPolicy{AllowLoopback: true, AllowPrivate: true}
	clients := []struct {
		name string
		c    *http.Client
	}{
		{"zero config (DefaultTransport clone)", NewClient(permissive, ClientConfig{Timeout: 5 * time.Second})},
		{"base transport carrying a proxy", NewClient(permissive, ClientConfig{
			Timeout: 5 * time.Second,
			Base:    &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		})},
		{"pooled client", NewPool(ClientConfig{Timeout: 5 * time.Second}).Client(permissive)},
	}
	targets := []string{"http://169.254.169.254/latest/meta-data/", "https://169.254.169.254/latest/meta-data/"}
	for _, cl := range clients {
		for _, target := range targets {
			t.Run(cl.name+" "+target, func(t *testing.T) {
				if tr := transportOf(t, cl.c); tr.Proxy != nil {
					t.Fatal("guarded transport kept a proxy selector")
				}
				resp, err := cl.c.Get(target)
				if err == nil {
					_ = resp.Body.Close()
					t.Fatalf("forbidden destination reached: status %d", resp.StatusCode)
				}
				if !errors.Is(err, netpolicy.ErrDialRefused) {
					t.Fatalf("want a dial-time refusal, got %v", err)
				}
			})
		}
	}
	if got := seen.Load(); got != 0 {
		t.Fatalf("the ambient proxy saw %d requests; want 0", got)
	}
}

// TestExplicitProxyHonoured: WithExplicitProxy routes every request through
// the operator's trusted proxy - even under the strictest policy, because
// the dial to the trusted proxy is checked against the proxy policy
// (loopback admitted) - while a generic ClientConfig.Proxy selector's dial
// is checked against the client's own policy (fail closed on loopback).
func TestExplicitProxyHonoured(t *testing.T) {
	proxy, seen := recordingProxy(t)
	proxyURL, _ := url.Parse(proxy.URL)
	get := func(c *http.Client) (string, error) {
		resp, err := c.Get("http://upstream.example/x")
		if err != nil {
			return "", err
		}
		defer func() { _ = resp.Body.Close() }()
		b := make([]byte, 64)
		n, _ := resp.Body.Read(b)
		return string(b[:n]), nil
	}

	strict := NewClient(netpolicy.DialPolicy{}, ClientConfig{Timeout: 5 * time.Second}.WithExplicitProxy(proxyURL))
	if body, err := get(strict); err != nil || body != "via-proxy" {
		t.Fatalf("explicit proxy: body=%q err=%v", body, err)
	}
	if seen.Load() != 1 {
		t.Fatalf("explicit proxy saw %d requests, want 1", seen.Load())
	}

	generic := NewClient(netpolicy.DialPolicy{}, ClientConfig{Timeout: 5 * time.Second, Proxy: http.ProxyURL(proxyURL)})
	if _, err := get(generic); !errors.Is(err, netpolicy.ErrDialRefused) {
		t.Fatalf("generic proxy selector on loopback under the strict policy: %v", err)
	}
	unlocked := NewClient(netpolicy.DialPolicy{AllowLoopback: true}, ClientConfig{Timeout: 5 * time.Second, Proxy: http.ProxyURL(proxyURL)})
	if body, err := get(unlocked); err != nil || body != "via-proxy" {
		t.Fatalf("generic proxy selector under a loopback policy: body=%q err=%v", body, err)
	}
	if seen.Load() != 2 {
		t.Fatalf("proxy saw %d requests, want 2", seen.Load())
	}
}

// TestExplicitProxyNeverForbidden: a trusted proxy on a link-local / metadata
// address is still refused at the dial.
func TestExplicitProxyNeverForbidden(t *testing.T) {
	u, _ := url.Parse("http://169.254.169.254:3128")
	c := NewClient(netpolicy.DialPolicy{AllowLoopback: true, AllowPrivate: true}, ClientConfig{Timeout: 5 * time.Second}.WithExplicitProxy(u))
	resp, err := c.Get("http://upstream.example/")
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("metadata-address proxy reached")
	}
	if !errors.Is(err, netpolicy.ErrDialRefused) {
		t.Fatalf("want a dial-time refusal, got %v", err)
	}
}

// TestExplicitProxyThroughConnectProxy is the recommended composition: the
// guarded client's explicit proxy is the egress-role ConnectProxy, which
// makes the destination decision per resolved address - a hostname that
// resolves to cloud metadata is refused there, an allow-listed upstream is
// tunnelled.
func TestExplicitProxyThroughConnectProxy(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("upstream")) }))
	defer upstream.Close()
	_, port, _ := strings.Cut(strings.TrimPrefix(upstream.URL, "https://"), ":")
	allowed := "example.com:" + port
	cp := NewConnectProxy(ConnectProxyOptions{
		Allow: []string{allowed},
		Resolver: func(_ context.Context, host string) ([]netip.Addr, error) {
			if host == "meta.example" {
				return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
			}
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
	})
	egress := httptest.NewServer(cp)
	defer egress.Close()
	egressURL, _ := url.Parse(egress.URL)
	base := upstream.Client().Transport.(*http.Transport).Clone()
	base.TLSClientConfig = base.TLSClientConfig.Clone()
	if base.TLSClientConfig == nil {
		base.TLSClientConfig = &tls.Config{}
	}
	c := NewClient(netpolicy.DialPolicy{}, ClientConfig{Timeout: 5 * time.Second, Base: base}.WithExplicitProxy(egressURL))

	if resp, err := c.Get("https://meta.example/latest/meta-data/"); err == nil {
		_ = resp.Body.Close()
		t.Fatal("metadata-resolving host tunnelled")
	}
	resp, err := c.Get("https://" + allowed + "/")
	if err != nil {
		t.Fatalf("allow-listed upstream through the egress proxy: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if attempts, refused := cp.Stats(); attempts != 2 || refused != 1 {
		t.Fatalf("egress proxy stats attempts=%d refused=%d, want 2/1", attempts, refused)
	}
}

func TestExplicitProxyAccessors(t *testing.T) {
	base := ClientConfig{UserAgent: "ua"}
	if got := base.WithExplicitProxy(nil); got.ExplicitProxy() != nil || got.UserAgent != "ua" {
		t.Fatalf("nil proxy must leave the config direct: %+v", got)
	}
	u, _ := url.Parse("http://proxy.corp:3128")
	cfg := base.WithExplicitProxy(u)
	u.Host = "mutated:1"
	if got := cfg.ExplicitProxy(); got == nil || got.Host != "proxy.corp:3128" {
		t.Fatalf("explicit proxy not copied: %v", got)
	}
	if NewPool(cfg).Config().ExplicitProxy() == nil {
		t.Fatal("pool dropped the explicit proxy")
	}
	cases := []struct{ in, want string }{
		{"http://Proxy.Corp:3128", "proxy.corp:3128"},
		{"http://proxy.corp", "proxy.corp:80"},
		{"https://proxy.corp", "proxy.corp:443"},
		{"http://[::1]:8855", "[::1]:8855"},
	}
	for _, tc := range cases {
		pu, _ := url.Parse(tc.in)
		if got := proxyAuthority(pu); got != tc.want {
			t.Errorf("proxyAuthority(%s) = %s, want %s", tc.in, got, tc.want)
		}
	}
}
