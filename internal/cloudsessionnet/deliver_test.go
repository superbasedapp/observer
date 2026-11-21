package cloudsessionnet

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudsession"
)

func dest(t *testing.T, kind cloudsession.DestinationKind, target string) cloudsession.Destination {
	t.Helper()
	d, err := cloudsession.ResolveDestination(kind, target)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestHTTPDeliver(t *testing.T) {
	var gotBody, gotAuth, gotPath, gotEnc string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotEnc = r.Header.Get("Content-Encoding")
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Errorf("body not gzip: %v", err)
			return
		}
		b, _ := io.ReadAll(zr)
		gotBody = string(b)
		_, _ = w.Write([]byte(`{"accepted_rows":3}`))
	}))
	defer srv.Close()
	d, err := NewHTTP(dest(t, cloudsession.DestOrg, srv.URL), "ship-tok", HTTPOptions{AgentVersion: "1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	r, err := d.Deliver(context.Background(), []byte(`{"agent_version":"1.2.3"}`))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != 200 || r.Accepted != 3 {
		t.Errorf("receipt = %+v", r)
	}
	if gotAuth != "Bearer ship-tok" || gotPath != "/ingest/cloud-session/v1/batch" || gotEnc != "gzip" || gotBody != `{"agent_version":"1.2.3"}` {
		t.Errorf("request = auth %q path %q enc %q body %q", gotAuth, gotPath, gotEnc, gotBody)
	}
}

func TestHTTPDeliverStatuses(t *testing.T) {
	cases := []struct {
		status    int
		retryable bool
	}{
		{401, false}, {403, false}, {413, false}, {429, true}, {500, true}, {503, true}, {408, true},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte("ship-tok echoed back"))
		}))
		d, err := NewHTTP(dest(t, cloudsession.DestNode, srv.URL), "ship-tok", HTTPOptions{})
		if err != nil {
			t.Fatal(err)
		}
		_, err = d.Deliver(context.Background(), []byte("{}"))
		var de *DeliveryError
		if !errors.As(err, &de) || de.Status != tc.status || de.Retryable != tc.retryable {
			t.Errorf("status %d: err = %v", tc.status, err)
		}
		if err != nil && strings.Contains(err.Error(), "ship-tok") {
			t.Errorf("status %d: error leaks the token: %v", tc.status, err)
		}
		srv.Close()
	}
}

func TestHTTPDoesNotFollowRedirects(t *testing.T) {
	hit := false
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	d, err := NewHTTP(dest(t, cloudsession.DestOrg, srv.URL), "ship-tok", HTTPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Deliver(context.Background(), []byte("{}")); err == nil {
		t.Error("a redirect counted as delivered")
	}
	if hit {
		t.Error("the redirect was followed (the token would go to another host)")
	}
}

func TestHTTPNoResponseIsRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()
	d, err := NewHTTP(dest(t, cloudsession.DestOrg, url), "ship-tok", HTTPOptions{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Deliver(context.Background(), []byte("{}"))
	var de *DeliveryError
	if !errors.As(err, &de) || !de.Retryable || de.Status != 0 {
		t.Errorf("err = %v", err)
	}
}

func TestNewHTTPRefusals(t *testing.T) {
	if _, err := NewHTTP(dest(t, cloudsession.DestOrg, "https://org.example.com"), "", HTTPOptions{}); err == nil {
		t.Error("missing token accepted")
	}
	if _, err := NewHTTP(dest(t, cloudsession.DestOrg, "https://org.example.com"), "a\nb", HTTPOptions{}); err == nil {
		t.Error("token with a line break accepted")
	}
	if _, err := NewHTTP(cloudsession.Destination{Network: true, Endpoint: "http://org.example.com/x"}, "t", HTTPOptions{}); err == nil {
		t.Error("plain http to a remote host accepted")
	}
	if _, err := NewHTTP(dest(t, cloudsession.DestFile, t.TempDir()), "t", HTTPOptions{}); err == nil {
		t.Error("file destination accepted by NewHTTP")
	}
	d, _ := NewHTTP(dest(t, cloudsession.DestOrg, "https://org.example.com"), "t", HTTPOptions{})
	if _, err := d.Deliver(context.Background(), make([]byte, MaxEnvelopeBytes+1)); err == nil {
		t.Error("oversized envelope accepted")
	}
}

func TestFileDeliver(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	d, err := New(dest(t, cloudsession.DestFile, dir), "", HTTPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	r1, err := d.Deliver(context.Background(), []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	r2, err := d.Deliver(context.Background(), []byte(`{"a":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if r1.Location == r2.Location {
		t.Fatal("two deliveries share a file name")
	}
	b, err := os.ReadFile(r2.Location)
	if err != nil || string(b) != `{"a":2}` {
		t.Errorf("file = %q, %v", b, err)
	}
	fi, err := os.Stat(r1.Location)
	if err != nil {
		t.Fatal(err)
	}
	// Windows has no POSIX permission bits: os.Chmod there only toggles the
	// read-only attribute, and Stat reports 0666 for a writable file, so the
	// owner-only mode is a POSIX property (the sandboxes are Linux).
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Errorf("leftover temporary files: %v", entries)
	}
	if _, err := d.Deliver(context.Background(), nil); err == nil {
		t.Error("empty envelope accepted")
	}
}

// TestHTTPConnectRefusedIsNetworkBlocked: an egress proxy that answers the
// CONNECT with 403 (a Claude Code cloud environment whose network level does
// not list the host, CA-A2) is reported as NetworkBlocked with the host, not
// as the destination's own 403 and not as retryable; the token never leaves
// the VM and never appears in the error.
func TestHTTPConnectRefusedIsNetworkBlocked(t *testing.T) {
	var connects int
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			connects++
			if r.Header.Get("Authorization") != "" {
				t.Error("the ship token reached the proxy")
			}
			http.Error(w, "egress policy denied", http.StatusForbidden)
			return
		}
		t.Errorf("proxy got a %s, want only CONNECT", r.Method)
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewHTTP(dest(t, cloudsession.DestOrg, "https://org.example.com"), "ship-tok", HTTPOptions{Proxy: http.ProxyURL(proxyURL), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Deliver(context.Background(), []byte("{}"))
	var de *DeliveryError
	if !errors.As(err, &de) || !de.NetworkBlocked || de.ConnectStatus != 403 || de.Host != "org.example.com" || de.Retryable || de.Status != 0 {
		t.Fatalf("err = %#v", err)
	}
	if connects != 1 {
		t.Errorf("CONNECTs = %d", connects)
	}
	if strings.Contains(err.Error(), "ship-tok") || !strings.Contains(err.Error(), "network level blocks the host") {
		t.Errorf("error text = %q", err)
	}

	// A proxy that lets the CONNECT through is not a block: the request then
	// fails at the TLS layer against this fake (no TLS behind it), which is
	// an ordinary retryable no-response.
	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			w.WriteHeader(http.StatusOK)
			if hj, ok := w.(http.Hijacker); ok {
				c, _, _ := hj.Hijack()
				_ = c.Close()
			}
		}
	}))
	defer open.Close()
	openURL, _ := url.Parse(open.URL)
	d, _ = NewHTTP(dest(t, cloudsession.DestOrg, "https://org.example.com"), "ship-tok", HTTPOptions{Proxy: http.ProxyURL(openURL), Timeout: 5 * time.Second})
	_, err = d.Deliver(context.Background(), []byte("{}"))
	if !errors.As(err, &de) || de.NetworkBlocked || !de.Retryable {
		t.Fatalf("pass-through proxy err = %#v", err)
	}
}

// TestLoopbackRuleAgreesWithDelivery: init's destination check
// (cloudsession.ResolveDestination) and the delivery's checkEndpoint accept
// plain http to exactly the same hosts, so init never commits a destination
// the flush then refuses, and a name that only looks like a loopback
// literal is refused by both.
func TestLoopbackRuleAgreesWithDelivery(t *testing.T) {
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.2", true},
		{"127.255.255.254", true},
		{"localhost", true},
		{"LocalHost", true},
		{"[::1]", true},
		{"[::ffff:127.0.0.1]", true},
		{"127.attacker.example", false},
		{"127.0.0.1.nip.io", false},
		{"localhost.attacker.example", false},
		{"0177.0.0.1", false},
		{"127.1", false},
		{"[fe80::1%25eth0]", false},
		{"10.0.0.1", false},
		{"node.example.com", false},
	} {
		raw := "http://" + tc.host + ":8822"
		d, rerr := cloudsession.ResolveDestination(cloudsession.DestNode, raw)
		cerr := checkEndpoint(raw + "/api/cloud-session/ingest")
		if (rerr == nil) != tc.want || (cerr == nil) != tc.want {
			t.Errorf("%s: init accepts=%v (%v), delivery accepts=%v (%v), want %v", tc.host, rerr == nil, rerr, cerr == nil, cerr, tc.want)
		}
		if rerr == nil {
			if err := checkEndpoint(d.Endpoint); err != nil {
				t.Errorf("%s: delivery refuses init's endpoint %s: %v", tc.host, d.Endpoint, err)
			}
		}
	}
}
