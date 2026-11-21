package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestCurlExit: one row per mapped outcome, in the table's order.
func TestCurlExit(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		err     error
		connect int
		hand    bool
		want    int
	}{
		{"the proxy refused the CONNECT", errors.New("Forbidden"), 403, false, 56},
		{"the proxy refused the CONNECT mid-handshake", errors.New("Forbidden"), 403, true, 56},
		{"a name that does not resolve", &net.DNSError{Err: "no such host", Name: "x", IsNotFound: true}, 0, false, 6},
		{"a name that does not resolve, in a dial", dialErr(&net.DNSError{Err: "no such host", Name: "x", IsNotFound: true}), 0, false, 6},
		{"an unknown CA", x509.UnknownAuthorityError{}, 200, true, 60},
		{"a hostname mismatch", fmt.Errorf("get: %w", x509.HostnameError{Host: "x"}), 0, false, 60},
		{"a deadline", context.DeadlineExceeded, 0, false, 28},
		{"a connect that timed out", dialErr(&os.SyscallError{Syscall: "connect", Err: syscall.ETIMEDOUT}), 0, false, 28},
		{"connection refused", fmt.Errorf("dial: %w", syscall.ECONNREFUSED), 0, false, 7},
		{"connect: ECONNREFUSED", dialErr(&os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}), 0, false, 7},
		{"connect: EACCES (OpenShell's broker)", dialErr(&os.SyscallError{Syscall: "connect", Err: syscall.EACCES}), 0, false, 7},
		{"connect: EPERM", dialErr(&os.SyscallError{Syscall: "connect", Err: syscall.EPERM}), 0, false, 7},
		{"connect: ENETUNREACH", dialErr(&os.SyscallError{Syscall: "connect", Err: syscall.ENETUNREACH}), 0, false, 7},
		{"connect: EHOSTUNREACH", dialErr(&os.SyscallError{Syscall: "connect", Err: syscall.EHOSTUNREACH}), 0, false, 7},
		{"connect: EADDRNOTAVAIL", dialErr(&os.SyscallError{Syscall: "connect", Err: syscall.EADDRNOTAVAIL}), 0, false, 7},
		{"a failed connect to the proxy", &url.Error{Op: "Get", URL: "https://x/", Err: &net.OpError{Op: "proxyconnect", Net: "tcp", Err: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.EACCES}}}, 0, false, 7},
		{"connect: ECANCELED (the broker's mediation unavailable)", dialErr(&os.SyscallError{Syscall: "connect", Err: syscall.ECANCELED}), 0, false, 99},
		{"a connect to the proxy: ECANCELED", &url.Error{Op: "Get", URL: "https://x/", Err: &net.OpError{Op: "proxyconnect", Net: "tcp", Err: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECANCELED}}}, 0, false, 99},
		{"a connect error of another kind", dialErr(errors.New("odd")), 0, false, 99},
		{"a TLS handshake failure", errors.New("remote error: tls: handshake failure"), 0, false, 35},
		{"a handshake cut by EOF", fmt.Errorf("get: %w", io.EOF), 0, true, 35},
		{"a handshake cut by a reset", &net.OpError{Op: "read", Net: "tcp", Err: &os.SyscallError{Syscall: "read", Err: syscall.ECONNRESET}}, 0, true, 35},
		{"the connection broke", fmt.Errorf("read: %w", io.ErrUnexpectedEOF), 0, false, 56},
		{"a reset after the handshake", &net.OpError{Op: "read", Net: "tcp", Err: &os.SyscallError{Syscall: "read", Err: syscall.ECONNRESET}}, 0, false, 56},
		{"anything else", errors.New("odd"), 0, false, 99},
	} {
		if got := curlExit(tc.err, tc.connect, tc.hand); got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, got, tc.want)
		}
	}
}

// TestAddrClass: one row per class; no address is ever the answer.
func TestAddrClass(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"10.0.0.1": "rfc1918", "192.168.1.2": "rfc1918", "127.0.0.1": "loopback", "169.254.169.254": "link-local",
		"100.64.1.1": "cgnat", "1.1.1.1": "public", "fd00::1": "other", "0.0.0.0": "other",
	} {
		if got := addrClass(netip.MustParseAddr(in)); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
	if statusText(0) != "000" || statusText(403) != "403" || statusText(1000) != "000" {
		t.Fatal("statusText")
	}
}

// fakeResolver answers LookupHost from fixed values.
type fakeResolver struct {
	addrs []string
	err   error
}

func (f fakeResolver) LookupHost(context.Context, string) ([]string, error) { return f.addrs, f.err }

// TestResolveClass: an answer's class, and each failure's class.
func TestResolveClass(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		r    fakeResolver
		want string
		ok   bool
	}{
		{fakeResolver{addrs: []string{"10.0.0.1"}}, "rfc1918", true},
		{fakeResolver{addrs: []string{"::ffff:1.1.1.1"}}, "public", true},
		{fakeResolver{}, "none:nxdomain", false},
		{fakeResolver{err: &net.DNSError{IsNotFound: true}}, "none:nxdomain", false},
		{fakeResolver{err: &net.DNSError{IsTimeout: true}}, "none:timeout", false},
		{fakeResolver{err: &net.DNSError{Err: "server misbehaving"}}, "none:servfail", false},
		{fakeResolver{err: errors.New("odd")}, "none:error", false},
	} {
		if got, ok := resolveClass(context.Background(), tc.r, "h.example"); got != tc.want || ok != tc.ok {
			t.Errorf("%+v: %s %v, want %s %v", tc.r, got, ok, tc.want, tc.ok)
		}
	}
}

// TestFetch: against a local server, an answer prints its status with no
// CONNECT, the body is written, a redirect is not followed, and a closed
// port is connection refused.
func TestFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":"policy_denied"}`)
	}))
	defer srv.Close()
	bodyFile := filepath.Join(t.TempDir(), "body")
	var out bytes.Buffer
	if code := run([]string{"fetch", "-noproxy", "-o", bodyFile, "-m", "5", srv.URL + "/"}, &out); code != 0 || strings.TrimSpace(out.String()) != "403,000,0" {
		t.Fatalf("answer: %d %q", code, out.String())
	}
	if b, _ := os.ReadFile(bodyFile); !strings.Contains(string(b), "policy_denied") {
		t.Fatalf("body %q", b)
	}
	if r := fetch(srv.URL+"/redirect", true, 5*time.Second, noEnv); r.code != "302" || r.exit != 0 {
		t.Fatalf("redirect followed: %+v", r)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	if r := fetch("http://"+addr+"/", true, 5*time.Second, noEnv); r.code != "000" || r.exit != 7 {
		t.Fatalf("closed port: %+v", r)
	}
	if run(nil, &out) != 2 || run([]string{"resolve"}, &out) != 2 || run([]string{"nope"}, &out) != 2 {
		t.Fatal("usage")
	}
}

// dialErr is a failed dial as http.Client.Do returns it.
func dialErr(inner error) error {
	return &url.Error{Op: "Get", URL: "https://example.com/", Err: &net.OpError{Op: "dial", Net: "tcp", Err: inner}}
}

// noEnv is an environment with nothing set.
func noEnv(string) string { return "" }

// envOf is an environment holding exactly kv.
func envOf(kv map[string]string) func(string) string {
	return func(k string) string { return kv[k] }
}

// TestCurlProxyURL (finding OC2-A4): the proxy curl would use, row by row.
func TestCurlProxyURL(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		env    map[string]string
		target string
		want   string
	}{
		{nil, "https://h.example/", ""},
		{map[string]string{"HTTP_PROXY": "http://p:1"}, "http://h.example/", ""},
		{map[string]string{"http_proxy": "http://p:1"}, "http://h.example/", "http://p:1"},
		{map[string]string{"http_proxy": "http://p:1"}, "https://h.example/", ""},
		{map[string]string{"HTTPS_PROXY": "http://p:2"}, "https://h.example/", "http://p:2"},
		{map[string]string{"https_proxy": "http://p:3", "HTTPS_PROXY": "http://p:2"}, "https://h.example/", "http://p:3"},
		{map[string]string{"ALL_PROXY": "http://p:4"}, "https://h.example/", "http://p:4"},
		{map[string]string{"ALL_PROXY": "http://p:4"}, "http://h.example/", "http://p:4"},
		{map[string]string{"all_proxy": "http://p:5", "ALL_PROXY": "http://p:4"}, "https://h.example/", "http://p:5"},
		{map[string]string{"HTTPS_PROXY": "http://p:2", "ALL_PROXY": "http://p:4"}, "https://h.example/", "http://p:2"},
		{map[string]string{"HTTP_PROXY": "http://p:1", "ALL_PROXY": "http://p:4"}, "http://h.example/", "http://p:4"},
		{map[string]string{"HTTPS_PROXY": "p:6"}, "https://h.example/", "http://p:6"},
		{map[string]string{"HTTPS_PROXY": "http://p:2", "NO_PROXY": "example"}, "https://h.example/", ""},
		{map[string]string{"HTTPS_PROXY": "http://p:2", "no_proxy": "*"}, "https://h.example/", ""},
		{map[string]string{"HTTPS_PROXY": "http://p:2", "NO_PROXY": "other.example"}, "https://h.example/", "http://p:2"},
	} {
		u, err := curlProxyURL(envOf(tc.env), mustURL(t, tc.target))
		got := ""
		if u != nil {
			got = u.String()
		}
		if err != nil || got != tc.want {
			t.Errorf("%v %s: %q %v, want %q", tc.env, tc.target, got, err, tc.want)
		}
	}
}

// TestNoProxyMatch: curl's no_proxy entries.
func TestNoProxyMatch(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		list, host string
		want       bool
	}{
		{"", "h.example", false},
		{"*", "h.example", true},
		{"*.example", "h.example", false},
		{"example", "h.example", true},
		{".example", "h.example", true},
		{"h.example", "h.example", true},
		{"H.Example", "h.example.", true},
		{"xh.example", "h.example", false},
		{"a.test, example", "h.example", true},
		{"a.test example", "h.example", true},
		{"10.0.0.0/8", "10.1.2.3", true},
		{"10.0.0.0/8", "11.1.2.3", false},
		{"192.0.2.1", "192.0.2.1", true},
		{"example", "10.1.2.3", false},
	} {
		if got := noProxyMatch(tc.list, tc.host); got != tc.want {
			t.Errorf("%q %q: %v, want %v", tc.list, tc.host, got, tc.want)
		}
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

// TestFetchProxyAndHandshake (finding OC2-A4): a stray uppercase
// HTTP_PROXY to a dead port is ignored for an http URL (so no dead proxy
// reads as a refusal), ALL_PROXY to a dead port is used (a failed connect
// to the proxy, 7, as curl), and a peer that closes during the TLS
// handshake is 35.
func TestFetchProxyAndHandshake(t *testing.T) {
	dead := closedAddr(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer srv.Close()
	if r := fetch(srv.URL+"/", false, 5*time.Second, envOf(map[string]string{"HTTP_PROXY": "http://" + dead})); r.code != "204" || r.exit != 0 {
		t.Fatalf("uppercase HTTP_PROXY used for an http URL: %+v", r)
	}
	if r := fetch(srv.URL+"/", false, 5*time.Second, envOf(map[string]string{"ALL_PROXY": "http://" + dead})); r.code != "000" || r.exit != 7 {
		t.Fatalf("ALL_PROXY to a dead port: %+v", r)
	}
	if r := fetch("https://"+dead+"/", false, 5*time.Second, envOf(map[string]string{"HTTPS_PROXY": "http://" + dead, "NO_PROXY": "*"})); r.exit != 7 {
		t.Fatalf("NO_PROXY=* with a refused origin: %+v", r)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 4096)
			_, _ = c.Read(buf)
			_ = c.Close()
		}
	}()
	if r := fetch("https://"+ln.Addr().String()+"/", true, 5*time.Second, noEnv); r.code != "000" || r.exit != 35 {
		t.Fatalf("a handshake cut by the peer: %+v", r)
	}
}

// closedAddr is a loopback address nothing listens on.
func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// TestFetchUnreachableInEmptyNetns (finding OC2-A1): in a network
// namespace with no route (unshare -rn), a connect fails with
// ENETUNREACH, which curl reports as 7; so must the probe. Linux only;
// skipped where unprivileged user namespaces are not available.
func TestFetchUnreachableInEmptyNetns(t *testing.T) {
	if os.Getenv("O3PROBE_NETNS_CHILD") == "1" {
		r := fetch("https://192.0.2.1/", true, 5*time.Second, noEnv)
		fmt.Printf("NETNS-RESULT %s,%s,%d\n", r.code, r.connect, r.exit)
		return
	}
	if runtime.GOOS != "linux" {
		t.Skip("unshare is Linux only")
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("no unshare")
	}
	cmd := exec.Command(unshare, "-rn", os.Args[0], "-test.run=^TestFetchUnreachableInEmptyNetns$", "-test.count=1") //nolint:gosec // G204: the test binary itself
	cmd.Env = append(os.Environ(), "O3PROBE_NETNS_CHILD=1")
	out, err := cmd.CombinedOutput()
	got := ""
	for _, line := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(line, "NETNS-RESULT "); ok {
			got = v
		}
	}
	if got == "" {
		t.Skipf("no empty network namespace here (%v): %s", err, out)
	}
	if got != "000,000,7" {
		t.Fatalf("an unreachable connect in an empty netns: %q, want 000,000,7 (curl's)", got)
	}
}
