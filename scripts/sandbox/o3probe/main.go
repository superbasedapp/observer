// Command o3probe is the in-box network probe of live check O3-L1
// (scripts/sandbox/o3-openshell-egress-live.sh, finding F-028). OpenShell
// v0.1.6's default box image has no curl, wget or python3, so the script
// builds this static binary from the repo (CGO_ENABLED=0, as it builds
// observer) and places it in the run's workspace: nothing is pulled from
// an unpinned source and no tool is added to the image.
//
// It prints the same facts the script's curl call printed, so the script's
// verdict table reads them unchanged:
//
//	o3probe fetch [-noproxy] [-o FILE] [-m SECONDS] URL
//	    one line "<http_code>,<connect_code>,<exit>": the final HTTP status
//	    (000 when there was none), the proxy's CONNECT status (000 when no
//	    CONNECT was sent), and curl's exit code for the same outcome (0
//	    answered, 6 name not resolved, 7 the connect was refused or
//	    unreachable: EACCES from OpenShell's network broker, EPERM,
//	    ECONNREFUSED, ENETUNREACH, EHOSTUNREACH or EADDRNOTAVAIL, as curl
//	    reports them (any other connect error, such as the broker's
//	    ECANCELED when mediation is unavailable, is 99), 28 timeout, 35
//	    the TLS handshake failed or was cut,
//	    56 the proxy refused the CONNECT or the connection broke after the
//	    handshake, 60 the certificate did not verify, 99 anything else,
//	    which the verdict reads as unknown). Redirects are not followed.
//	    The body (at most 1 MiB) goes to FILE.
//	o3probe resolve HOST
//	    one line: the class of the first address the box's resolver answers
//	    (rfc1918, loopback, link-local, cgnat, public or other) or
//	    "none:<nxdomain|timeout|servfail|error>"; exit 0 only when it
//	    resolved. No address is printed.
//
// It reads proxy settings the way curl does (curlProxyURL): http_proxy
// for an http URL (lowercase only), https_proxy or HTTPS_PROXY for an
// https one, then all_proxy or ALL_PROXY, and no_proxy or NO_PROXY; and the
// box's CA bundle through SSL_CERT_FILE, which OpenShell sets to its
// per-box interception CA.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout))
}

// run dispatches a subcommand and returns the process exit code.
func run(args []string, out io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: o3probe fetch [-noproxy] [-o FILE] [-m SECONDS] URL | o3probe resolve HOST")
		return 2
	}
	switch args[0] {
	case "fetch":
		return fetchCmd(args[1:], out)
	case "resolve":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: o3probe resolve HOST")
			return 2
		}
		class, ok := resolveClass(context.Background(), net.DefaultResolver, args[1])
		fmt.Fprintln(out, class)
		if ok {
			return 0
		}
		return 1
	}
	fmt.Fprintln(os.Stderr, "o3probe: unknown subcommand", args[0])
	return 2
}

// fetchCmd is `o3probe fetch`; it always exits 0 once its arguments parse
// (the outcome is in the printed line, as curl's -w line was).
func fetchCmd(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
	noProxy := fs.Bool("noproxy", false, "never use a proxy")
	body := fs.String("o", "", "write the body here")
	secs := fs.Int("m", 15, "give up after this many seconds")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		return 2
	}
	r := fetch(fs.Arg(0), *noProxy, time.Duration(*secs)*time.Second, os.Getenv)
	if *body != "" {
		_ = os.WriteFile(*body, r.body, 0o600)
	}
	fmt.Fprintf(out, "%s,%s,%d\n", r.code, r.connect, r.exit)
	return 0
}

// fetchResult is one fetch's facts.
type fetchResult struct {
	code, connect string
	exit          int
	body          []byte
}

// maxBody bounds the body kept for the policy_denied check.
const maxBody = 1 << 20

// fetch requests rawURL once and classifies the outcome; getenv is the
// environment the proxy settings are read from.
func fetch(rawURL string, noProxy bool, timeout time.Duration, getenv func(string) string) fetchResult {
	var connect atomic.Int32
	// handshake is 1 while a TLS handshake is under way and 2 once one
	// finished, so a failure inside the handshake reads as curl's 35.
	var handshake atomic.Int32
	tr := &http.Transport{
		Proxy: func(req *http.Request) (*url.URL, error) {
			return curlProxyURL(getenv, req.URL)
		},
		TLSHandshakeTimeout: timeout,
		OnProxyConnectResponse: func(_ context.Context, _ *url.URL, _ *http.Request, res *http.Response) error {
			connect.Store(int32(res.StatusCode)) //nolint:gosec // G115: an HTTP status fits
			return nil
		},
	}
	if noProxy {
		tr.Proxy = nil
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	trace := &httptrace.ClientTrace{
		TLSHandshakeStart: func() { handshake.CompareAndSwap(0, 1) },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil {
				handshake.Store(2)
			}
		},
	}
	r := fetchResult{code: "000", connect: "000"}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), http.MethodGet, rawURL, nil)
	if err != nil {
		r.exit = 99
		return r
	}
	res, err := client.Do(req) //nolint:gosec // G107: the probe's whole job is this URL; the client carries the timeout
	if err != nil {
		r.connect = statusText(int(connect.Load()))
		r.exit = curlExit(err, int(connect.Load()), handshake.Load() == 1)
		return r
	}
	defer func() { _ = res.Body.Close() }()
	r.code = statusText(res.StatusCode)
	r.connect = statusText(int(connect.Load()))
	b, rerr := io.ReadAll(io.LimitReader(res.Body, maxBody))
	r.body = b
	if rerr != nil {
		r.exit = curlExit(rerr, int(connect.Load()), false)
	}
	return r
}

// curlProxyURL is the proxy curl would use for target (finding OC2-A4):
// none when no_proxy (or NO_PROXY) lists the host; else http_proxy for
// an http URL (curl reads no uppercase HTTP_PROXY), https_proxy or
// HTTPS_PROXY for an https one; else all_proxy or ALL_PROXY. A value
// without a scheme is an http:// proxy, as curl reads it.
func curlProxyURL(getenv func(string) string, target *url.URL) (*url.URL, error) {
	if noProxyMatch(firstEnv(getenv, "no_proxy", "NO_PROXY"), target.Hostname()) {
		return nil, nil
	}
	var v string
	switch target.Scheme {
	case "http":
		v = getenv("http_proxy")
	case "https":
		v = firstEnv(getenv, "https_proxy", "HTTPS_PROXY")
	}
	if v == "" {
		v = firstEnv(getenv, "all_proxy", "ALL_PROXY")
	}
	if v == "" {
		return nil, nil
	}
	if !strings.Contains(v, "://") {
		v = "http://" + v
	}
	return url.Parse(v)
}

// firstEnv is the first of names set to a non-empty value.
func firstEnv(getenv func(string) string, names ...string) string {
	for _, n := range names {
		if v := getenv(n); v != "" {
			return v
		}
	}
	return ""
}

// noProxyMatch is curl's no_proxy rule: "*" alone matches every host;
// otherwise each comma or space separated entry matches the host itself
// or any name below it (a leading dot is optional), and an entry that is
// an address or an address range matches an address host in it.
func noProxyMatch(list, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if strings.TrimSpace(list) == "*" {
		return true
	}
	ip, ipErr := netip.ParseAddr(host)
	for _, e := range strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		e = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(e, "."), "."))
		if e == "" {
			continue
		}
		if ipErr == nil {
			if p, err := netip.ParsePrefix(e); err == nil && p.Contains(ip.Unmap()) {
				return true
			}
			if a, err := netip.ParseAddr(e); err == nil && a.Unmap() == ip.Unmap() {
				return true
			}
			continue
		}
		if host == e || strings.HasSuffix(host, "."+e) {
			return true
		}
	}
	return false
}

// statusText is an HTTP status as curl's three digits (000 for none).
func statusText(code int) string {
	if code <= 0 || code > 999 {
		return "000"
	}
	return fmt.Sprintf("%03d", code)
}

// curlExit maps a failed request to the curl exit code of the same
// outcome. connect is the proxy's CONNECT status (0 when none was sent);
// inHandshake says the failure came while a TLS handshake was under way.
// The rows are checked in order.
func curlExit(err error, connect int, inHandshake bool) int {
	var dnsErr *net.DNSError
	var netErr net.Error
	var unknownCA x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var invalid x509.CertificateInvalidError
	var verify *tls.CertificateVerificationError
	var recordErr tls.RecordHeaderError
	switch {
	case connect != 0 && connect != 200:
		return 56
	case errors.As(err, &dnsErr):
		return 6
	case errors.As(err, &unknownCA), errors.As(err, &hostErr), errors.As(err, &invalid), errors.As(err, &verify):
		return 60
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return 28
	// A connect refused or unreachable is curl's 7 (findings OC2-A1 and
	// OC2-V2): OpenShell's network broker denies a policy-refused connect
	// with EACCES, and EPERM, ECONNREFUSED, ENETUNREACH, EHOSTUNREACH and
	// EADDRNOTAVAIL are the same outcome, also on a connect to the proxy.
	// Any other connect error, such as the broker's ECANCELED when its
	// mediation is unavailable (not a policy decision), stays unknown.
	case refusedConnect(err), strings.Contains(err.Error(), "connection refused"), strings.Contains(err.Error(), "actively refused"):
		return 7
	// A handshake cut by the peer (EOF or a reset) is curl's 35 too
	// (finding OC2-A4), as is any other handshake failure.
	case inHandshake, errors.As(err, &recordErr), strings.Contains(err.Error(), "tls: "):
		return 35
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, syscall.ECONNRESET):
		return 56
	}
	return 99
}

// refusedErrnos are the connect errors that mean refused or unreachable.
var refusedErrnos = []syscall.Errno{syscall.EACCES, syscall.EPERM, syscall.ECONNREFUSED, syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.EADDRNOTAVAIL}

// refusedConnect says err holds one of refusedErrnos.
func refusedConnect(err error) bool {
	for _, e := range refusedErrnos {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// lookuper is the resolver seam (net.DefaultResolver in the box).
type lookuper interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// resolveClass resolves host and names the class of its first address.
func resolveClass(ctx context.Context, r lookuper, host string) (string, bool) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	addrs, err := r.LookupHost(ctx, host)
	if err != nil {
		return "none:" + dnsErrorClass(err), false
	}
	if len(addrs) == 0 {
		return "none:nxdomain", false
	}
	a, perr := netip.ParseAddr(addrs[0])
	if perr != nil {
		return "other", true
	}
	return addrClass(a.Unmap()), true
}

// dnsErrorClass names a lookup failure.
func dnsErrorClass(err error) string {
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		return "nxdomain"
	case errors.As(err, &dnsErr) && dnsErr.IsTimeout, errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.As(err, &dnsErr) && strings.Contains(dnsErr.Err, "server misbehaving"):
		return "servfail"
	}
	return "error"
}

// cgnat is 100.64.0.0/10 (shared address space).
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// addrClass names an address's class; the address itself is never printed.
func addrClass(a netip.Addr) string {
	switch {
	case a.IsLoopback():
		return "loopback"
	case a.IsLinkLocalUnicast():
		return "link-local"
	case a.Is4() && a.IsPrivate():
		return "rfc1918"
	case cgnat.Contains(a):
		return "cgnat"
	case a.IsGlobalUnicast() && !a.IsPrivate():
		return "public"
	}
	return "other"
}
