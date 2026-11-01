//go:build !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// mxcHelperForwarder is the MXC helper's relay forwarder: it relays box
// hook requests to the daemon over its local IPC endpoint and, because the
// helper serves box connections through ServeConn on its own port (never
// Forwarder.Serve), it takes the launch's hook registration now and starts
// the periodic re-check itself (WatchHooks, every interval; zero is
// sandboxrelayd.DefaultHookInterval). Before this the Windows helper read
// the baseline and never read it again, so an agent that switched its
// hooks off mid-run was never marked hooks_drifted (RERUN2 D3).
func mxcHelperForwarder(ctx context.Context, rec sandboxrelayd.RunRecord, observerDir string, probe func() (sandboxrelayd.HookRegistration, error), interval time.Duration) *sandboxrelayd.Forwarder {
	fw := &sandboxrelayd.Forwarder{
		Run: rec, DialDaemon: dialSandboxRelay(observerDir), Rules: relayRules,
		HookProbe: probe, HookInterval: interval,
		DaemonAddr: sandboxRelayAddr(observerDir),
	}
	fw.ReadLaunchHooks()
	go fw.WatchHooks(ctx)
	return fw
}

// terminal_sandbox_mxc_port.go is the MXC run's one loopback port (sandbox
// plan v2 section 5.2, single_loopback_port_token; lane SBX-P6): the host
// helper listens on 127.0.0.1 and every request the box makes there is
// routed by sandboxmxc.Classify, which checks the run's token and the
// tier's table. The relay and OOB streams are upgraded connections; the
// model proxy is a reverse proxy to the daemon's proxy port with the token
// prefix stripped; the egress gateway is internal/sandboxnet's Gateway
// (the provider-host block of section 7.3 included). It has no OS calls of
// its own, so it is tested end to end on any host.

// mxcPort is one run's port server.
type mxcPort struct {
	Token string
	Tier  vocab.Tier
	// Relay serves one upgraded relay connection (the run's
	// sandboxrelayd.Forwarder.ServeConn).
	Relay func(ctx context.Context, c net.Conn) error
	// OOB serves one upgraded OOB connection from the box.
	OOB func(ctx context.Context, c net.Conn)
	// Identity answers the box's identity request (nil: refused): the SID
	// the helper read from the box process's token (mxcIdentityAnswer).
	Identity func(ctx context.Context) sandboxmxc.BoxIdentity
	// UIClass takes the box's report of the UI limit class its first
	// Observer process read back on its own job (nil: refused; WINFIX4
	// audit finding 4).
	UIClass func(class uint32)
	// ProxyAddr is the daemon's model proxy ("127.0.0.1:8820"); empty
	// refuses the proxy stream.
	ProxyAddr string
	// Gateway is the egress gateway (nil: refused).
	Gateway http.Handler
	Logger  *slog.Logger
	// Log receives one line for each request the port refuses and each
	// stream it closes without serving it (the helper's host lines in the
	// run's inner log, mxcHostLog; Windows 11 Pro run 3, 2026-10-22, where
	// the helper closed the box's relay stream and nothing said why). A
	// line never carries the run's token. nil: nothing.
	Log func(line string)

	once  sync.Once
	proxy *httputil.ReverseProxy
}

// mxcPortReadHeader bounds a request's header read.
const mxcPortReadHeader = 15 * time.Second

// mxcIdentityWait bounds how long the port holds an identity request while
// the helper is still looking for the box process, and
// mxcIdentityFetchTimeout how long a process in the box waits for the
// answer.
const (
	mxcIdentityWait         = 15 * time.Second
	mxcIdentityFetchTimeout = 20 * time.Second
)

// logf writes one line to Log.
func (p *mxcPort) logf(format string, a ...any) {
	if p.Log != nil {
		p.Log(fmt.Sprintf(format, a...))
	}
}

// mxcRequestKind names a request on the port without its token: the method
// and the first path segment of an origin-form target, or the form of a
// proxy request.
func mxcRequestKind(r *http.Request) string {
	switch {
	case strings.EqualFold(r.Method, http.MethodConnect):
		return "CONNECT"
	case !strings.HasPrefix(r.RequestURI, "/"):
		return r.Method + " (absolute form)"
	}
	seg, _, _ := strings.Cut(strings.TrimPrefix(r.RequestURI, "/"), "/")
	if len(seg) > 16 {
		seg = seg[:16] + "..."
	}
	return r.Method + " /" + seg + "/..."
}

// Serve answers on ln until ctx ends.
func (p *mxcPort) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           p,
		ReadHeaderTimeout: mxcPortReadHeader,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ErrorLog:          nil,
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// ServeHTTP routes one request.
func (p *mxcPort) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route := sandboxmxc.Classify(sandboxmxc.Request{
		Method: r.Method, RequestURI: r.RequestURI,
		Upgrade: r.Header.Get("Upgrade"), ProxyAuthorization: r.Header.Get("Proxy-Authorization"),
	}, p.Token, p.Tier)
	if route.Refused() {
		p.logf("port: refused %s with %d: %s", mxcRequestKind(r), route.Status, route.Reason)
		if route.Status == http.StatusProxyAuthRequired {
			w.Header().Set("Proxy-Authenticate", `Basic realm="observer sandbox"`)
		}
		http.Error(w, "observer sandbox port: "+route.Reason, route.Status)
		return
	}
	switch route.Stream {
	case sandboxmxc.StreamRelay:
		p.upgrade(w, r, sandboxmxc.UpgradeRelay, func(ctx context.Context, c net.Conn) {
			switch {
			case p.Relay == nil:
				p.logf("relay: closed the box's relay stream: this run serves no relay")
			default:
				if err := p.Relay(ctx, c); err != nil {
					p.logf("relay: closed the box's relay stream: %v", err)
				}
			}
			_ = c.Close()
		})
	case sandboxmxc.StreamOOB:
		p.upgrade(w, r, sandboxmxc.UpgradeOOB, func(ctx context.Context, c net.Conn) {
			if p.OOB != nil {
				p.OOB(ctx, c)
			}
			_ = c.Close()
		})
	case sandboxmxc.StreamIdentity:
		if p.Identity == nil {
			p.logf("identity: refused: this run has no box identity")
			http.Error(w, "observer sandbox port: no box identity on this run", http.StatusNotFound)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), mxcIdentityWait)
		defer cancel()
		ans := p.Identity(ctx)
		if ans.Error != "" {
			p.logf("identity: answered without a SID: %s", ans.Error)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ans)
	case sandboxmxc.StreamUIClass:
		if p.UIClass == nil {
			p.logf("uiclass: refused: this run takes no UI class report")
			http.Error(w, "observer sandbox port: no UI class report on this run", http.StatusNotFound)
			return
		}
		p.UIClass(route.UIClass)
		w.WriteHeader(http.StatusNoContent)
	case sandboxmxc.StreamProxy:
		p.serveProxy(w, r, route.Path)
	case sandboxmxc.StreamGateway:
		if p.Gateway == nil {
			p.logf("gateway: refused: this run has no egress gateway")
			http.Error(w, "observer sandbox port: no egress gateway on this run", http.StatusForbidden)
			return
		}
		// The run's credentials are this port's, never the destination's.
		r.Header.Del("Proxy-Authorization")
		p.Gateway.ServeHTTP(w, r)
	default:
		p.logf("port: refused %s: no stream serves it", mxcRequestKind(r))
		http.Error(w, "observer sandbox port: refused", http.StatusForbidden)
	}
}

// upgrade answers 101 and hands the raw connection to serve.
func (p *mxcPort) upgrade(w http.ResponseWriter, r *http.Request, proto string, serve func(context.Context, net.Conn)) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		p.logf("port: closed the %s stream: the connection cannot be upgraded", proto)
		http.Error(w, "observer sandbox port: cannot upgrade", http.StatusInternalServerError)
		return
	}
	c, rw, err := hj.Hijack()
	if err != nil {
		p.logf("port: closed the %s stream: %v", proto, err)
		return
	}
	_ = c.SetDeadline(time.Time{})
	if _, err := fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: %s\r\nConnection: Upgrade\r\n\r\n", proto); err != nil || rw.Flush() != nil {
		p.logf("port: closed the %s stream: the upgrade answer could not be written", proto)
		_ = c.Close()
		return
	}
	serve(r.Context(), &bufferedConn{Conn: c, r: rw.Reader})
}

// serveProxy forwards an origin-form request to the daemon's model proxy.
func (p *mxcPort) serveProxy(w http.ResponseWriter, r *http.Request, path string) {
	if p.ProxyAddr == "" {
		p.logf("proxy: refused: this run has no model proxy")
		http.Error(w, "observer sandbox port: no model proxy on this run", http.StatusForbidden)
		return
	}
	p.once.Do(func() {
		target := &url.URL{Scheme: "http", Host: p.ProxyAddr}
		p.proxy = &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(target)
				pr.Out.Header.Del("Proxy-Authorization")
				pr.Out.Host = p.ProxyAddr
			},
			// Streamed answers (SSE) reach the agent as they arrive.
			FlushInterval: -1,
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
				p.logf("proxy: the model proxy at %s did not answer: %v", p.ProxyAddr, err)
				w.WriteHeader(http.StatusBadGateway)
			},
		}
	})
	u, err := url.ParseRequestURI(path)
	if err != nil {
		p.logf("proxy: refused a request whose path does not parse")
		http.Error(w, "observer sandbox port: bad path", http.StatusBadRequest)
		return
	}
	r2 := r.Clone(r.Context())
	r2.URL.Path, r2.URL.RawPath, r2.URL.RawQuery = u.Path, u.RawPath, u.RawQuery
	r2.RequestURI = ""
	p.proxy.ServeHTTP(w, r2)
}

// bufferedConn reads what the HTTP reader already buffered first.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// ---- the box side ---------------------------------------------------------

// mxcLoopbackName is the file in the run's box directory that tells the
// box where its port is and which token proves the run (box-readable by
// design: the token authorizes only this run's own streams).
const mxcLoopbackName = "loopback.json"

// mxcLoopback is that file.
type mxcLoopback struct {
	V     int    `json:"v"`
	Port  int    `json:"port"`
	Token string `json:"token"`
}

// writeMXCLoopback writes the loopback file into dir (created fresh).
func writeMXCLoopback(dir string, lb mxcLoopback) error {
	b, err := json.Marshal(lb)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, mxcLoopbackName), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the run's own box dir
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = ownSandboxRecord(filepath.Join(dir, mxcLoopbackName))
	}
	return werr
}

// readMXCLoopback reads and checks the loopback file in dir.
func readMXCLoopback(dir string) (mxcLoopback, error) {
	p := filepath.Join(dir, mxcLoopbackName)
	fi, err := os.Lstat(p) //nolint:gosec // G703: the box's own launch dir, a fixed file name
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > 4096 {
		return mxcLoopback{}, fmt.Errorf("the sandbox's loopback record is missing or not a small regular file")
	}
	b, err := os.ReadFile(p) //nolint:gosec // G304: the box's own launch dir
	if err != nil {
		return mxcLoopback{}, err
	}
	var lb mxcLoopback
	if err := json.Unmarshal(b, &lb); err != nil {
		return mxcLoopback{}, err
	}
	if lb.V != 1 || lb.Port <= 0 || lb.Port > 65535 || !sandboxmxc.ValidToken(lb.Token) {
		return mxcLoopback{}, errors.New("the sandbox's loopback record is refused")
	}
	return lb, nil
}

// dialMXCUpgrade opens an upgraded stream on the run's port. A failure
// names the box to helper hop (*sandboxrelay.HopError) and the port's
// address, never the token.
func dialMXCUpgrade(ctx context.Context, lb mxcLoopback, stream, proto string) (net.Conn, error) {
	var d net.Dialer
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(lb.Port))
	hop := func(h sandboxrelay.Hop, detail string) error {
		return &sandboxrelay.HopError{Hop: h, Addr: addr, Detail: detail}
	}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, hop(sandboxrelay.HopBoxConnect, "reach the sandbox port: "+err.Error())
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if _, err := fmt.Fprintf(c, "GET /%s/%s HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: %s\r\nConnection: Upgrade\r\n\r\n", stream, lb.Token, proto); err != nil {
		_ = c.Close()
		return nil, hop(sandboxrelay.HopBoxClosed, "send the "+stream+" stream request: "+err.Error())
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		_ = c.Close()
		return nil, hop(sandboxrelay.HopBoxClosed, "read the "+stream+" stream answer: "+err.Error())
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = c.Close()
		return nil, hop(sandboxrelay.HopBoxStream, "the sandbox port refused the "+stream+" stream: "+resp.Status)
	}
	_ = c.SetDeadline(time.Time{})
	return &bufferedConn{Conn: c, r: br}, nil
}

// mxcFetchIdentity asks the run's port which container the run's box runs
// in. The request goes straight to the loopback port (no proxy), and an
// error never carries the request URL, which holds the run's token.
func mxcFetchIdentity(ctx context.Context, lb mxcLoopback) (sandboxmxc.BoxIdentity, error) {
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort("127.0.0.1", strconv.Itoa(lb.Port))+"/identity/"+lb.Token, nil)
	if err != nil {
		return sandboxmxc.BoxIdentity{}, errors.New("the identity request cannot be built")
	}
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return sandboxmxc.BoxIdentity{}, fmt.Errorf("reach the sandbox port: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return sandboxmxc.BoxIdentity{}, fmt.Errorf("the sandbox port refused the identity request: %s", resp.Status)
	}
	var id sandboxmxc.BoxIdentity
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&id); err != nil {
		return sandboxmxc.BoxIdentity{}, fmt.Errorf("the sandbox port's identity answer: %w", err)
	}
	return id, nil
}

// mxcAskBoxIdentity reads the loopback record in the box directory and asks
// the run's port for the box's identity; the token is registered as a
// secret first, so no diagnostic ever carries it.
func mxcAskBoxIdentity(dir string) (*sandboxmxc.BoxIdentity, error) {
	lb, err := readMXCLoopback(dir)
	if err != nil {
		return nil, err
	}
	registerBoxSecret(lb.Token)
	ctx, cancel := context.WithTimeout(context.Background(), mxcIdentityFetchTimeout)
	defer cancel()
	id, err := mxcFetchIdentity(ctx, lb)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

// mxcUIClassReportTimeout bounds the box's UI class report.
const mxcUIClassReportTimeout = 15 * time.Second

// mxcReportUIClass tells the run's host helper the UI limit class this
// process read back on its own job (WINFIX4 audit finding 4). The request
// goes straight to the loopback port, and an error never carries the
// request URL, which holds the run's token.
func mxcReportUIClass(dir string, class uint32) error {
	lb, err := readMXCLoopback(dir)
	if err != nil {
		return err
	}
	registerBoxSecret(lb.Token)
	ctx, cancel := context.WithTimeout(context.Background(), mxcUIClassReportTimeout)
	defer cancel()
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+net.JoinHostPort("127.0.0.1", strconv.Itoa(lb.Port))+sandboxmxc.UIClassPath(lb.Token, class), nil)
	if err != nil {
		return errors.New("the UI class report cannot be built")
	}
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("reach the sandbox port: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("the sandbox port refused the UI class report: %s", resp.Status)
	}
	return nil
}

// mxcBoxRoundTrip is the box-side relay client of the MXC row: it reads the
// loopback record beside the launch record, opens the relay stream and
// speaks for the run with its box secret.
func mxcBoxRoundTrip(ctx context.Context, dir string, rec sandboxrelayd.BoxRecord, req sandboxrelay.HookRequest) (sandboxrelay.HookResponse, error) {
	msg, err := sandboxrelay.EncodeHookRequest(req)
	if err != nil {
		return sandboxrelay.HookResponse{}, err
	}
	lb, err := readMXCLoopback(dir)
	if err != nil {
		return sandboxrelay.HookResponse{}, err
	}
	c, err := dialMXCUpgrade(ctx, lb, "relay", sandboxmxc.UpgradeRelay)
	if err != nil {
		return sandboxrelay.HookResponse{}, err
	}
	return sandboxrelayd.BoxRoundTripConn(ctx, c, rec, msg, sandboxrelay.ClientConnLimits)
}

// mxcInnerEnv is the box environment's network part: the model proxy and
// the egress gateway of the tier, never the host's own proxy variables.
// The box reaches its own port directly (NO_PROXY), so a client that
// honours the proxy variables never sends the model base URL through the
// gateway.
func mxcInnerEnv(tier vocab.Tier, port int, token string) []string {
	out := []string{"NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost"}
	if sandboxmxc.Grants(tier, sandboxmxc.StreamGateway) {
		gw := sandboxmxc.GatewayURL(port, token)
		out = append(out, "HTTPS_PROXY="+gw, "HTTP_PROXY="+gw, "https_proxy="+gw, "http_proxy="+gw)
	}
	return out
}

var _ io.Reader = (*bufferedConn)(nil)
