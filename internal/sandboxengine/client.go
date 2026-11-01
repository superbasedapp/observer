package sandboxengine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
)

// maxBody caps every JSON answer the client reads; an engine answer larger
// than this is refused, never buffered whole.
const maxBody = 8 << 20

// requestTimeout bounds a plain request (not the create, the wait, attach,
// events and pull streams, which run under their caller's context).
const requestTimeout = 30 * time.Second

// libpodPrefix is the path prefix of Podman's own API; Podman 4 and 5
// answer it under any version, so the oldest supported one is used.
const libpodPrefix = "/v4.0.0/libpod"

// APIError is an engine answer that is not a success: the HTTP status and
// the engine's own message.
type APIError struct {
	Op      string
	Status  int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("sandboxengine: %s: engine answered %d: %s", e.Op, e.Status, e.Message)
}

// IsNotFound reports a 404 (no such container or image).
func IsNotFound(err error) bool {
	var a *APIError
	return errors.As(err, &a) && a.Status == http.StatusNotFound
}

// IsServerError reports a 5xx: the engine failed the request itself (as
// rootless Podman 5.7.0 does for every archive path stat of a created
// container), which says nothing about what was asked.
func IsServerError(err error) bool {
	var a *APIError
	return errors.As(err, &a) && a.Status >= http.StatusInternalServerError
}

// IsConflict reports a 409 (a name in use, a container in the wrong state).
func IsConflict(err error) bool {
	var a *APIError
	return errors.As(err, &a) && a.Status == http.StatusConflict
}

// Client speaks the Engine API on one unix socket. Build it only for a
// socket that passed sandboxoci.ValidateSocket.
type Client struct {
	socket string
	hc     *http.Client
	stream *http.Client

	mu  sync.Mutex
	api string
}

// New returns a client for the unix socket at socketPath (absolute). It
// does not dial; Version negotiates the API version on first use.
func New(socketPath string) (*Client, error) {
	if !path.IsAbs(socketPath) || path.Clean(socketPath) != socketPath {
		return nil, fmt.Errorf("sandboxengine: socket %q is not a clean absolute path", socketPath)
	}
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socketPath)
	}
	tr := &http.Transport{DialContext: dial, DisableCompression: true, MaxIdleConns: 2, IdleConnTimeout: 30 * time.Second, Proxy: nil}
	return &Client{
		socket: socketPath,
		hc:     &http.Client{Transport: tr, Timeout: requestTimeout, CheckRedirect: noRedirect},
		stream: &http.Client{Transport: &http.Transport{DialContext: dial, DisableCompression: true, Proxy: nil}, CheckRedirect: noRedirect},
	}, nil
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// Socket returns the socket path the client dials.
func (c *Client) Socket() string { return c.socket }

// APIVersion returns the negotiated API version ("" before Version).
func (c *Client) APIVersion() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.api
}

// SetAPIVersion fixes the API version (a host helper that already
// negotiated in the daemon passes it on).
func (c *Client) SetAPIVersion(v string) error {
	n, err := sandboxoci.NegotiateAPI(v)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.api = n
	c.mu.Unlock()
	return nil
}

func (c *Client) versioned(p string) (string, error) {
	api := c.APIVersion()
	if api == "" {
		return "", fmt.Errorf("sandboxengine: the API version was not negotiated (call Version first)")
	}
	return "/v" + api + p, nil
}

// do sends one request and returns the response; a non-2xx answer (and a
// 304 unless ok304) becomes an *APIError.
func (c *Client) do(ctx context.Context, hc *http.Client, op, method, p string, q url.Values, body any, ok304 bool) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("sandboxengine: %s: %w", op, err)
		}
		rd = bytes.NewReader(b)
	}
	u := "http://engine" + p
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, fmt.Errorf("sandboxengine: %s: %w", op, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sandboxengine: %s: %w", op, err)
	}
	if resp.StatusCode == http.StatusNotModified && ok304 {
		return resp, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		defer func() { _ = resp.Body.Close() }()
		return nil, &APIError{Op: op, Status: resp.StatusCode, Message: errorMessage(resp.Body)}
	}
	return resp, nil
}

// errorMessage reads the engine's {"message": "..."} error body, capped.
func errorMessage(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 64<<10))
	var e struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(b, &e) == nil && e.Message != "" {
		return e.Message
	}
	return strings.TrimSpace(string(b))
}

// getJSON GETs p and decodes the capped answer into out.
func (c *Client) getJSON(ctx context.Context, op, p string, q url.Values, out any) error {
	resp, err := c.do(ctx, c.hc, op, http.MethodGet, p, q, nil, false)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	return decodeCapped(resp.Body, out, op)
}

func decodeCapped(r io.Reader, out any, op string) error {
	b, err := io.ReadAll(io.LimitReader(r, maxBody+1))
	if err != nil {
		return fmt.Errorf("sandboxengine: %s: %w", op, err)
	}
	if len(b) > maxBody {
		return fmt.Errorf("sandboxengine: %s: the answer is over %d bytes", op, maxBody)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("sandboxengine: %s: %w", op, err)
	}
	return nil
}

// Ping is GET /_ping.
func (c *Client) Ping(ctx context.Context) error {
	resp, err := c.do(ctx, c.hc, "ping", http.MethodGet, "/_ping", nil, nil, false)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

// Version is GET /version (unversioned, so any engine answers); it
// negotiates the API version the other calls put in their path.
func (c *Client) Version(ctx context.Context) (sandboxoci.VersionFacts, error) {
	var w struct {
		Version       string `json:"Version"`
		APIVersion    string `json:"ApiVersion"`
		MinAPIVersion string `json:"MinAPIVersion"`
		Platform      struct {
			Name string `json:"Name"`
		} `json:"Platform"`
		Components []struct {
			Name string `json:"Name"`
		} `json:"Components"`
	}
	if err := c.getJSON(ctx, "version", "/version", nil, &w); err != nil {
		return sandboxoci.VersionFacts{}, err
	}
	v := sandboxoci.VersionFacts{Version: w.Version, APIVersion: w.APIVersion, MinAPIVersion: w.MinAPIVersion, PlatformName: w.Platform.Name}
	for _, cpt := range w.Components {
		v.Components = append(v.Components, cpt.Name)
	}
	if err := c.SetAPIVersion(w.APIVersion); err != nil {
		return v, err
	}
	return v, nil
}

// Info is GET /info; on Podman it also reads /libpod/info for the rootless
// flag (Podman's own word on its mode).
func (c *Client) Info(ctx context.Context, engine sandboxoci.Engine) (sandboxoci.InfoFacts, error) {
	p, err := c.versioned("/info")
	if err != nil {
		return sandboxoci.InfoFacts{}, err
	}
	var w struct {
		ID              string   `json:"ID"`
		Name            string   `json:"Name"`
		OperatingSystem string   `json:"OperatingSystem"`
		KernelVersion   string   `json:"KernelVersion"`
		DockerRootDir   string   `json:"DockerRootDir"`
		SecurityOptions []string `json:"SecurityOptions"`
		// Runtimes is Docker's registered OCI runtimes (types.Runtime:
		// "path" and "runtimeArgs"), read for the oci-runsc row.
		Runtimes map[string]struct {
			Path        string   `json:"path"`
			RuntimeArgs []string `json:"runtimeArgs"`
		} `json:"Runtimes"`
	}
	if err := c.getJSON(ctx, "info", p, nil, &w); err != nil {
		return sandboxoci.InfoFacts{}, err
	}
	i := sandboxoci.InfoFacts{ID: w.ID, Name: w.Name, OperatingSystem: w.OperatingSystem, KernelVersion: w.KernelVersion, DockerRootDir: w.DockerRootDir, SecurityOptions: w.SecurityOptions}
	if len(w.Runtimes) > 0 {
		i.Runtimes = make(map[string]sandboxoci.RuntimeInfo, len(w.Runtimes))
		for name, rt := range w.Runtimes {
			i.Runtimes[name] = sandboxoci.RuntimeInfo{Path: rt.Path, Args: rt.RuntimeArgs}
		}
	}
	if engine == sandboxoci.EnginePodman {
		var lp struct {
			Host struct {
				Security struct {
					Rootless *bool `json:"rootless"`
				} `json:"security"`
				// OCIRuntime is the runtime Podman runs containers with,
				// read for the known-runtime hint (sandboxoci.RuntimeHint).
				OCIRuntime struct {
					Name string `json:"name"`
				} `json:"ociRuntime"`
			} `json:"host"`
		}
		if err := c.getJSON(ctx, "libpod info", libpodPrefix+"/info", nil, &lp); err != nil {
			return i, err
		}
		if lp.Host.Security.Rootless == nil {
			return i, fmt.Errorf("sandboxengine: libpod info: host.security.rootless is missing")
		}
		i.PodmanRootless = lp.Host.Security.Rootless
		i.PodmanOCIRuntime = lp.Host.OCIRuntime.Name
	}
	return i, nil
}

// ImagePresent is GET /images/{ref}/json: false on 404.
func (c *Client) ImagePresent(ctx context.Context, ref string) (bool, error) {
	p, err := c.versioned("/images/" + url.PathEscape(ref) + "/json")
	if err != nil {
		return false, err
	}
	err = c.getJSON(ctx, "image inspect", p, nil, nil)
	switch {
	case err == nil:
		return true, nil
	case IsNotFound(err):
		return false, nil
	}
	return false, err
}

// ImageIdentity is what GET /images/{ref}/json says about who an image
// is: its id (the config digest), the repository digests the engine holds
// it under, and its platform. Present is false on 404.
type ImageIdentity struct {
	Present      bool
	ID           string
	RepoDigests  []string
	OS           string
	Architecture string
	// Labels are the image's own Config.Labels (Observer's default image
	// carries its recipe's labels).
	Labels map[string]string
}

// ImageIdentity reads the image's id, repository digests and platform, for
// the default image's trust check (internal/sandboximage, plan 12.3).
func (c *Client) ImageIdentity(ctx context.Context, ref string) (ImageIdentity, error) {
	p, err := c.versioned("/images/" + url.PathEscape(ref) + "/json")
	if err != nil {
		return ImageIdentity{}, err
	}
	var w struct {
		ID           string   `json:"Id"`
		RepoDigests  []string `json:"RepoDigests"`
		OS           string   `json:"Os"`
		Architecture string   `json:"Architecture"`
		Config       *struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	err = c.getJSON(ctx, "image inspect", p, nil, &w)
	switch {
	case IsNotFound(err):
		return ImageIdentity{}, nil
	case err != nil:
		return ImageIdentity{}, err
	}
	id := ImageIdentity{Present: true, ID: w.ID, RepoDigests: w.RepoDigests, OS: w.OS, Architecture: w.Architecture}
	if w.Config != nil {
		id.Labels = w.Config.Labels
	}
	return id, nil
}

// ImageEnv is GET /images/{ref}/json's Config.Env: the environment the image
// itself sets, which the engine merges UNDER the create body's Env (a name
// the body does not set keeps the image's value). nil when the image sets
// none.
func (c *Client) ImageEnv(ctx context.Context, ref string) ([]string, error) {
	p, err := c.versioned("/images/" + url.PathEscape(ref) + "/json")
	if err != nil {
		return nil, err
	}
	var w struct {
		Config *struct {
			Env []string `json:"Env"`
		} `json:"Config"`
	}
	if err := c.getJSON(ctx, "image inspect", p, nil, &w); err != nil {
		return nil, err
	}
	if w.Config == nil {
		return nil, nil
	}
	return w.Config.Env, nil
}

// ContainerCreate is POST /containers/create?name=<name>.
func (c *Client) ContainerCreate(ctx context.Context, name string, body any) (string, []string, error) {
	p, err := c.versioned("/containers/create")
	if err != nil {
		return "", nil, err
	}
	// The create runs under its caller's context, never the 30 s client
	// timeout: a first rootless keep-id create prepares the image for the
	// user namespace and can take longer (Linux live check 2026-10-23, rootless
	// Podman 5.7.0: "Client.Timeout exceeded while awaiting headers" under
	// the helper's 60 s budget, and the container was left behind).
	resp, err := c.do(ctx, c.stream, "container create", http.MethodPost, p, url.Values{"name": {name}}, body, false)
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		ID       string   `json:"Id"`
		Warnings []string `json:"Warnings"`
	}
	if err := decodeCapped(resp.Body, &out, "container create"); err != nil {
		return "", nil, err
	}
	if out.ID == "" {
		return "", nil, fmt.Errorf("sandboxengine: container create: no id in the answer")
	}
	return out.ID, out.Warnings, nil
}

// ContainerInspect is GET /containers/{id}/json, returned raw for the
// strict read-back parser (sandboxoci.ParseInspect).
func (c *Client) ContainerInspect(ctx context.Context, id string) ([]byte, error) {
	p, err := c.versioned("/containers/" + url.PathEscape(id) + "/json")
	if err != nil {
		return nil, err
	}
	return c.raw(ctx, "container inspect", p)
}

// ContainerInspectLibpod is Podman's GET /libpod/containers/{id}/json: the
// uid map and the real OCI runtime.
func (c *Client) ContainerInspectLibpod(ctx context.Context, id string) ([]byte, error) {
	return c.raw(ctx, "libpod container inspect", libpodPrefix+"/containers/"+url.PathEscape(id)+"/json")
}

func (c *Client) raw(ctx context.Context, op, p string) ([]byte, error) {
	resp, err := c.do(ctx, c.hc, op, http.MethodGet, p, nil, nil, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("sandboxengine: %s: %w", op, err)
	}
	if len(b) > maxBody {
		return nil, fmt.Errorf("sandboxengine: %s: the answer is over %d bytes", op, maxBody)
	}
	return b, nil
}

// postEmpty sends a body-less POST and discards the answer.
func (c *Client) postEmpty(ctx context.Context, op, p string, q url.Values, ok304 bool) error {
	vp, err := c.versioned(p)
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, c.hc, op, http.MethodPost, vp, q, nil, ok304)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return resp.Body.Close()
}

// ContainerStart is POST /containers/{id}/start (304, already started, is
// not an error).
func (c *Client) ContainerStart(ctx context.Context, id string) error {
	return c.postEmpty(ctx, "container start", "/containers/"+url.PathEscape(id)+"/start", nil, true)
}

// ContainerResize is POST /containers/{id}/resize?h=&w=.
func (c *Client) ContainerResize(ctx context.Context, id string, rows, cols uint16) error {
	q := url.Values{"h": {strconv.Itoa(int(rows))}, "w": {strconv.Itoa(int(cols))}}
	return c.postEmpty(ctx, "container resize", "/containers/"+url.PathEscape(id)+"/resize", q, false)
}

// ContainerKill is POST /containers/{id}/kill?signal=<name>.
func (c *Client) ContainerKill(ctx context.Context, id, signal string) error {
	return c.postEmpty(ctx, "container kill", "/containers/"+url.PathEscape(id)+"/kill", url.Values{"signal": {signal}}, false)
}

// ContainerStop is POST /containers/{id}/stop?t=<seconds> (304, already
// stopped, is not an error).
func (c *Client) ContainerStop(ctx context.Context, id string, grace time.Duration) error {
	q := url.Values{"t": {strconv.Itoa(int(grace / time.Second))}}
	return c.postEmpty(ctx, "container stop", "/containers/"+url.PathEscape(id)+"/stop", q, true)
}

// ContainerRemove is DELETE /containers/{id}?force=1&v=1 (anonymous
// volumes go with it). A container already gone is not an error.
func (c *Client) ContainerRemove(ctx context.Context, id string) error {
	p, err := c.versioned("/containers/" + url.PathEscape(id))
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, c.hc, "container remove", http.MethodDelete, p, url.Values{"force": {"1"}, "v": {"1"}}, nil, false)
	if IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// ContainerList is GET /containers/json?all=1&filters=<filters>.
func (c *Client) ContainerList(ctx context.Context, filters map[string][]string) ([]sandboxoci.ContainerFact, error) {
	p, err := c.versioned("/containers/json")
	if err != nil {
		return nil, err
	}
	f, err := json.Marshal(filters)
	if err != nil {
		return nil, err
	}
	var w []struct {
		ID     string            `json:"Id"`
		Labels map[string]string `json:"Labels"`
		State  string            `json:"State"`
	}
	if err := c.getJSON(ctx, "container list", p, url.Values{"all": {"1"}, "filters": {string(f)}}, &w); err != nil {
		return nil, err
	}
	out := make([]sandboxoci.ContainerFact, 0, len(w))
	for _, x := range w {
		out = append(out, sandboxoci.ContainerFact{ID: x.ID, Labels: x.Labels, Running: x.State == "running"})
	}
	return out, nil
}

// WaitResult is the container's end as the engine reports it.
type WaitResult struct {
	StatusCode int
	Err        error
}

// ContainerWait is POST /containers/{id}/wait?condition=<cond>. It returns
// once the engine has accepted the wait (the answer's header), so a caller
// that starts the container afterwards is guaranteed to get this run's
// status (the wait-first rule of section 4.6, JSP-4); the status arrives on
// the channel when the container ends.
func (c *Client) ContainerWait(ctx context.Context, id, condition string) (<-chan WaitResult, error) {
	p, err := c.versioned("/containers/" + url.PathEscape(id) + "/wait")
	if err != nil {
		return nil, err
	}
	resp, err := c.do(ctx, c.stream, "container wait", http.MethodPost, p, url.Values{"condition": {condition}}, nil, false)
	if err != nil {
		return nil, err
	}
	ch := make(chan WaitResult, 1)
	go func() {
		defer func() { _ = resp.Body.Close() }()
		var w struct {
			StatusCode int `json:"StatusCode"`
			Error      *struct {
				Message string `json:"Message"`
			} `json:"Error"`
		}
		if err := decodeCapped(resp.Body, &w, "container wait"); err != nil {
			ch <- WaitResult{StatusCode: -1, Err: err}
			return
		}
		if w.Error != nil && w.Error.Message != "" {
			ch <- WaitResult{StatusCode: w.StatusCode, Err: fmt.Errorf("sandboxengine: container wait: %s", w.Error.Message)}
			return
		}
		ch <- WaitResult{StatusCode: w.StatusCode}
	}()
	return ch, nil
}

// Event is one engine event the sweep reads.
type Event struct {
	Type   string
	Action string
	ID     string
	Labels map[string]string
}

// Events is GET /events?filters=<filters>, a stream until ctx ends.
func (c *Client) Events(ctx context.Context, filters map[string][]string) (<-chan Event, error) {
	p, err := c.versioned("/events")
	if err != nil {
		return nil, err
	}
	f, err := json.Marshal(filters)
	if err != nil {
		return nil, err
	}
	resp, err := c.do(ctx, c.stream, "events", http.MethodGet, p, url.Values{"filters": {string(f)}}, nil, false)
	if err != nil {
		return nil, err
	}
	ch := make(chan Event, 16)
	go func() {
		defer close(ch)
		defer func() { _ = resp.Body.Close() }()
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			var w struct {
				Type   string `json:"Type"`
				Action string `json:"Action"`
				Actor  struct {
					ID         string            `json:"ID"`
					Attributes map[string]string `json:"Attributes"`
				} `json:"Actor"`
			}
			if json.Unmarshal(sc.Bytes(), &w) != nil {
				continue
			}
			select {
			case ch <- Event{Type: w.Type, Action: w.Action, ID: w.Actor.ID, Labels: w.Actor.Attributes}:
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch, nil
}

// ContainerPathStat is HEAD /containers/{id}/archive?path=<p>: whether a
// path exists in a container's filesystem. On Docker it works on a created
// container that never started, so the driver can ask an image what it
// holds (the tool-delivery loader check) without running anything in it.
// Rootless Podman 5.7.0 answers 500 for every path of a created container
// (live check 2026-10-22, D4; HEAD carries no message): that is returned as
// an *APIError that IsServerError matches, never as "absent", and the
// driver then asks through a started check of its own binary.
func (c *Client) ContainerPathStat(ctx context.Context, id, p string) (bool, error) {
	vp, err := c.versioned("/containers/" + url.PathEscape(id) + "/archive")
	if err != nil {
		return false, err
	}
	resp, err := c.do(ctx, c.hc, "container path stat", http.MethodHead, vp, url.Values{"path": {p}}, nil, false)
	if IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_ = resp.Body.Close()
	return true, nil
}
