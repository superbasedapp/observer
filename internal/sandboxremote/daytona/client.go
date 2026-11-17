// Package daytona is the Daytona wire client of the hosted sandbox rows
// (sandbox plan v2 section 13 P7, a hosted vendor): Daytona's public
// REST API (app.daytona.io/api, the main API of
// https://www.daytona.io/docs/openapi.json) and the per-sandbox toolbox API
// (proxy.app.daytona.io/toolbox/{sandboxId}, the toolbox API of
// https://www.daytona.io/docs/toolbox-openapi.json), spoken from Go with
// net/http and golang.org/x/crypto/ssh
// (BSD-3-Clause), for the exec transport over Daytona's SSH access tokens
// (sandbox plan v2's Daytona row: REST plus its SSH access tokens through
// the pure-Go SSH transport). Daytona's own Go SDK is AGPL and is never
// imported, nor is any other Daytona module.
//
// It is one of the packages that talk to a vendor (an egress lane row in
// tests/invariant/egress_lanes_test.go) and is imported only by
// cmd/observer (tests/invariant/sandbox_remote_egress_test.go). The call
// table is in docs/sandboxed-terminals.md ("Hosted sandboxes", Daytona) and
// in the vendor row's Docs (internal/sandboxremote/vendors.go). Every fact
// was read from Daytona's documentation on 2026-11-11; nothing was run with
// a key.
//
// It implements sandboxremote.Client and nothing more. A box is a Daytona
// sandbox whose NAME is derived from the run id, so a retried or lost create
// is found by name and by label (delete accepts the name too). Every box is
// created ephemeral (autoDeleteInterval 0: deleted as soon as it stops),
// with auto-stop off (Daytona's auto-stop fires even while processes run,
// sandboxes page "Auto-stop sandboxes"), a wall-clock TTL equal to the
// vendor timeout (ttlMinutes destroys the box in any state), no public
// preview, and networkBlockAll unless the tier is internet. The key never
// appears in an error.
//
// Processes run on SSH exec channels (ssh.go, process.go): stdout, stdin,
// stdin's close, stderr and the exit status are the SSH protocol's own. The
// PTY Daytona documents is reached over a WebSocket whose framing the docs
// do not describe (the PTY page, 2026-11-11), and its toolbox session
// commands stream logs over an undocumented WebSocket framing too, so the
// client uses neither: the guest helper owns the PTY over an exec channel,
// there is no vendor resize and no reattach (a cut transport ends the run,
// A7).
package daytona

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// Options configure a client.
type Options struct {
	// Endpoint is the main API origin the key is bound to
	// (https://app.daytona.io/api, the API reference's curl base).
	Endpoint string
	// Key is the Daytona API key (Authorization: Bearer, on the main API
	// and on the toolbox).
	Key string
	// HTTP is the transport (nil: a client that never follows a redirect).
	HTTP *http.Client
	// Retries bounds the retries of a 429 or a 5xx (default 2).
	Retries int
	// MaxRetryWait caps one Retry-After wait (default 20 s).
	MaxRetryWait time.Duration
	// Sleep waits (tests inject a no-op).
	Sleep func(context.Context, time.Duration) error
	// DialSSH opens the TCP connection to the SSH gateway (nil: a plain
	// dial; tests inject a loopback server).
	DialSSH func(ctx context.Context, addr string) (net.Conn, error)
}

// Client is the Daytona wire client.
type Client struct {
	o    Options
	http *http.Client
	base *url.URL
	mu   sync.Mutex
	// toolbox holds each box's toolbox base (the sandbox's toolboxProxyUrl
	// plus its id), learned from a create or a get.
	toolbox map[string]string
	// ssh holds each box's SSH connection; ttl the TTL minutes a create set
	// (the SSH access lifetime asked for); hostKeys the gateway keys seen.
	ssh      map[string]*sshConn
	ttl      map[string]int
	hostKeys map[string][]byte
	// secrets are every credential value this client holds (the key and
	// each SSH access token), for redaction.
	secrets []string
}

// New builds a client. It makes no call.
func New(o Options) (*Client, error) {
	o.Endpoint = strings.TrimSuffix(strings.TrimSpace(o.Endpoint), "/")
	u, err := url.Parse(o.Endpoint)
	if err != nil || (u.Scheme != "https" && !strings.HasPrefix(o.Endpoint, "http://127.0.0.1")) || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("daytona: endpoint %q is not an https origin", o.Endpoint)
	}
	if strings.TrimSpace(o.Key) == "" {
		return nil, errors.New("daytona: an API key is needed")
	}
	if o.Retries == 0 {
		o.Retries = 2
	}
	if o.MaxRetryWait == 0 {
		o.MaxRetryWait = 20 * time.Second
	}
	if o.DialSSH == nil {
		o.DialSSH = dialTCP
	}
	if o.Sleep == nil {
		o.Sleep = sleepCtx
	}
	hc := o.HTTP
	if hc == nil {
		hc = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	return &Client{
		o: o, http: hc, base: u, toolbox: map[string]string{},
		ssh: map[string]*sshConn{}, ttl: map[string]int{}, hostKeys: map[string][]byte{},
		secrets: []string{o.Key},
	}, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

var _ sandboxremote.Client = (*Client)(nil)

// apiError is a vendor error, redacted. The toolbox documents ErrorResponse
// ({statusCode, message, path, timestamp, code, source}); the main API
// documents no error body, so the same fields are read where present and the
// raw text is kept otherwise.
type apiError struct {
	status int
	code   string
	msg    string
	retry  bool
	after  time.Duration
}

func (e *apiError) Error() string {
	s := "daytona: HTTP " + strconv.Itoa(e.status)
	if e.code != "" {
		s += " " + e.code
	}
	return s + ": " + e.msg
}

func (c *Client) redact(s string) string {
	c.mu.Lock()
	secrets := append([]string(nil), c.secrets...)
	c.mu.Unlock()
	return sandboxremote.Redact(s, secrets)
}

// addSecret adds a credential value to the redaction list.
func (c *Client) addSecret(v string) {
	c.mu.Lock()
	c.secrets = append(c.secrets, v)
	c.mu.Unlock()
}

// request is one call: method, an absolute URL, a body that can be re-sent,
// and its content type.
type request struct {
	method, url string
	body        []byte
	ctype       string
	// noRetry marks a call that must not be repeated (a stdin write).
	noRetry bool
}

// apiURL is a main-API URL.
func (c *Client) apiURL(p string, q url.Values) string {
	s := c.o.Endpoint + p
	if len(q) > 0 {
		s += "?" + q.Encode()
	}
	return s
}

// do sends one request with bounded retries of 429 and 5xx answers
// (Retry-After honoured up to MaxRetryWait).
func (c *Client) do(ctx context.Context, r request) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		var body io.Reader
		if r.body != nil {
			body = bytes.NewReader(r.body)
		}
		req, err := http.NewRequestWithContext(ctx, r.method, r.url, body)
		if err != nil {
			return nil, errors.New(c.redact(err.Error()))
		}
		req.Header.Set("Authorization", "Bearer "+c.o.Key)
		if r.ctype != "" {
			req.Header.Set("Content-Type", r.ctype)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, errors.New(c.redact(err.Error()))
		}
		if resp.StatusCode < 300 {
			return resp, nil
		}
		ae := c.readError(resp)
		if r.noRetry || !ae.retry || attempt >= c.o.Retries || ae.after > c.o.MaxRetryWait {
			switch resp.StatusCode {
			case http.StatusTooManyRequests:
				return nil, fmt.Errorf("%w: %w", sandboxremote.ErrRateLimited, ae)
			case http.StatusNotFound, http.StatusGone:
				return nil, fmt.Errorf("%w: %w", sandboxremote.ErrNotFound, ae)
			}
			return nil, ae
		}
		wait := ae.after
		if wait == 0 {
			wait = time.Duration(1<<attempt) * 400 * time.Millisecond
		}
		if err := c.o.Sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

// readError reads a vendor error answer (3xx included: no redirect is
// followed), capped and redacted.
func (c *Client) readError(resp *http.Response) *apiError {
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	ae := &apiError{status: resp.StatusCode, msg: c.redact(strings.TrimSpace(string(b)))}
	var e struct {
		Message json.RawMessage `json:"message"`
		Code    string          `json:"code"`
		Error   string          `json:"error"`
	}
	if json.Unmarshal(b, &e) == nil {
		var msg string
		if json.Unmarshal(e.Message, &msg) != nil && len(e.Message) > 0 {
			msg = string(e.Message) // a list of messages is kept as text
		}
		if msg != "" || e.Code != "" || e.Error != "" {
			if msg == "" {
				msg = e.Error
			}
			ae.code, ae.msg = c.redact(e.Code), c.redact(msg)
		}
	}
	ae.retry = resp.StatusCode == http.StatusTooManyRequests || (resp.StatusCode >= 500 && resp.StatusCode != http.StatusNotImplemented)
	if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s >= 0 {
		ae.after = time.Duration(s) * time.Second
	}
	return ae
}

// doJSON sends a JSON body and decodes a JSON answer into out (nil: drop).
func (c *Client) doJSON(ctx context.Context, r request, in, out any) error {
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		r.body, r.ctype = b, "application/json"
	}
	resp, err := c.do(ctx, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out); err != nil {
		return fmt.Errorf("daytona: %s %s: decode: %w", r.method, c.redact(stripQuery(r.url)), err)
	}
	return nil
}

func stripQuery(s string) string {
	if i := strings.IndexByte(s, '?'); i >= 0 {
		return s[:i]
	}
	return s
}

// sandboxJSON is a Sandbox (main API components/schemas/Sandbox, the fields
// the client reads).
type sandboxJSON struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	State           string            `json:"state"`
	ErrorReason     string            `json:"errorReason"`
	Target          string            `json:"target"`
	Labels          map[string]string `json:"labels"`
	ToolboxProxyURL string            `json:"toolboxProxyUrl"`
	AutoDestroyAt   string            `json:"autoDestroyAt"`
	Snapshot        string            `json:"snapshot"`
}

// BoxName derives the sandbox name from a run id: a retried or lost create
// finds the same name, and delete accepts it (DELETE /sandbox/{sandboxIdOrName}).
// The docs state no name grammar, so the name keeps to lower-case letters,
// digits and dashes and stays under 63 characters (unverified: the limit is
// chosen, not documented).
func BoxName(run string) string {
	var b strings.Builder
	b.WriteString("observer-")
	for _, r := range strings.ToLower(run) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			b.WriteRune(r)
		}
	}
	s := b.String()
	if len(s) > 63 {
		s = s[:63]
	}
	return strings.TrimRight(s, "-")
}

// The states the client reads (SandboxState): started is the one running
// state; destroyed means the vendor no longer has the box.
const (
	stateStarted     = "started"
	stateDestroyed   = "destroyed"
	stateBuildFailed = "build_failed"
)

// info converts a sandbox and remembers its toolbox base. A toolbox URL
// outside the bound endpoint's own host or Daytona's domain is refused
// (never sent the key) and simply not remembered.
func (c *Client) info(s sandboxJSON) sandboxremote.BoxInfo {
	id := s.ID
	if id == "" {
		id = s.Name
	}
	if tb, err := c.toolboxBase(s.ToolboxProxyURL, s.ID); err == nil && s.ID != "" {
		c.mu.Lock()
		c.toolbox[s.ID] = tb
		if s.Name != "" {
			c.toolbox[s.Name] = tb
		}
		c.mu.Unlock()
	}
	info := sandboxremote.BoxInfo{
		ID: id, Region: s.Target, Running: s.State == stateStarted,
		Labels: s.Labels, Extra: map[string]string{"name": s.Name, "state": s.State},
	}
	if t, err := time.Parse(time.RFC3339, s.AutoDestroyAt); err == nil {
		info.Deadline = t
	}
	return info
}

// toolboxBase builds a box's toolbox base from the sandbox's
// toolboxProxyUrl (toolbox API: "{toolboxProxyUrl}/{sandboxId}/{endpoint}").
// The key goes there, so the host must be the bound endpoint's own host or,
// when the endpoint is Daytona's, under one of Daytona's domains, with the
// endpoint's scheme (credential binding, SBX-GOV-4).
func (c *Client) toolboxBase(raw, id string) (string, error) {
	if raw == "" || id == "" {
		return "", errors.New("daytona: the sandbox names no toolbox")
	}
	u, err := url.Parse(strings.TrimSuffix(raw, "/"))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Scheme != c.base.Scheme {
		return "", fmt.Errorf("daytona: %w: the toolbox URL is not an origin like the endpoint's", sandboxremote.ErrCredentialEndpointMismatch)
	}
	if !strings.EqualFold(u.Host, c.base.Host) {
		v, _ := sandboxremote.VendorFor(sandboxremote.VendorDaytona)
		if !v.OwnsHost(c.base.Hostname()) || !v.OwnsHost(u.Hostname()) {
			return "", fmt.Errorf("daytona: %w: the toolbox host %s is outside %s", sandboxremote.ErrCredentialEndpointMismatch, u.Hostname(), strings.Join(v.Domains, ", "))
		}
	}
	return u.Scheme + "://" + u.Host + u.EscapedPath() + "/" + url.PathEscape(id), nil
}

// tb returns a box's toolbox base, reading the sandbox when it is not known.
func (c *Client) tb(ctx context.Context, id string) (string, error) {
	c.mu.Lock()
	base := c.toolbox[id]
	c.mu.Unlock()
	if base != "" {
		return base, nil
	}
	var s sandboxJSON
	if err := c.doJSON(ctx, request{method: http.MethodGet, url: c.apiURL("/sandbox/"+url.PathEscape(id), nil)}, nil, &s); err != nil {
		return "", err
	}
	if s.ID == "" {
		s.ID = id
	}
	base, err := c.toolboxBase(s.ToolboxProxyURL, s.ID)
	if err != nil {
		return "", err
	}
	c.info(s)
	return base, nil
}

// createBody is the create request (CreateSandbox, the fields the client
// sends).
func createBody(spec sandboxremote.BoxSpec, name string, labels map[string]string) map[string]any {
	body := map[string]any{
		"name": name, "labels": labels,
		// Auto-stop fires even while processes run (sandboxes page), so it
		// is off; the wall-clock TTL is the vendor timeout instead, and the
		// box is ephemeral (deleted as soon as it stops).
		"autoStopInterval": 0, "autoDeleteInterval": 0,
		"ttlMinutes": ttlMinutes(spec.TimeoutSeconds),
		"public":     false,
		// Block-all for none and proxy_only, where the relay is the only
		// way out; the organization's own tier policy on internet.
		"networkBlockAll": spec.Tier != vocab.TierInternet,
	}
	if spec.Template != "" {
		body["snapshot"] = spec.Template
	}
	if spec.Region != "" && spec.Region != sandboxremote.ProviderChosen {
		body["target"] = spec.Region
	}
	if len(spec.Env) > 0 {
		body["env"] = spec.Env
	}
	return body
}

// Create starts a sandbox named from the run, carrying the run label. A
// conflict on the name is resolved by reading the box back and accepting it
// only when it carries this run's label. A transport failure, or a 5xx left
// after the retries, returns ErrCreateUnknown (the box may exist under its
// name and label). A refused snapshot (404 with a template named, or a box
// that answers build_failed) returns ErrTemplateUnavailable.
func (c *Client) Create(ctx context.Context, spec sandboxremote.BoxSpec) (sandboxremote.BoxInfo, error) {
	if spec.TimeoutSeconds <= 0 {
		return sandboxremote.BoxInfo{}, errors.New("daytona: a box needs a timeout")
	}
	name := BoxName(spec.RunID)
	labels := maps.Clone(spec.Labels)
	if labels == nil {
		labels = map[string]string{}
	}
	labels[sandboxremote.LabelKey] = spec.RunID
	var out sandboxJSON
	err := c.doJSON(ctx, request{method: http.MethodPost, url: c.apiURL("/sandbox", nil)}, createBody(spec, name, labels), &out)
	var ae *apiError
	switch {
	case errors.As(err, &ae) && ae.status == http.StatusConflict:
		got, gerr := c.Get(ctx, name)
		if gerr != nil {
			return sandboxremote.BoxInfo{}, fmt.Errorf("daytona: create: the name exists and could not be read: %w", gerr)
		}
		if got.Labels[sandboxremote.LabelKey] != spec.RunID {
			return sandboxremote.BoxInfo{}, fmt.Errorf("daytona: create: a sandbox named %s exists for another run", name)
		}
		return got, nil
	case err != nil && ae == nil && !errors.Is(err, sandboxremote.ErrRateLimited) && !errors.Is(err, sandboxremote.ErrNotFound) && ctx.Err() == nil,
		err != nil && ae != nil && ae.status >= 500 && ctx.Err() == nil:
		return sandboxremote.BoxInfo{}, fmt.Errorf("daytona: create: %w (%s)", sandboxremote.ErrCreateUnknown, c.redact(err.Error()))
	case errors.Is(err, sandboxremote.ErrNotFound) && spec.Template != "":
		return sandboxremote.BoxInfo{}, fmt.Errorf("daytona: create: %w: %w", sandboxremote.ErrTemplateUnavailable, err)
	case err != nil:
		return sandboxremote.BoxInfo{}, fmt.Errorf("daytona: create: %w", err)
	}
	if out.State == stateBuildFailed {
		return sandboxremote.BoxInfo{}, fmt.Errorf("daytona: create: %w: the box answered build_failed (%s)", sandboxremote.ErrTemplateUnavailable, c.redact(out.ErrorReason))
	}
	if out.Name == "" {
		out.Name = name
	}
	if out.Labels == nil {
		out.Labels = labels
	}
	info := c.info(out)
	c.mu.Lock()
	c.ttl[info.ID] = ttlMinutes(spec.TimeoutSeconds)
	c.mu.Unlock()
	return info, nil
}

// ttlMinutes is the wall-clock TTL a create asks for: the vendor timeout,
// rounded up to whole minutes.
func ttlMinutes(seconds int) int { return int(math.Ceil(float64(seconds) / 60)) }

// Get reads a sandbox by id or name. A destroyed sandbox is not found.
func (c *Client) Get(ctx context.Context, id string) (sandboxremote.BoxInfo, error) {
	var out sandboxJSON
	if err := c.doJSON(ctx, request{method: http.MethodGet, url: c.apiURL("/sandbox/"+url.PathEscape(id), nil)}, nil, &out); err != nil {
		return sandboxremote.BoxInfo{}, err
	}
	if out.State == stateDestroyed {
		return sandboxremote.BoxInfo{}, fmt.Errorf("daytona: %s is destroyed: %w", id, sandboxremote.ErrNotFound)
	}
	if out.ID == "" && out.Name == "" {
		out.Name = id
	}
	return c.info(out), nil
}

// listPage bounds a list page (the spec allows 1 to 200, default 100).
const listPage = 100

// ListByLabel lists the organization's sandboxes carrying key=value (the
// documented server-side labels filter, a JSON map, re-checked here),
// following nextCursor.
func (c *Client) ListByLabel(ctx context.Context, key, value string) ([]sandboxremote.BoxInfo, error) {
	filter, err := json.Marshal(map[string]string{key: value})
	if err != nil {
		return nil, err
	}
	var boxes []sandboxremote.BoxInfo
	cursor := ""
	for page := 0; page < 100; page++ {
		q := url.Values{"labels": {string(filter)}, "limit": {strconv.Itoa(listPage)}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var out struct {
			Items      []sandboxJSON `json:"items"`
			NextCursor string        `json:"nextCursor"`
		}
		if err := c.doJSON(ctx, request{method: http.MethodGet, url: c.apiURL("/sandbox", q)}, nil, &out); err != nil {
			return nil, err
		}
		for _, s := range out.Items {
			if s.Labels[key] != value || s.State == stateDestroyed {
				continue
			}
			boxes = append(boxes, c.info(s))
		}
		if out.NextCursor == "" || len(out.Items) == 0 {
			return boxes, nil
		}
		cursor = out.NextCursor
	}
	return boxes, errors.New("daytona: list: too many pages")
}

// Delete removes a sandbox by id or name.
func (c *Client) Delete(ctx context.Context, id string) error {
	c.dropSSH(id, nil)
	err := c.doJSON(ctx, request{method: http.MethodDelete, url: c.apiURL("/sandbox/"+url.PathEscape(id), nil)}, nil, nil)
	if err == nil {
		c.mu.Lock()
		delete(c.toolbox, id)
		delete(c.ttl, id)
		c.mu.Unlock()
	}
	return err
}

// maxUpload caps one file read into memory (Daytona documents no upload
// limit; the cap is the client's own).
const maxUpload = 512 << 20

// WriteFiles writes each file through the toolbox's upload (POST
// /files/upload-v2?path=, a raw application/octet-stream body; parents are
// created and an existing file is overwritten), then sets its mode (POST
// /files/permissions?path=&mode=, octal).
func (c *Client) WriteFiles(ctx context.Context, id string, files []sandboxremote.UploadFile) error {
	base, err := c.tb(ctx, id)
	if err != nil {
		return err
	}
	for _, f := range files {
		if !path.IsAbs(f.Path) || path.Clean(f.Path) != f.Path {
			return fmt.Errorf("daytona: upload path %q is not a clean absolute path", f.Path)
		}
		data, err := readUpload(f)
		if err != nil {
			return err
		}
		q := url.Values{"path": {f.Path}}
		if err := c.doJSON(ctx, request{method: http.MethodPost, url: base + "/files/upload-v2?" + q.Encode(), body: data, ctype: "application/octet-stream"}, nil, nil); err != nil {
			return fmt.Errorf("daytona: upload %s: %w", f.Path, err)
		}
		mode := f.Mode & 0o7777
		if mode == 0 {
			mode = 0o644
		}
		q.Set("mode", fmt.Sprintf("%04o", mode))
		if err := c.doJSON(ctx, request{method: http.MethodPost, url: base + "/files/permissions?" + q.Encode()}, nil, nil); err != nil {
			return fmt.Errorf("daytona: mode of %s: %w", f.Path, err)
		}
	}
	return nil
}

func readUpload(f sandboxremote.UploadFile) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	limit := int64(maxUpload)
	if f.Size > 0 && f.Size < limit {
		limit = f.Size
	}
	data, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("daytona: %s grew past %d bytes while uploading", f.Path, limit)
	}
	return data, nil
}

// ReadFile reads one file's raw bytes (GET /files/download?path=), refusing
// one over max bytes.
func (c *Client) ReadFile(ctx context.Context, id, p string, max int64) ([]byte, error) {
	base, err := c.tb(ctx, id)
	if err != nil {
		return nil, err
	}
	return c.readAt(ctx, base, p, max)
}

// readAt reads one file through a known toolbox base.
func (c *Client) readAt(ctx context.Context, base, p string, max int64) ([]byte, error) {
	resp, err := c.do(ctx, request{method: http.MethodGet, url: base + "/files/download?" + url.Values{"path": {p}}.Encode()})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if max <= 0 {
		max = maxUpload
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, errors.New(c.redact(err.Error()))
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("daytona: %s is over %d bytes", p, max)
	}
	return data, nil
}

// Reattach: Daytona documents no reattach to a running exec (the PTY
// WebSocket, whose framing is not documented, is not used), and the guest
// helper's kept-PTY re-adoption is held off on this row, so a cut transport
// ends the run; the agent's own resume picks it up (A7).
func (c *Client) Reattach(context.Context, string, string) (sandboxremote.Process, error) {
	return nil, fmt.Errorf("daytona: reattach: %w", sandboxremote.ErrNotSupported)
}
