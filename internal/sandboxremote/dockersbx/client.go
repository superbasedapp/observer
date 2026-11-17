package dockersbx

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// DefaultExchangeURL is Docker Hub's exchange of an account's access token
// for a short-lived management token (the authentication page).
const DefaultExchangeURL = "https://hub.docker.com/v2/auth/token"

// DefaultImage is the image a box starts from when the user named no
// template: a Debian image with git, curl and npm (the Modal row's default),
// so the internet tier can install an agent CLI at first start. It runs as
// root, which the vendor row's BoxHome (/root) relies on.
const DefaultImage = "node:22-bookworm"

// The box size the driver asks for: the limits page's small (2 vCPU,
// 4096 MiB), the size the vendor row prices. A direct REST create must name
// both values as a supported pair.
const (
	boxCPUs      = 2
	boxMemoryMiB = 4096
)

// keepAlive is the start command that keeps a raw image box running: an
// image's own command (node's REPL, bash) would exit at once without a
// terminal, and the docs do not say a box outlives it.
var keepAlive = []string{"sleep", "infinity"}

// endpointPermissions are the scoped endpoint permissions every box grant
// asks for (files and processes).
var endpointPermissions = []string{"sandboxesExec", "sandboxesFilesRead", "sandboxesFilesWrite"}

// endpointTTL is the scoped grant's lifetime (the service clamps it to at
// most five minutes); it is minted again when less than endpointMargin is
// left.
const (
	endpointTTL    = "300s"
	endpointMargin = 60 * time.Second
)

// Options configure a client.
type Options struct {
	// Endpoint is the management API base the account is bound to
	// (https://connect.docker.com/sandboxes); every /v1 path is appended to
	// it, keeping its path prefix.
	Endpoint string
	// ExchangeURL is the Docker Hub exchange (DefaultExchangeURL when "").
	ExchangeURL string
	// DockerID is the Docker account name; Access is the account's access
	// token made with "Allow Cloud Sandboxes access". Both go to the
	// exchange URL only.
	DockerID string
	Access   string
	// HTTP is the transport (nil: a client that never follows a redirect).
	HTTP *http.Client
	// Retries bounds the retries of a 429, a 5xx or a lost idempotent call
	// (default 2, the SDK's).
	Retries int
	// MaxRetryWait caps one server-named retry delay (default 20 s; past
	// it the call fails).
	MaxRetryWait time.Duration
	// ReadyWait bounds Create's wait for a box to run (default 180 s);
	// Poll is the wait between its reads (default 1 s).
	ReadyWait, Poll time.Duration
	// Sleep waits (tests inject a no-op).
	Sleep func(context.Context, time.Duration) error
	// Now is the clock (tests inject one).
	Now func() time.Time
	// CPUs and MemoryMiB override the box size (0: the small size the
	// vendor row prices); the pair must be one the limits page lists
	// (micro 1/2048, small 2/4096, medium 4/8192, large 8/16384, xl
	// 16/32768).
	CPUs, MemoryMiB int
}

// Client is the Docker Sandboxes wire client.
type Client struct {
	o        Options
	http     *http.Client
	vendor   sandboxremote.Vendor
	loopback bool

	mu sync.Mutex
	// mgmt is the current management token ("" until the first exchange).
	mgmt string
	// grants holds each box's scoped endpoint grant; uris each box's
	// endpoint.
	grants map[string]endpointGrant
	uris   map[string]string
	// env is each box's base environment, added to every process (the
	// create request's environment field is non-secret metadata, so the
	// base environment is never sent there).
	env map[string]map[string]string
	// seq is the last stream sequence received per process name, so a
	// Reattach resumes after it.
	seq map[string]int64
}

// endpointGrant is one box's scoped endpoint grant: the base URL, the value
// sent in the Authorization header and its expiry.
type endpointGrant struct {
	base   string
	scope  string
	expiry time.Time
}

// New builds a client. It makes no call.
func New(o Options) (*Client, error) {
	v, ok := sandboxremote.VendorFor(sandboxremote.VendorDockerSandboxes)
	if !ok {
		return nil, errors.New("dockersbx: no vendor row")
	}
	if o.ExchangeURL == "" {
		o.ExchangeURL = DefaultExchangeURL
	}
	c := &Client{o: o, vendor: v, grants: map[string]endpointGrant{}, uris: map[string]string{}, env: map[string]map[string]string{}, seq: map[string]int64{}}
	// A loopback http endpoint is a test server: its box endpoints may be
	// loopback http too. Anything else is https under docker.com.
	c.loopback = strings.HasPrefix(o.Endpoint, "http://127.0.0.1:")
	if !c.allowed(o.Endpoint) {
		return nil, fmt.Errorf("dockersbx: endpoint %q is not an https URL under %s", o.Endpoint, strings.Join(v.Domains, ", "))
	}
	if !c.allowed(o.ExchangeURL) {
		return nil, fmt.Errorf("dockersbx: exchange URL %q is not an https URL under %s", o.ExchangeURL, strings.Join(v.Domains, ", "))
	}
	if strings.TrimSpace(o.DockerID) == "" || strings.TrimSpace(o.Access) == "" {
		return nil, errors.New("dockersbx: a Docker ID and its access token are both needed")
	}
	if c.o.Retries == 0 {
		c.o.Retries = 2
	}
	if c.o.MaxRetryWait == 0 {
		c.o.MaxRetryWait = 20 * time.Second
	}
	if c.o.ReadyWait == 0 {
		c.o.ReadyWait = 180 * time.Second
	}
	if c.o.Poll == 0 {
		c.o.Poll = time.Second
	}
	if c.o.Now == nil {
		c.o.Now = time.Now
	}
	if c.o.Sleep == nil {
		c.o.Sleep = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-t.C:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	c.http = o.HTTP
	if c.http == nil {
		c.http = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	return c, nil
}

var _ sandboxremote.Client = (*Client)(nil)

// allowed reports whether raw is a URL the client may send to: https on
// one of the vendor's own domains, or loopback http in a test client.
func (c *Client) allowed(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	switch {
	case u.Scheme == "https":
		return c.vendor.OwnsHost(u.Hostname())
	case u.Scheme == "http" && c.loopback:
		return u.Hostname() == "127.0.0.1"
	}
	return false
}

// redact scrubs every credential value the client holds from s.
func (c *Client) redact(s string) string {
	c.mu.Lock()
	vals := []string{c.o.Access, c.mgmt}
	for _, g := range c.grants {
		vals = append(vals, g.scope)
	}
	c.mu.Unlock()
	return sandboxremote.Redact(s, vals)
}

// newIdem returns a fresh Idempotency-Key value.
func newIdem(prefix string) string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// authorization is the Authorization header value for an issued value.
func authorization(v string) string { return "Bearer " + v }

// ---- errors -------------------------------------------------------------------

// apiError is a vendor error (the shared Error body: code, message,
// details), redacted.
type apiError struct {
	status int
	code   string
	msg    string
	retry  bool
	after  time.Duration
}

func (e *apiError) Error() string {
	s := "dockersbx: HTTP " + strconv.Itoa(e.status)
	if e.code != "" {
		s += " " + e.code
	}
	return s + ": " + e.msg
}

// errorBody is the Error schema, with the RetryInfo detail's delay.
type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details []struct {
		Type       string `json:"@type"`
		RetryDelay string `json:"retryDelay"`
	} `json:"details"`
}

// readError reads an error answer, capped and redacted. 429, 502, 503 and
// 504 and the unavailable and resourceExhausted codes are retryable; a
// Retry-After header or a google.rpc.RetryInfo detail names the delay.
func (c *Client) readError(resp *http.Response) *apiError {
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	ae := &apiError{status: resp.StatusCode, msg: c.redact(strings.TrimSpace(string(b)))}
	var e errorBody
	if json.Unmarshal(b, &e) == nil && (e.Code != "" || e.Message != "") {
		ae.code, ae.msg = c.redact(e.Code), c.redact(e.Message)
		for _, d := range e.Details {
			if strings.HasSuffix(d.Type, "google.rpc.RetryInfo") && d.RetryDelay != "" {
				if dur, err := time.ParseDuration(d.RetryDelay); err == nil && dur >= 0 {
					ae.after = dur
				}
			}
		}
	}
	switch resp.StatusCode {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		ae.retry = true
	}
	if ae.code == "unavailable" || ae.code == "resourceExhausted" {
		ae.retry = true
	}
	if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s >= 0 {
		ae.after = time.Duration(s) * time.Second
	}
	return ae
}

// classify wraps a final error answer in the shared sentinels.
func classify(ae *apiError) error {
	switch {
	case ae.status == http.StatusTooManyRequests || ae.code == "resourceExhausted":
		return fmt.Errorf("%w: %w", sandboxremote.ErrRateLimited, ae)
	case ae.status == http.StatusNotFound || ae.code == "notFound":
		return fmt.Errorf("%w: %w", sandboxremote.ErrNotFound, ae)
	}
	return ae
}

// ---- requests -----------------------------------------------------------------

// plane says which credential a request carries.
type plane int

const (
	// planeManagement: the management token, to the bound endpoint.
	planeManagement plane = iota
	// planeBox: a box's scoped endpoint grant, to that box's endpoint.
	planeBox
)

// request is one call. path is appended to the plane's base URL.
type request struct {
	plane  plane
	box    string
	method string
	path   string
	query  url.Values
	body   []byte
	ctype  string
	header http.Header
	// stream, when set, is the body (sent once, never retried).
	stream func() io.Reader
	// idempotent: a lost answer may be repeated (a read, or a call under
	// an Idempotency-Key).
	idempotent bool
	// noRetry: never repeated, even after a retryable answer.
	noRetry bool
}

// do sends one request with bounded retries of a retryable answer (the
// server's delay honoured up to MaxRetryWait) and, for an idempotent call,
// of a lost answer. A 401 mints the plane's credential again once.
func (c *Client) do(ctx context.Context, r request) (*http.Response, error) {
	reauth := false
	for attempt := 0; ; attempt++ {
		base, auth, err := c.authFor(ctx, r, reauth)
		if err != nil {
			return nil, err
		}
		target := strings.TrimSuffix(base, "/") + r.path
		if len(r.query) > 0 {
			target += "?" + r.query.Encode()
		}
		var body io.Reader
		switch {
		case r.stream != nil:
			body = r.stream()
		case r.body != nil:
			body = bytes.NewReader(r.body)
		}
		req, err := http.NewRequestWithContext(ctx, r.method, target, body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", authorization(auth))
		if r.ctype != "" {
			req.Header.Set("Content-Type", r.ctype)
		}
		for k, v := range r.header {
			req.Header[k] = v
		}
		resp, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() == nil && r.idempotent && r.stream == nil && attempt < c.o.Retries {
				if serr := c.o.Sleep(ctx, backoff(attempt)); serr != nil {
					return nil, serr
				}
				continue
			}
			return nil, errors.New(c.redact(err.Error()))
		}
		if resp.StatusCode < 400 {
			return resp, nil
		}
		ae := c.readError(resp)
		if resp.StatusCode == http.StatusUnauthorized && !reauth && r.stream == nil {
			reauth = true
			continue
		}
		if r.noRetry || r.stream != nil || !ae.retry || attempt >= c.o.Retries || ae.after > c.o.MaxRetryWait {
			return nil, classify(ae)
		}
		wait := ae.after
		if wait == 0 {
			wait = backoff(attempt)
		}
		if err := c.o.Sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

func backoff(attempt int) time.Duration {
	return time.Duration(1<<attempt) * 400 * time.Millisecond
}

// authFor returns the base URL and the issued value of a request's plane,
// minting it when absent (or again when force).
func (c *Client) authFor(ctx context.Context, r request, force bool) (base, auth string, err error) {
	if r.plane == planeBox {
		g, err := c.grant(ctx, r.box, force)
		if err != nil {
			return "", "", err
		}
		return g.base, g.scope, nil
	}
	m, err := c.management(ctx, force)
	return c.o.Endpoint, m, err
}

// doJSON sends a JSON body and decodes a JSON answer into out (nil: drop).
func (c *Client) doJSON(ctx context.Context, r request, in, out any) (http.Header, int, error) {
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, 0, err
		}
		r.body, r.ctype = b, "application/json"
	}
	resp, err := c.do(ctx, r)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if out == nil || resp.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return resp.Header, resp.StatusCode, nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out); err != nil {
		return nil, 0, fmt.Errorf("dockersbx: %s %s: decode: %w", r.method, r.path, err)
	}
	return resp.Header, resp.StatusCode, nil
}

// ---- credentials --------------------------------------------------------------

// exchangeBody is the Docker Hub exchange request (the authentication page:
// the Docker ID and the account's access token).
type exchangeBody struct {
	Identifier string `json:"identifier"`
	Value      string `json:"secret"`
}

// exchangeAnswer is the field of the exchange answer the client reads.
type exchangeAnswer struct {
	Issued string `json:"access_token"`
}

// management returns the management token, exchanging the account's access
// token for one when there is none (or again when force).
func (c *Client) management(ctx context.Context, force bool) (string, error) {
	c.mu.Lock()
	m := c.mgmt
	c.mu.Unlock()
	if m != "" && !force {
		return m, nil
	}
	b, err := json.Marshal(exchangeBody{Identifier: c.o.DockerID, Value: c.o.Access}) //nolint:gosec // G117: the exchange body IS the credential, sent only to the bound Docker Hub exchange URL
	if err != nil {
		return "", err
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.o.ExchangeURL, bytes.NewReader(b))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.http.Do(req)
		if err != nil {
			return "", fmt.Errorf("dockersbx: exchange: %s", c.redact(err.Error()))
		}
		if resp.StatusCode >= 400 {
			ae := c.readError(resp)
			if ae.retry && attempt < c.o.Retries && ae.after <= c.o.MaxRetryWait {
				wait := ae.after
				if wait == 0 {
					wait = backoff(attempt)
				}
				if err := c.o.Sleep(ctx, wait); err != nil {
					return "", err
				}
				continue
			}
			return "", fmt.Errorf("dockersbx: exchange: %w", classify(ae))
		}
		var out exchangeAnswer
		derr := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out)
		resp.Body.Close()
		if derr != nil || out.Issued == "" {
			return "", errors.New("dockersbx: exchange: the answer carries no management token")
		}
		c.mu.Lock()
		c.mgmt = out.Issued
		c.mu.Unlock()
		return out.Issued, nil
	}
}

// grantRequest is the CreateEndpointCredential body.
type grantRequest struct {
	Permissions []string `json:"permissions"`
	TTL         string   `json:"ttl"`
}

// grantAnswer is the EndpointCredential fields the client reads.
type grantAnswer struct {
	Issued     string `json:"token"`
	ExpireTime string `json:"expireTime"`
}

// grant returns a box's scoped endpoint grant and endpoint base, minting
// one when there is none, it has less than endpointMargin left, or force.
func (c *Client) grant(ctx context.Context, box string, force bool) (endpointGrant, error) {
	now := c.o.Now()
	c.mu.Lock()
	g, ok := c.grants[box]
	base := c.uris[box]
	c.mu.Unlock()
	if ok && !force && g.expiry.Sub(now) > endpointMargin {
		return g, nil
	}
	if base == "" {
		if _, err := c.Get(ctx, box); err != nil {
			return endpointGrant{}, err
		}
		c.mu.Lock()
		base = c.uris[box]
		c.mu.Unlock()
	}
	if base == "" {
		return endpointGrant{}, fmt.Errorf("dockersbx: box %s publishes no endpoint", box)
	}
	if !c.allowed(base) {
		return endpointGrant{}, fmt.Errorf("dockersbx: %w: box %s's endpoint %q is not an https URL under %s", sandboxremote.ErrCredentialEndpointMismatch, box, base, strings.Join(c.vendor.Domains, ", "))
	}
	var out grantAnswer
	_, _, err := c.doJSON(ctx, request{
		plane: planeManagement, method: http.MethodPost, path: "/v1/sandboxes/" + url.PathEscape(box) + "/endpoint-credentials", idempotent: true,
	}, grantRequest{Permissions: endpointPermissions, TTL: endpointTTL}, &out)
	if err != nil {
		return endpointGrant{}, fmt.Errorf("dockersbx: endpoint grant: %w", err)
	}
	if out.Issued == "" {
		return endpointGrant{}, errors.New("dockersbx: endpoint grant: the answer carries none")
	}
	exp, perr := time.Parse(time.RFC3339Nano, out.ExpireTime)
	if perr != nil {
		exp = now.Add(4 * time.Minute)
	}
	ng := endpointGrant{base: base, expiry: exp}
	ng.scope = out.Issued
	c.mu.Lock()
	c.grants[box] = ng
	c.mu.Unlock()
	return ng, nil
}

// ---- boxes --------------------------------------------------------------------

// sandboxJSON is the Sandbox schema, the fields the client reads.
type sandboxJSON struct {
	Name        string `json:"name"`
	UID         string `json:"uid"`
	DisplayName string `json:"displayName"`
	Core        struct {
		Status   string            `json:"status"`
		Labels   map[string]string `json:"labels"`
		Etag     string            `json:"etag"`
		Endpoint struct {
			URI string `json:"uri"`
		} `json:"endpoint"`
	} `json:"core"`
	EffectiveFeatures struct {
		Timeouts struct {
			ExpiresAt string `json:"expiresAt"`
		} `json:"timeouts"`
	} `json:"effectiveFeatures"`
	Failure *errorBody `json:"failure"`
}

// id is the box's immutable id: the uid, or the resource name's last
// segment.
func (s sandboxJSON) id() string {
	if s.UID != "" {
		return s.UID
	}
	return strings.TrimPrefix(s.Name, "sandboxes/")
}

// live reports the statuses in which the box still runs or may (running,
// or degraded: runtime contact lost, recovery or failure may follow).
func live(status string) bool { return status == "running" || status == "degraded" }

func (c *Client) info(s sandboxJSON) sandboxremote.BoxInfo {
	id := s.id()
	if u := s.Core.Endpoint.URI; u != "" {
		c.mu.Lock()
		c.uris[id] = u
		c.mu.Unlock()
	}
	info := sandboxremote.BoxInfo{
		ID: id, Region: sandboxremote.ProviderChosen, Running: live(s.Core.Status),
		Labels: s.Core.Labels, Extra: map[string]string{"name": s.Name, "status": s.Core.Status},
	}
	if s.DisplayName != "" {
		info.Extra["display_name"] = s.DisplayName
	}
	if s.Failure != nil {
		info.Extra["failure"] = c.redact(strings.TrimSpace(s.Failure.Code + " " + s.Failure.Message))
	}
	if t, err := time.Parse(time.RFC3339Nano, s.EffectiveFeatures.Timeouts.ExpiresAt); err == nil {
		info.Deadline = t
	}
	return info
}

// BoxName derives the display name from a run id (the vendor allows
// [a-zA-Z0-9_-], up to 64).
func BoxName(run string) string {
	var b strings.Builder
	b.WriteString("observer-")
	for _, r := range run {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	s := b.String()
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

// The create request (CreateSandboxRequest; unknown fields are refused, so
// every optional field is omitted when unset).
type (
	createBody struct {
		DisplayName      string            `json:"displayName"`
		ImageRef         string            `json:"imageRef"`
		Resources        resources         `json:"resources"`
		Labels           map[string]string `json:"labels"`
		StartupExecution startup           `json:"startupExecution"`
		Features         features          `json:"features"`
		NetworkPolicies  []networkPolicy   `json:"networkPolicies,omitempty"`
	}
	resources struct {
		CPUs      int `json:"cpus"`
		MemoryMiB int `json:"memoryMib"`
	}
	startup struct {
		RawImage struct {
			Start struct {
				Argv []string `json:"argv"`
			} `json:"start"`
		} `json:"rawImage"`
	}
	features struct {
		Timeouts struct {
			Timeout   string `json:"timeout"`
			OnTimeout string `json:"onTimeout"`
		} `json:"timeouts"`
	}
	networkPolicy struct {
		Mode         string   `json:"mode"`
		DenyNetworks []string `json:"denyNetworks,omitempty"`
	}
)

// size is the box size a create asks for.
func (c *Client) size() resources {
	if c.o.CPUs > 0 && c.o.MemoryMiB > 0 {
		return resources{CPUs: c.o.CPUs, MemoryMiB: c.o.MemoryMiB}
	}
	return resources{CPUs: boxCPUs, MemoryMiB: boxMemoryMiB}
}

// denyEverything are the explicit deny rules of the none and proxy_only
// policy: every name and every address. A denyAll mode alone is not a deny:
// the live smoke of 2026-11-11 found an installed default-layer allow of
// "**" in the effective policy, and example.com, 1.1.1.1, github.com and
// the npm registry all answered from a denyAll box. A deny rule wins over an
// allow (the network-policy page), and with these three the same box
// resolved no name and reached no address.
var denyEverything = []string{"**", "0.0.0.0/0", "::/0"}

// networkPolicies maps a tier: an inline denyAll with explicit deny rules
// for every name and address for none and proxy_only, where the relay is
// the only way out; none for internet (the inline policy has no allow-all
// mode, so the account's default applies).
func networkPolicies(t vocab.Tier) []networkPolicy {
	if t == vocab.TierInternet {
		return nil
	}
	return []networkPolicy{{Mode: "denyAll", DenyNetworks: denyEverything}}
}

// Create admits a box from the template (or DefaultImage) at the small
// size, with the run label, the keep-alive start command, a delete-on-timeout
// deadline and the tier's network policy, then waits until it runs. The
// request carries an Idempotency-Key derived from the run, so a lost answer
// is recovered by repeating it (the errors page); past the retries it reads
// ErrCreateUnknown. A box that fails to start is deleted.
func (c *Client) Create(ctx context.Context, spec sandboxremote.BoxSpec) (sandboxremote.BoxInfo, error) {
	if spec.TimeoutSeconds <= 0 {
		return sandboxremote.BoxInfo{}, errors.New("dockersbx: a box needs a timeout")
	}
	labels := maps.Clone(spec.Labels)
	if labels == nil {
		labels = map[string]string{}
	}
	labels[sandboxremote.LabelKey] = spec.RunID
	image := spec.Template
	if image == "" {
		image = DefaultImage
	}
	body := createBody{
		DisplayName: BoxName(spec.RunID), ImageRef: image,
		Resources: c.size(), Labels: labels,
		NetworkPolicies: networkPolicies(spec.Tier),
	}
	body.StartupExecution.RawImage.Start.Argv = keepAlive
	body.Features.Timeouts.Timeout = strconv.Itoa(spec.TimeoutSeconds) + "s"
	body.Features.Timeouts.OnTimeout = "delete"
	var out sandboxJSON
	_, _, err := c.doJSON(ctx, request{
		plane: planeManagement, method: http.MethodPost, path: "/v1/sandboxes", idempotent: true,
		header: http.Header{"Idempotency-Key": {"observer-create-" + BoxName(spec.RunID)}},
	}, body, &out)
	var ae *apiError
	switch {
	case errors.As(err, &ae) && ae.status == http.StatusConflict:
		// The display name exists (or the key was used with another body):
		// accepted only as this run's box.
		boxes, lerr := c.ListByLabel(ctx, sandboxremote.LabelKey, spec.RunID)
		if lerr != nil || len(boxes) != 1 {
			return sandboxremote.BoxInfo{}, fmt.Errorf("dockersbx: create: the name exists and is not this run's box: %w", err)
		}
		return c.waitRunning(ctx, boxes[0].ID, spec)
	case err != nil && ae == nil && !errors.Is(err, sandboxremote.ErrRateLimited) && ctx.Err() == nil,
		// A 5xx still there after the retries may come after the box was
		// admitted: lost, resolved by the run label.
		err != nil && ae != nil && ae.status >= 500 && ctx.Err() == nil:
		return sandboxremote.BoxInfo{}, fmt.Errorf("dockersbx: create: %w (%s)", sandboxremote.ErrCreateUnknown, c.redact(err.Error()))
	case errors.As(err, &ae) && spec.Template != "" && (ae.status == http.StatusBadRequest || ae.status == http.StatusNotFound):
		// Refused before admission (the image reference): no box was made.
		return sandboxremote.BoxInfo{}, fmt.Errorf("dockersbx: create: %w: %w", sandboxremote.ErrTemplateUnavailable, err)
	case err != nil:
		return sandboxremote.BoxInfo{}, fmt.Errorf("dockersbx: create: %w", err)
	}
	if len(spec.Env) > 0 {
		c.mu.Lock()
		c.env[out.id()] = maps.Clone(spec.Env)
		c.mu.Unlock()
	}
	if out.Core.Status == "running" {
		if out.Core.Labels == nil {
			out.Core.Labels = labels
		}
		return c.info(out), nil
	}
	return c.waitRunning(ctx, out.id(), spec)
}

// waitRunning reads the box until it runs, bounded by ReadyWait. A box that
// failed, or did not run in time, is deleted (it would otherwise bill until
// its timeout) and the create fails; a failed template box reads
// ErrTemplateUnavailable.
func (c *Client) waitRunning(ctx context.Context, id string, spec sandboxremote.BoxSpec) (sandboxremote.BoxInfo, error) {
	deadline := c.o.Now().Add(c.o.ReadyWait)
	for {
		s, err := c.get(ctx, id)
		if err != nil {
			return sandboxremote.BoxInfo{}, fmt.Errorf("dockersbx: create: read the new box: %w", err)
		}
		switch s.Core.Status {
		case "running":
			return c.info(s), nil
		case "failed", "deleting", "stopped":
			why := s.Core.Status
			if s.Failure != nil {
				why += ": " + c.redact(s.Failure.Code+" "+s.Failure.Message)
			}
			_ = c.Delete(context.WithoutCancel(ctx), id)
			if spec.Template != "" && s.Core.Status == "failed" {
				return sandboxremote.BoxInfo{}, fmt.Errorf("dockersbx: create: %w: the box did not start (%s)", sandboxremote.ErrTemplateUnavailable, why)
			}
			return sandboxremote.BoxInfo{}, fmt.Errorf("dockersbx: create: the box did not start (%s)", why)
		}
		if !c.o.Now().Before(deadline) {
			_ = c.Delete(context.WithoutCancel(ctx), id)
			return sandboxremote.BoxInfo{}, fmt.Errorf("dockersbx: create: the box was still %s after %s and was deleted", s.Core.Status, c.o.ReadyWait)
		}
		if err := c.o.Sleep(ctx, c.o.Poll); err != nil {
			return sandboxremote.BoxInfo{}, err
		}
	}
}

// get reads one box and its etag.
func (c *Client) get(ctx context.Context, id string) (sandboxJSON, error) {
	var out sandboxJSON
	h, _, err := c.doJSON(ctx, request{plane: planeManagement, method: http.MethodGet, path: "/v1/sandboxes/" + url.PathEscape(id), idempotent: true}, nil, &out)
	if err != nil {
		return sandboxJSON{}, err
	}
	if out.UID == "" && out.Name == "" {
		out.UID = id
	}
	if et := h.Get("ETag"); et != "" {
		out.Core.Etag = et
	}
	return out, nil
}

// Get reads a box by id.
func (c *Client) Get(ctx context.Context, id string) (sandboxremote.BoxInfo, error) {
	s, err := c.get(ctx, id)
	if err != nil {
		return sandboxremote.BoxInfo{}, err
	}
	return c.info(s), nil
}

// ListByLabel lists the account's boxes carrying key=value. The API filters
// on name, display name, uid, status and agent only, so every page is read
// and the label is matched here.
func (c *Client) ListByLabel(ctx context.Context, key, value string) ([]sandboxremote.BoxInfo, error) {
	var boxes []sandboxremote.BoxInfo
	next := ""
	for page := 0; page < 100; page++ {
		q := url.Values{}
		q.Set("pageSize", "100")
		if next != "" {
			q.Set("pageToken", next)
		}
		var out struct {
			Sandboxes []sandboxJSON `json:"sandboxes"`
			Next      string        `json:"nextPageToken"`
		}
		if _, _, err := c.doJSON(ctx, request{plane: planeManagement, method: http.MethodGet, path: "/v1/sandboxes", query: q, idempotent: true}, nil, &out); err != nil {
			return nil, err
		}
		for _, s := range out.Sandboxes {
			if s.Core.Labels[key] == value {
				boxes = append(boxes, c.info(s))
			}
		}
		if out.Next == "" {
			return boxes, nil
		}
		next = out.Next
	}
	return boxes, errors.New("dockersbx: list: too many pages")
}

// Delete deletes a box with force, sending its current etag as If-Match (an
// etag that moved is read again once). A 202 is the deleting box, a 204 a
// box already gone; the caller confirms with Get.
func (c *Client) Delete(ctx context.Context, id string) error {
	for attempt := 0; attempt < 2; attempt++ {
		s, err := c.get(ctx, id)
		if err != nil {
			return err
		}
		if s.Core.Status == "deleting" {
			return nil
		}
		q := url.Values{}
		q.Set("force", "true")
		_, _, err = c.doJSON(ctx, request{
			plane: planeManagement, method: http.MethodDelete, path: "/v1/sandboxes/" + url.PathEscape(id), query: q, idempotent: true,
			header: http.Header{"If-Match": {s.Core.Etag}, "Idempotency-Key": {newIdem("observer-delete-")}},
		}, nil, nil)
		var ae *apiError
		if errors.As(err, &ae) && ae.status == http.StatusPreconditionFailed {
			continue
		}
		if err == nil || errors.Is(err, sandboxremote.ErrNotFound) {
			c.mu.Lock()
			delete(c.grants, id)
			delete(c.uris, id)
			delete(c.env, id)
			c.mu.Unlock()
		}
		return err
	}
	return fmt.Errorf("dockersbx: delete %s: the box kept changing", id)
}

// ---- files --------------------------------------------------------------------

// Upload batches: one streamed request carries at most this many files or
// bytes.
const (
	uploadBatchFiles = 256
	uploadBatchBytes = 64 << 20
)

// maxRead caps one file read when the caller names no cap.
const maxRead = 512 << 20

// WriteFiles makes each file's directory (parents included), then streams
// the files in multipart batches of metadata and content pairs, each file
// with its mode. A batch is sent once (its content is opened once).
func (c *Client) WriteFiles(ctx context.Context, box string, files []sandboxremote.UploadFile) error {
	dirs := map[string]bool{}
	for _, f := range files {
		if !strings.HasPrefix(f.Path, "/") || cleanSlash(f.Path) != f.Path {
			return fmt.Errorf("dockersbx: upload path %q is not a clean absolute path", f.Path)
		}
		if d := dirOf(f.Path); d != "/" {
			dirs[d] = true
		}
	}
	for _, d := range sortedKeys(dirs) {
		if err := c.mkdir(ctx, box, d); err != nil {
			return err
		}
	}
	for len(files) > 0 {
		n, size := 0, int64(0)
		for n < len(files) && n < uploadBatchFiles && (n == 0 || size+files[n].Size <= uploadBatchBytes) {
			size += files[n].Size
			n++
		}
		if err := c.uploadBatch(ctx, box, files[:n]); err != nil {
			return err
		}
		files = files[n:]
	}
	return nil
}

func (c *Client) mkdir(ctx context.Context, box, dir string) error {
	body := struct {
		Path    string `json:"path"`
		Mode    int    `json:"mode"`
		Parents bool   `json:"parents"`
	}{dir, 0o755, true}
	_, _, err := c.doJSON(ctx, request{plane: planeBox, box: box, method: http.MethodPut, path: "/v1/files/directories", idempotent: true}, body, nil)
	if err != nil {
		return fmt.Errorf("dockersbx: mkdir %s: %w", dir, err)
	}
	return nil
}

// uploadBatch streams one batch to /v1/files/upload.
func (c *Client) uploadBatch(ctx context.Context, box string, files []sandboxremote.UploadFile) error {
	ctype, stream := multipartStream(files)
	var out struct {
		FilesWritten int `json:"filesWritten"`
	}
	_, _, err := c.doJSON(ctx, request{plane: planeBox, box: box, method: http.MethodPost, path: "/v1/files/upload", ctype: ctype, stream: stream, noRetry: true}, nil, &out)
	if err != nil {
		return fmt.Errorf("dockersbx: upload: %w", err)
	}
	if out.FilesWritten != 0 && out.FilesWritten != len(files) {
		return fmt.Errorf("dockersbx: upload: %d of %d files written", out.FilesWritten, len(files))
	}
	return nil
}

// ReadFile reads one file's raw bytes, refusing one over max bytes.
func (c *Client) ReadFile(ctx context.Context, box, p string, max int64) ([]byte, error) {
	if max <= 0 {
		max = maxRead
	}
	q := url.Values{}
	q.Set("path", p)
	resp, err := c.do(ctx, request{plane: planeBox, box: box, method: http.MethodGet, path: "/v1/files/content", query: q, idempotent: true})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.ContentLength > max {
		return nil, fmt.Errorf("dockersbx: %s is over %d bytes", p, max)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, errors.New(c.redact(err.Error()))
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("dockersbx: %s is over %d bytes", p, max)
	}
	return data, nil
}
