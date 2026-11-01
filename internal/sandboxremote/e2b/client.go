// Package e2b is the E2B wire client of the hosted sandbox rows (sandbox
// plan v2 section 13 P7 R2, lane SBX-P7): E2B's REST control plane and
// envd's Connect-RPC process service and files endpoint, spoken from Go with
// net/http (no SDK). It is one of the three packages that talk to a vendor
// (an egress lane row in tests/invariant/egress_lanes_test.go) and is
// imported only by cmd/observer (tests/invariant/sandbox_remote_egress_
// test.go). Every call is grounded in E2B's public spec; the table is in
// docs/sandboxed-terminals.md ("Hosted sandboxes", E2B).
//
// It implements sandboxremote.Client and nothing more: no vendor type leaves
// the package. A credential is held only in memory for the client's life and
// never appears in an error (errors carry the vendor's status and a
// redacted body).
package e2b

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// envdPort is envd's port (the E2b-Sandbox-Port routing header).
const envdPort = "49983"

// boxUser is the box's default user (envd's user query parameter).
const boxUser = "user"

// Options configure a client.
type Options struct {
	// Endpoint is the API origin the credential is bound to
	// (https://api.<domain>).
	Endpoint string
	// APIKey is the E2B API key (X-API-Key).
	APIKey string
	// EnvdURL overrides the envd origin (tests); empty derives
	// https://sandbox.<domain> from the box's domain or the endpoint.
	EnvdURL string
	// HTTP is the transport (nil: a client that never follows a redirect).
	HTTP *http.Client
	// Retries bounds the retries of a 429 or a retryable 5xx (default 3).
	Retries int
	// MaxRetryWait caps one Retry-After wait (default 10 s).
	MaxRetryWait time.Duration
	// Sleep waits (tests inject a no-op).
	Sleep func(context.Context, time.Duration) error
	// SPKISHA256 pins the API and envd servers' public key (the SHA-256 of
	// the leaf certificate's SubjectPublicKeyInfo, lowercase hex) on top of
	// the usual certificate checks: an org-published self-hosted endpoint
	// (lane SBX-UPD, SBX-GOV-4). "" pins nothing.
	SPKISHA256 string
}

// Client is the E2B wire client.
type Client struct {
	o    Options
	http *http.Client
	mu   sync.Mutex
	// boxes holds each box's envd access token and domain (from create or
	// get), so envd calls authenticate without asking again.
	boxes map[string]boxAccess
}

type boxAccess struct {
	token  string
	domain string
}

// New builds a client. It makes no call.
func New(o Options) (*Client, error) {
	u, err := url.Parse(o.Endpoint)
	if err != nil || (u.Scheme != "https" && !strings.HasPrefix(o.Endpoint, "http://127.0.0.1")) || u.Host == "" {
		return nil, fmt.Errorf("e2b: endpoint %q is not an https origin", o.Endpoint)
	}
	if strings.TrimSpace(o.APIKey) == "" {
		return nil, errors.New("e2b: no API key")
	}
	if o.Retries == 0 {
		o.Retries = 3
	}
	if o.MaxRetryWait == 0 {
		o.MaxRetryWait = 10 * time.Second
	}
	if o.Sleep == nil {
		o.Sleep = func(ctx context.Context, d time.Duration) error {
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
	hc := o.HTTP
	if hc == nil {
		hc = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		if o.SPKISHA256 != "" {
			hc.Transport = pinnedTransport(o.SPKISHA256, nil)
		}
	}
	return &Client{o: o, http: hc, boxes: map[string]boxAccess{}}, nil
}

var _ sandboxremote.Client = (*Client)(nil)

// apiError is a vendor error with the key redacted.
type apiError struct {
	status int
	body   string
	retry  bool
	after  time.Duration
}

func (e *apiError) Error() string {
	return "e2b: HTTP " + strconv.Itoa(e.status) + ": " + e.body
}

func (c *Client) redact(s string) string {
	return sandboxremote.Redact(s, []string{c.o.APIKey})
}

// do sends one control-plane request with bounded retries of 429 and
// retryable 5xx answers (Retry-After honoured up to MaxRetryWait).
func (c *Client) do(ctx context.Context, method, path string, body any, extra http.Header) (*http.Response, error) {
	var payload []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		payload = b
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.o.Endpoint, "/")+path, bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-API-Key", c.o.APIKey)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range extra {
			req.Header[k] = v
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, errors.New(c.redact(err.Error()))
		}
		if resp.StatusCode < 400 {
			return resp, nil
		}
		ae := c.readError(resp)
		if !ae.retry || attempt >= c.o.Retries {
			if resp.StatusCode == http.StatusTooManyRequests {
				return nil, fmt.Errorf("%w: %w", sandboxremote.ErrRateLimited, ae)
			}
			if resp.StatusCode == http.StatusNotFound {
				return nil, fmt.Errorf("%w: %w", sandboxremote.ErrNotFound, ae)
			}
			return nil, ae
		}
		wait := ae.after
		if wait == 0 {
			wait = time.Duration(1<<attempt) * 500 * time.Millisecond
		}
		if wait > c.o.MaxRetryWait {
			wait = c.o.MaxRetryWait
		}
		if err := c.o.Sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

// readError reads a vendor error answer (`{code, message}`), redacted and
// capped, and decides whether to retry: a 429 always, a 5xx unless the
// vendor's Should-Retry says false.
func (c *Client) readError(resp *http.Response) *apiError {
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var e struct {
		Message string `json:"message"`
	}
	msg := strings.TrimSpace(string(b))
	if json.Unmarshal(b, &e) == nil && e.Message != "" {
		msg = e.Message
	}
	ae := &apiError{status: resp.StatusCode, body: c.redact(msg)}
	ae.retry = resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
	if resp.Header.Get("Should-Retry") == "false" {
		ae.retry = false
	}
	if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s >= 0 {
		ae.after = time.Duration(s) * time.Second
	}
	return ae
}

// newSandboxV2 is the create body (spec/openapi.yml NewSandboxV2).
type newSandboxV2 struct {
	TemplateID          string            `json:"templateID"`
	Timeout             int               `json:"timeout"`
	AutoPause           bool              `json:"autoPause"`
	AllowInternetAccess bool              `json:"allow_internet_access"`
	Metadata            map[string]string `json:"metadata,omitempty"`
	EnvVars             map[string]string `json:"envVars,omitempty"`
}

// sandboxResp is the create and get answer (Sandbox / SandboxDetail).
type sandboxResp struct {
	SandboxID       string            `json:"sandboxID"`
	EnvdAccessToken string            `json:"envdAccessToken"`
	Domain          *string           `json:"domain"`
	State           string            `json:"state"`
	EndAt           string            `json:"endAt"`
	Metadata        map[string]string `json:"metadata"`
}

// defaultTemplate is E2B's base template (the docs' default).
const defaultTemplate = "base"

// idempotencyKey derives the create's Idempotency-Key from the run label
// (the vendor allows [a-z0-9-], 1 to 255): a retried create replays the
// first answer instead of creating a second box.
func idempotencyKey(run string) string {
	var b strings.Builder
	b.WriteString("observer-")
	for _, r := range strings.ToLower(run) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Create starts a box with the vendor's own timeout, the run label as
// metadata and auto-pause off. A transport failure after the request was
// sent returns ErrCreateUnknown: the box may exist under its label.
func (c *Client) Create(ctx context.Context, spec sandboxremote.BoxSpec) (sandboxremote.BoxInfo, error) {
	if spec.TimeoutSeconds <= 0 {
		return sandboxremote.BoxInfo{}, errors.New("e2b: a box is never created without a timeout")
	}
	tpl := spec.Template
	if tpl == "" {
		tpl = defaultTemplate
	}
	body := newSandboxV2{
		TemplateID: tpl, Timeout: spec.TimeoutSeconds, AutoPause: false,
		// none and proxy_only: block-all (allow_internet_access = false is
		// denyOut 0.0.0.0/0); internet: E2B's default egress.
		AllowInternetAccess: string(spec.Tier) == "internet",
		Metadata:            spec.Labels, EnvVars: spec.Env,
	}
	hdr := http.Header{"Idempotency-Key": []string{idempotencyKey(spec.Labels[sandboxremote.LabelKey])}}
	resp, err := c.do(ctx, http.MethodPost, "/v2/sandboxes", body, hdr)
	if err != nil {
		var ae *apiError
		isAPI := errors.As(err, &ae)
		// A transport failure, or a 5xx still there after the retries: a
		// gateway error may come after the box was made, so the answer is
		// lost and resolved by the run label, never a definite failure (the
		// SBX-P7 merge's audit finding 6).
		if (!isAPI && !errors.Is(err, context.Canceled)) || (isAPI && ae.status >= 500) {
			return sandboxremote.BoxInfo{}, fmt.Errorf("%w: %w", sandboxremote.ErrCreateUnknown, err)
		}
		return sandboxremote.BoxInfo{}, err
	}
	defer resp.Body.Close()
	var s sandboxResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&s); err != nil || s.SandboxID == "" {
		return sandboxremote.BoxInfo{}, fmt.Errorf("%w: the create answer did not parse", sandboxremote.ErrCreateUnknown)
	}
	c.remember(s)
	info := c.info(s)
	info.Running = true
	info.Deadline = time.Now().Add(time.Duration(spec.TimeoutSeconds) * time.Second)
	return info, nil
}

func (c *Client) remember(s sandboxResp) {
	if s.SandboxID == "" || s.EnvdAccessToken == "" {
		return
	}
	acc := boxAccess{token: s.EnvdAccessToken}
	if s.Domain != nil {
		acc.domain = *s.Domain
	}
	c.mu.Lock()
	c.boxes[s.SandboxID] = acc
	c.mu.Unlock()
}

func (c *Client) info(s sandboxResp) sandboxremote.BoxInfo {
	i := sandboxremote.BoxInfo{ID: s.SandboxID, Running: s.State == "" || s.State == "running", Labels: s.Metadata, EnvdToken: s.EnvdAccessToken}
	if s.Domain != nil {
		i.Extra = map[string]string{"domain": *s.Domain}
	}
	if t, err := time.Parse(time.RFC3339, s.EndAt); err == nil {
		i.Deadline = t
	}
	return i
}

// Get reads one box (ErrNotFound once it is gone).
func (c *Client) Get(ctx context.Context, id string) (sandboxremote.BoxInfo, error) {
	resp, err := c.do(ctx, http.MethodGet, "/sandboxes/"+url.PathEscape(id), nil, nil)
	if err != nil {
		return sandboxremote.BoxInfo{}, err
	}
	defer resp.Body.Close()
	var s sandboxResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&s); err != nil {
		return sandboxremote.BoxInfo{}, fmt.Errorf("e2b: the get answer did not parse: %w", err)
	}
	c.remember(s)
	return c.info(s), nil
}

// ListByLabel lists the boxes whose metadata holds key = value.
func (c *Client) ListByLabel(ctx context.Context, key, value string) ([]sandboxremote.BoxInfo, error) {
	var out []sandboxremote.BoxInfo
	meta := url.QueryEscape(key) + "=" + url.QueryEscape(value)
	next := ""
	for page := 0; page < 50; page++ {
		q := url.Values{"metadata": {meta}, "limit": {"100"}}
		if next != "" {
			q.Set("nextToken", next)
		}
		resp, err := c.do(ctx, http.MethodGet, "/v2/sandboxes?"+q.Encode(), nil, nil)
		if err != nil {
			return nil, err
		}
		var list []sandboxResp
		err = json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&list)
		next = resp.Header.Get("X-Next-Token")
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("e2b: the list answer did not parse: %w", err)
		}
		for _, s := range list {
			if s.Metadata[key] == value {
				out = append(out, c.info(s))
			}
		}
		if next == "" {
			return out, nil
		}
	}
	return out, nil
}

// Delete kills a box (ErrNotFound when it is already gone).
func (c *Client) Delete(ctx context.Context, id string) error {
	resp, err := c.do(ctx, http.MethodDelete, "/sandboxes/"+url.PathEscape(id), nil, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	c.mu.Lock()
	delete(c.boxes, id)
	c.mu.Unlock()
	return nil
}

// access returns a box's envd origin and token.
func (c *Client) access(ctx context.Context, id string) (string, string, error) {
	c.mu.Lock()
	acc, ok := c.boxes[id]
	c.mu.Unlock()
	if !ok {
		if _, err := c.Get(ctx, id); err != nil {
			return "", "", err
		}
		c.mu.Lock()
		acc, ok = c.boxes[id]
		c.mu.Unlock()
		if !ok {
			return "", "", errors.New("e2b: no envd access token for the box")
		}
	}
	if c.o.EnvdURL != "" {
		return strings.TrimSuffix(c.o.EnvdURL, "/"), acc.token, nil
	}
	domain := acc.domain
	if domain == "" {
		u, _ := url.Parse(c.o.Endpoint)
		domain = strings.TrimPrefix(u.Hostname(), "api.")
	}
	return "https://sandbox." + domain, acc.token, nil
}

// envdRequest builds a request to envd with the routing and token headers.
func (c *Client) envdRequest(ctx context.Context, id, method, path string, body io.Reader, asRoot bool) (*http.Request, string, error) {
	base, token, err := c.access(ctx, id)
	if err != nil {
		return nil, "", err
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, body)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("E2b-Sandbox-Id", id)
	req.Header.Set("E2b-Sandbox-Port", envdPort)
	req.Header.Set("X-Access-Token", token)
	user := boxUser
	if asRoot {
		user = "root"
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":")))
	return req, token, nil
}

// envdError reads an envd error answer, with both secrets redacted.
func (c *Client) envdError(resp *http.Response, token string) error {
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	msg := sandboxremote.Redact(strings.TrimSpace(string(b)), []string{c.o.APIKey, token})
	err := fmt.Errorf("e2b envd: HTTP %d: %s", resp.StatusCode, msg)
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusBadGateway {
		return fmt.Errorf("%w: %w", sandboxremote.ErrNotFound, err)
	}
	return err
}

// WriteFiles uploads each file through envd's /files (multipart, part
// "file"); parents are created by envd. The mode is applied by the caller
// with an exec (envd's upload has no mode field).
func (c *Client) WriteFiles(ctx context.Context, id string, files []sandboxremote.UploadFile) error {
	for _, f := range files {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		pr, pw := io.Pipe()
		mw := multipart.NewWriter(pw)
		go func() {
			part, err := mw.CreateFormFile("file", f.Path)
			if err == nil {
				_, err = io.Copy(part, rc)
			}
			if err == nil {
				err = mw.Close()
			}
			_ = rc.Close()
			pw.CloseWithError(err)
		}()
		q := url.Values{"path": {f.Path}, "username": {boxUser}}
		req, token, err := c.envdRequest(ctx, id, http.MethodPost, "/files?"+q.Encode(), pr, false)
		if err != nil {
			_ = pr.Close()
			return err
		}
		req.Header.Set("Content-Type", mw.FormDataContentType())
		resp, err := c.http.Do(req)
		if err != nil {
			_ = pr.Close()
			return errors.New(c.redact(err.Error()))
		}
		if resp.StatusCode != http.StatusOK {
			return c.envdError(resp, token)
		}
		resp.Body.Close()
	}
	return nil
}

// ReadFile downloads one file through envd's /files, capped at max.
func (c *Client) ReadFile(ctx context.Context, id, path string, max int64) ([]byte, error) {
	q := url.Values{"path": {path}, "username": {boxUser}}
	req, token, err := c.envdRequest(ctx, id, http.MethodGet, "/files?"+q.Encode(), nil, false)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, errors.New(c.redact(err.Error()))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, c.envdError(resp, token)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("e2b: %s is over %d bytes", path, max)
	}
	return b, nil
}

// pinnedTransport is an HTTPS transport that, after the usual certificate
// verification, also requires the leaf's SubjectPublicKeyInfo to hash to
// pin. roots nil uses the system roots.
func pinnedTransport(pin string, roots *x509.CertPool) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("e2b: the server sent no certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if !strings.EqualFold(hex.EncodeToString(sum[:]), pin) {
				return errors.New("e2b: the server's public key does not match the endpoint's pin")
			}
			return nil
		},
	}
	return t
}
