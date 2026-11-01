// Package vercel is the Vercel Sandbox wire client of the hosted sandbox
// rows (sandbox plan v2 section 13 P7 R4, lane SBX-P7): Vercel's public REST
// API (api.vercel.com, the /v2 and /v3 sandbox paths of openapi.vercel.sh),
// spoken from Go with net/http (no SDK). It is one of the three packages
// that talk to a vendor (an egress lane row in
// tests/invariant/egress_lanes_test.go) and is imported only by
// cmd/observer (tests/invariant/sandbox_remote_egress_test.go). The call
// table is in docs/sandboxed-terminals.md ("Hosted sandboxes", Vercel).
//
// It implements sandboxremote.Client and nothing more. A box is a Vercel
// sandbox NAME derived from the run id (so a retried or lost create is found
// by name and by tag), created with persistent=false (no snapshot on stop),
// no ports and a deny-all network policy unless the tier is internet; the
// client keeps each name's current session id, which every command and file
// call addresses. The token never appears in an error.
//
// The interactive PTY Vercel's CLI uses is an undocumented WebSocket
// protocol; the client does not speak it. The guest helper owns the PTY over
// the documented command stdin and log stream instead, so there is no
// vendor resize and no reattach (a cut transport ends the run, A7).
package vercel

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
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
	// Endpoint is the API origin the token is bound to (https://api.vercel.com).
	Endpoint string
	// Token is the Vercel access token (Authorization: Bearer).
	Token string
	// TeamID scopes every call (teamId query); ProjectID the sandboxes.
	TeamID    string
	ProjectID string
	// HTTP is the transport (nil: a client that never follows a redirect).
	HTTP *http.Client
	// Retries bounds the retries of a 429 or a 5xx (default 2, the SDK's).
	Retries int
	// MaxRetryWait caps one Retry-After wait (default 20 s: the SDK gives up
	// past it).
	MaxRetryWait time.Duration
	// Sleep waits (tests inject a no-op).
	Sleep func(context.Context, time.Duration) error
}

// Client is the Vercel Sandbox wire client.
type Client struct {
	o    Options
	http *http.Client
	mu   sync.Mutex
	// sessions holds each sandbox name's current session id.
	sessions map[string]string
}

// New builds a client. It makes no call.
func New(o Options) (*Client, error) {
	u, err := url.Parse(o.Endpoint)
	if err != nil || (u.Scheme != "https" && !strings.HasPrefix(o.Endpoint, "http://127.0.0.1")) || u.Host == "" {
		return nil, fmt.Errorf("vercel: endpoint %q is not an https origin", o.Endpoint)
	}
	if strings.TrimSpace(o.Token) == "" || strings.TrimSpace(o.TeamID) == "" || strings.TrimSpace(o.ProjectID) == "" {
		return nil, errors.New("vercel: a token, a team id and a project id are all needed")
	}
	if o.Retries == 0 {
		o.Retries = 2
	}
	if o.MaxRetryWait == 0 {
		o.MaxRetryWait = 20 * time.Second
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
	}
	return &Client{o: o, http: hc, sessions: map[string]string{}}, nil
}

var _ sandboxremote.Client = (*Client)(nil)

// apiError is a vendor error (`{"error":{"code","message"}}`), redacted.
type apiError struct {
	status       int
	code         string
	msg          string
	retry        bool
	after        time.Duration
	bytesWritten int64
}

func (e *apiError) Error() string {
	s := "vercel: HTTP " + strconv.Itoa(e.status)
	if e.code != "" {
		s += " " + e.code
	}
	return s + ": " + e.msg
}

func (c *Client) redact(s string) string {
	return sandboxremote.Redact(s, []string{c.o.Token})
}

// request is one call: method, path, query (teamId is added), a body that
// can be re-sent, and its content type.
type request struct {
	method, path string
	query        url.Values
	body         []byte
	ctype        string
	header       http.Header
	// noRetry marks a call that must not be repeated (stdin with an offset
	// is safe; a stream is not).
	noRetry bool
}

// do sends one request with bounded retries of 429 and 5xx answers
// (Retry-After honoured up to MaxRetryWait; past it the call fails as the
// SDK does).
func (c *Client) do(ctx context.Context, r request) (*http.Response, error) {
	q := url.Values{}
	maps.Copy(q, r.query)
	q.Set("teamId", c.o.TeamID)
	target := strings.TrimSuffix(c.o.Endpoint, "/") + r.path + "?" + q.Encode()
	for attempt := 0; ; attempt++ {
		var body io.Reader
		if r.body != nil {
			body = bytes.NewReader(r.body)
		}
		req, err := http.NewRequestWithContext(ctx, r.method, target, body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.o.Token)
		if r.ctype != "" {
			req.Header.Set("Content-Type", r.ctype)
		}
		for k, v := range r.header {
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

// readError reads a vendor error answer, capped and redacted.
func (c *Client) readError(resp *http.Response) *apiError {
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var e struct {
		Error struct {
			Code         string `json:"code"`
			Message      string `json:"message"`
			BytesWritten int64  `json:"bytesWritten"`
		} `json:"error"`
	}
	ae := &apiError{status: resp.StatusCode, msg: c.redact(strings.TrimSpace(string(b)))}
	if json.Unmarshal(b, &e) == nil && (e.Error.Message != "" || e.Error.Code != "") {
		ae.code, ae.msg, ae.bytesWritten = c.redact(e.Error.Code), c.redact(e.Error.Message), e.Error.BytesWritten
	}
	ae.retry = resp.StatusCode == http.StatusTooManyRequests || (resp.StatusCode >= 500 && resp.StatusCode != http.StatusGatewayTimeout)
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
		return fmt.Errorf("vercel: %s %s: decode: %w", r.method, r.path, err)
	}
	return nil
}

// sandboxJSON is a sandbox (OAPI Sandbox, the fields the client reads).
type sandboxJSON struct {
	Name             string            `json:"name"`
	Status           string            `json:"status"`
	CurrentSessionID string            `json:"currentSessionId"`
	Region           string            `json:"region"`
	Tags             map[string]string `json:"tags"`
	Persistent       bool              `json:"persistent"`
}

// sessionJSON is a session (OAPI Session, the fields the client reads).
type sessionJSON struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Region    string `json:"region"`
	Timeout   int64  `json:"timeout"`
	StartedAt int64  `json:"startedAt"`
}

// sandboxResp is the create and get answer.
type sandboxResp struct {
	Sandbox sandboxJSON `json:"sandbox"`
	Session sessionJSON `json:"session"`
}

// BoxName derives the sandbox name from a run id (the vendor allows
// [a-zA-Z0-9_-], up to 128): a retried or lost create finds the same name.
func BoxName(run string) string {
	var b strings.Builder
	b.WriteString("observer-")
	for _, r := range run {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	s := b.String()
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}

func (c *Client) remember(name, session string) {
	if name == "" || session == "" {
		return
	}
	c.mu.Lock()
	c.sessions[name] = session
	c.mu.Unlock()
}

func (c *Client) info(r sandboxResp) sandboxremote.BoxInfo {
	sid := r.Session.ID
	if sid == "" {
		sid = r.Sandbox.CurrentSessionID
	}
	c.remember(r.Sandbox.Name, sid)
	region := r.Session.Region
	if region == "" {
		region = r.Sandbox.Region
	}
	st := r.Sandbox.Status
	if r.Session.Status != "" {
		st = r.Session.Status
	}
	info := sandboxremote.BoxInfo{
		ID: r.Sandbox.Name, Region: region, Running: st == "running" || st == "pending",
		Labels: r.Sandbox.Tags, Extra: map[string]string{"session": sid, "project": c.o.ProjectID},
	}
	if r.Session.StartedAt > 0 && r.Session.Timeout > 0 {
		info.Deadline = time.UnixMilli(r.Session.StartedAt + r.Session.Timeout)
	}
	return info
}

// networkPolicy maps a tier: deny-all (DNS included) for none and
// proxy_only, where the relay is the only way out; allow-all for internet.
func networkPolicy(t vocab.Tier) map[string]string {
	if t == vocab.TierInternet {
		return map[string]string{"mode": "allow-all"}
	}
	return map[string]string{"mode": "deny-all"}
}

// Create starts a sandbox (v3, which takes an image) named from the run,
// persistent=false, no ports, the tier's network policy, the vendor
// timeout and the run tag. A 409 means the name exists: the box is read
// back and accepted only when it carries this run's tag. A transport failure
// after the request was sent returns ErrCreateUnknown.
func (c *Client) Create(ctx context.Context, spec sandboxremote.BoxSpec) (sandboxremote.BoxInfo, error) {
	if spec.TimeoutSeconds <= 0 {
		return sandboxremote.BoxInfo{}, errors.New("vercel: a box needs a timeout")
	}
	name := BoxName(spec.RunID)
	tags := maps.Clone(spec.Labels)
	if tags == nil {
		tags = map[string]string{}
	}
	tags[sandboxremote.LabelKey] = spec.RunID
	body := map[string]any{
		"projectId": c.o.ProjectID, "name": name, "timeout": spec.TimeoutSeconds * 1000,
		"persistent": false, "networkPolicy": networkPolicy(spec.Tier), "tags": tags,
	}
	if spec.Template != "" {
		body["image"] = spec.Template
	}
	if spec.Region != "" && spec.Region != sandboxremote.ProviderChosen {
		body["region"] = spec.Region
	}
	if len(spec.Env) > 0 {
		body["env"] = spec.Env
	}
	var out sandboxResp
	err := c.doJSON(ctx, request{method: http.MethodPost, path: "/v3/sandboxes"}, body, &out)
	var ae *apiError
	switch {
	case errors.As(err, &ae) && ae.status == http.StatusConflict:
		got, gerr := c.Get(ctx, name)
		if gerr != nil {
			return sandboxremote.BoxInfo{}, fmt.Errorf("vercel: create: the name exists and could not be read: %w", gerr)
		}
		if got.Labels[sandboxremote.LabelKey] != spec.RunID {
			return sandboxremote.BoxInfo{}, fmt.Errorf("vercel: create: a sandbox named %s exists for another run", name)
		}
		return got, nil
	case err != nil && ae == nil && !errors.Is(err, sandboxremote.ErrRateLimited) && ctx.Err() == nil,
		// A 5xx still there after the retries may come after the box was
		// made: lost, resolved by the run label (the SBX-P7 merge's audit
		// finding 6).
		err != nil && ae != nil && ae.status >= 500 && ctx.Err() == nil:
		return sandboxremote.BoxInfo{}, fmt.Errorf("vercel: create: %w (%s)", sandboxremote.ErrCreateUnknown, c.redact(err.Error()))
	case errors.As(err, &ae) && ae.status == http.StatusNotFound && spec.Template != "":
		// The v3 create answers 404 for an image the team does not own (live
		// run 2026-10-23: "Image not found." for node22); no box was made.
		return sandboxremote.BoxInfo{}, fmt.Errorf("vercel: create: %w: %w", sandboxremote.ErrTemplateUnavailable, err)
	case err != nil:
		return sandboxremote.BoxInfo{}, fmt.Errorf("vercel: create: %w", err)
	}
	if out.Sandbox.Name == "" {
		out.Sandbox.Name = name
	}
	if out.Sandbox.Tags == nil {
		out.Sandbox.Tags = tags
	}
	return c.info(out), nil
}

// Get reads a sandbox by name (never resuming it).
func (c *Client) Get(ctx context.Context, name string) (sandboxremote.BoxInfo, error) {
	var out sandboxResp
	q := url.Values{"projectId": {c.o.ProjectID}}
	if err := c.doJSON(ctx, request{method: http.MethodGet, path: "/v2/sandboxes/" + url.PathEscape(name), query: q}, nil, &out); err != nil {
		return sandboxremote.BoxInfo{}, err
	}
	if out.Sandbox.Name == "" {
		out.Sandbox.Name = name
	}
	return c.info(out), nil
}

// ListByLabel lists the project's sandboxes carrying key=value (the
// vendor's one tag filter, re-checked here), following the pagination.
func (c *Client) ListByLabel(ctx context.Context, key, value string) ([]sandboxremote.BoxInfo, error) {
	var boxes []sandboxremote.BoxInfo
	cursor := ""
	for page := 0; page < 100; page++ {
		q := url.Values{"project": {c.o.ProjectID}, "tags": {key + ":" + value}, "limit": {"50"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var out struct {
			Sandboxes  []sandboxJSON `json:"sandboxes"`
			Pagination struct {
				Next *string `json:"next"`
			} `json:"pagination"`
		}
		if err := c.doJSON(ctx, request{method: http.MethodGet, path: "/v2/sandboxes", query: q}, nil, &out); err != nil {
			return nil, err
		}
		for _, s := range out.Sandboxes {
			if s.Tags[key] != value {
				continue
			}
			boxes = append(boxes, c.info(sandboxResp{Sandbox: s}))
		}
		if out.Pagination.Next == nil || *out.Pagination.Next == "" {
			return boxes, nil
		}
		cursor = *out.Pagination.Next
	}
	return boxes, errors.New("vercel: list: too many pages")
}

// Delete removes a sandbox (stopping it first) and any orphan snapshot.
func (c *Client) Delete(ctx context.Context, name string) error {
	q := url.Values{"projectId": {c.o.ProjectID}, "deleteOrphanSnapshots": {"true"}}
	err := c.doJSON(ctx, request{method: http.MethodDelete, path: "/v2/sandboxes/" + url.PathEscape(name), query: q}, nil, nil)
	if err == nil {
		c.mu.Lock()
		delete(c.sessions, name)
		c.mu.Unlock()
	}
	return err
}

// session returns a sandbox's current session id.
func (c *Client) session(ctx context.Context, name string) (string, error) {
	c.mu.Lock()
	sid := c.sessions[name]
	c.mu.Unlock()
	if sid != "" {
		return sid, nil
	}
	info, err := c.Get(ctx, name)
	if err != nil {
		return "", err
	}
	if info.Extra["session"] == "" || !info.Running {
		return "", fmt.Errorf("vercel: %s has no running session: %w", name, sandboxremote.ErrNotFound)
	}
	return info.Extra["session"], nil
}

func sessionPath(sid, rest string) string {
	return "/v2/sandboxes/sessions/" + url.PathEscape(sid) + rest
}

// uploadBatch caps the file content of one fs/write request.
const uploadBatch = 64 << 20

// maxUpload caps one file read into memory when its size is not given.
const maxUpload = 512 << 20

// WriteFiles writes the files as gzip-compressed tar batches extracted at
// the root (x-cwd /), each entry carrying its mode.
func (c *Client) WriteFiles(ctx context.Context, name string, files []sandboxremote.UploadFile) error {
	sid, err := c.session(ctx, name)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	pending := int64(0)
	flush := func() error {
		if pending == 0 {
			return nil
		}
		if err := tw.Close(); err != nil {
			return err
		}
		if err := gz.Close(); err != nil {
			return err
		}
		err := c.doJSON(ctx, request{
			method: http.MethodPost, path: sessionPath(sid, "/fs/write"), body: bytes.Clone(buf.Bytes()),
			ctype: "application/gzip", header: http.Header{"X-Cwd": {"/"}},
		}, nil, nil)
		buf.Reset()
		gz.Reset(&buf)
		tw = tar.NewWriter(gz)
		pending = 0
		return err
	}
	for _, f := range files {
		if !path.IsAbs(f.Path) || path.Clean(f.Path) != f.Path {
			return fmt.Errorf("vercel: upload path %q is not a clean absolute path", f.Path)
		}
		data, err := readUpload(f)
		if err != nil {
			return err
		}
		if pending > 0 && pending+int64(len(data)) > uploadBatch {
			if err := flush(); err != nil {
				return err
			}
		}
		mode := int64(f.Mode)
		if mode == 0 {
			mode = 0o644
		}
		hdr := &tar.Header{Name: strings.TrimPrefix(f.Path, "/"), Mode: mode, Size: int64(len(data)), Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0)}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
		pending += int64(len(data)) + 1 // an empty file still needs a request
	}
	return flush()
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
		return nil, fmt.Errorf("vercel: %s grew past %d bytes while uploading", f.Path, limit)
	}
	return data, nil
}

// ReadFile reads one file's raw bytes, refusing one over max bytes.
func (c *Client) ReadFile(ctx context.Context, name, p string, max int64) ([]byte, error) {
	sid, err := c.session(ctx, name)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(map[string]string{"path": p})
	if err != nil {
		return nil, err
	}
	resp, err := c.do(ctx, request{method: http.MethodPost, path: sessionPath(sid, "/fs/read"), body: b, ctype: "application/json"})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/octet-stream") {
		return nil, fmt.Errorf("vercel: read %s: unexpected content type %q", p, ct)
	}
	if max <= 0 {
		max = maxUpload
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, errors.New(c.redact(err.Error()))
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("vercel: %s is over %d bytes", p, max)
	}
	return data, nil
}

// Reattach: Vercel documents no reattach to a command's terminal (the
// interactive WebSocket is undocumented and unused), so a cut transport
// ends the run; the agent's own resume picks it up (A7).
func (c *Client) Reattach(context.Context, string, string) (sandboxremote.Process, error) {
	return nil, fmt.Errorf("vercel: reattach: %w", sandboxremote.ErrNotSupported)
}
