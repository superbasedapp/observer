package instabox

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
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// Options configure a client.
type Options struct {
	// Endpoint is the API origin the key is bound to (https://api.instabox.sh).
	Endpoint string
	// Key is the InstaBox API key (ibk_..., sent as X-API-Key). It needs the
	// machines:write and machines:delete scopes (machines:write includes
	// machines:read).
	Key string
	// HTTP is the transport (nil: a client that never follows a redirect).
	HTTP *http.Client
	// Retries bounds the retries of an answer the vendor marks retryable
	// (default 2).
	Retries int
	// MaxRetryWait caps one Retry-After wait (default 20 s).
	MaxRetryWait time.Duration
	// OperationWait bounds the wait for a create or a delete operation to
	// end (default 5 minutes).
	OperationWait time.Duration
	// StartWait bounds the wait for a streamed process's start marker
	// (default 2 minutes: the login shell starts first).
	StartWait time.Duration
	// Sleep waits (tests inject a no-op).
	Sleep func(context.Context, time.Duration) error
	// Rand is the source of session names and idempotency keys (nil:
	// crypto/rand).
	Rand io.Reader
}

// Client is the InstaBox wire client.
type Client struct {
	o    Options
	http *http.Client
}

// New builds a client. It makes no call.
func New(o Options) (*Client, error) {
	u, err := url.Parse(o.Endpoint)
	if err != nil || (u.Scheme != "https" && !strings.HasPrefix(o.Endpoint, "http://127.0.0.1")) || u.Host == "" {
		return nil, fmt.Errorf("instabox: endpoint %q is not an https origin", o.Endpoint)
	}
	if strings.TrimSpace(o.Key) == "" {
		return nil, errors.New("instabox: an API key is needed")
	}
	if o.Retries == 0 {
		o.Retries = 2
	}
	if o.MaxRetryWait == 0 {
		o.MaxRetryWait = 20 * time.Second
	}
	if o.OperationWait == 0 {
		o.OperationWait = 5 * time.Minute
	}
	if o.StartWait == 0 {
		o.StartWait = 2 * time.Minute
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
	if o.Rand == nil {
		o.Rand = rand.Reader
	}
	o.Endpoint = strings.TrimSuffix(o.Endpoint, "/")
	hc := o.HTTP
	if hc == nil {
		hc = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	return &Client{o: o, http: hc}, nil
}

var _ sandboxremote.Client = (*Client)(nil)

// apiError is a vendor error (the envelope
// {"error":{"code","message","requestId","retryable","operationId"}}),
// redacted.
type apiError struct {
	status    int
	code      string
	msg       string
	retryable bool
	after     time.Duration
}

func (e *apiError) Error() string {
	s := "instabox: HTTP " + strconv.Itoa(e.status)
	if e.code != "" {
		s += " " + e.code
	}
	return s + ": " + e.msg
}

func (c *Client) redact(s string) string {
	return sandboxremote.Redact(s, []string{c.o.Key})
}

// nonce returns n random bytes as lowercase hex.
func (c *Client) nonce(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(c.o.Rand, b); err != nil {
		return "", fmt.Errorf("instabox: random: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// request is one call: method, path, query, a body that can be re-sent (or
// a one-shot stream), its content type and extra headers.
type request struct {
	method, path string
	query        url.Values
	body         []byte
	stream       io.Reader
	length       int64
	ctype        string
	header       http.Header
	// noRetry marks a call that must not be repeated (a streamed body).
	noRetry bool
}

func (c *Client) target(r request) string {
	t := c.o.Endpoint + r.path
	if len(r.query) > 0 {
		t += "?" + r.query.Encode()
	}
	return t
}

// do sends one request, retrying only an answer the vendor marks retryable
// (its envelope's retryable field; a 429 or a 503 with it set), honouring
// Retry-After up to MaxRetryWait. A retried mutation carries the same
// Idempotency-Key, so the vendor replays rather than repeats it.
func (c *Client) do(ctx context.Context, r request) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		var body io.Reader
		switch {
		case r.stream != nil:
			body = r.stream
		case r.body != nil:
			body = bytes.NewReader(r.body)
		}
		req, err := http.NewRequestWithContext(ctx, r.method, c.target(r), body)
		if err != nil {
			return nil, err
		}
		if r.stream != nil && r.length >= 0 {
			req.ContentLength = r.length
		}
		req.Header.Set("X-API-Key", c.o.Key)
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
		if r.noRetry || r.stream != nil || !ae.retryable || attempt >= c.o.Retries || ae.after > c.o.MaxRetryWait {
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
			wait = time.Duration(1<<attempt) * 500 * time.Millisecond
		}
		if err := c.o.Sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

// errorBody is the vendor's error envelope (OpenAPI Error, the fields read).
type errorBody struct {
	Code              string `json:"code"`
	Message           string `json:"message"`
	Retryable         bool   `json:"retryable"`
	RetryAfterSeconds int    `json:"retryAfterSeconds"`
}

// readError reads a vendor error answer, capped and redacted.
func (c *Client) readError(resp *http.Response) *apiError {
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var e struct {
		Error errorBody `json:"error"`
	}
	ae := &apiError{status: resp.StatusCode, msg: c.redact(strings.TrimSpace(string(b)))}
	if json.Unmarshal(b, &e) == nil && (e.Error.Message != "" || e.Error.Code != "") {
		ae.code, ae.msg, ae.retryable = c.redact(e.Error.Code), c.redact(e.Error.Message), e.Error.Retryable
		if e.Error.RetryAfterSeconds > 0 {
			ae.after = time.Duration(e.Error.RetryAfterSeconds) * time.Second
		}
	}
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
		return fmt.Errorf("instabox: %s %s: decode: %w", r.method, r.path, err)
	}
	return nil
}

// machineJSON is a machine (OpenAPI Machine, the fields the client reads).
type machineJSON struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	State           string            `json:"state"`
	Metadata        map[string]string `json:"metadata"`
	DeleteAt        *string           `json:"deleteAt"`
	AutoSuspendedAt string            `json:"autoSuspendedAt"`
	CooldownUntil   *string           `json:"cooldownUntil"`
	Free            bool              `json:"free"`
	Runtime         struct {
		Ready bool `json:"ready"`
	} `json:"runtime"`
	Template struct {
		ID string `json:"id"`
	} `json:"template"`
}

// operationJSON is an operation (OpenAPI Operation, the fields read).
type operationJSON struct {
	ID        string       `json:"id"`
	MachineID string       `json:"machineId"`
	Type      string       `json:"type"`
	State     string       `json:"state"`
	Error     *errorBody   `json:"error"`
	Machine   *machineJSON `json:"machine"`
}

// BoxName derives the machine name from a run id: 1-63 lowercase letters,
// digits or dashes, starting with a letter or digit (the create's name
// rule), so a retried or lost create finds the same name.
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

// live reports whether a machine counts as running for the drivers: running
// and ready, or paused by InstaBox for idleness and not under a cooldown
// (any use wakes it, docs/idle-suspend.md). A machine the user paused or
// stopped, or one in a max-run cooldown, is not.
func live(m machineJSON, now time.Time) bool {
	if m.CooldownUntil != nil && *m.CooldownUntil != "" {
		if t, err := time.Parse(time.RFC3339, *m.CooldownUntil); err == nil && t.After(now) {
			return false
		}
	}
	switch m.State {
	case "running":
		return m.Runtime.Ready
	case "suspending", "suspended":
		return m.AutoSuspendedAt != ""
	}
	return false
}

func (c *Client) info(m machineJSON) sandboxremote.BoxInfo {
	info := sandboxremote.BoxInfo{
		ID: m.ID, Region: sandboxremote.ProviderChosen, Running: live(m, time.Now()),
		Labels: m.Metadata, Extra: map[string]string{"name": m.Name, "state": m.State},
	}
	if m.Template.ID != "" {
		info.Extra["template"] = m.Template.ID
	}
	if m.Free {
		info.Extra["plan"] = "free"
	}
	if m.CooldownUntil != nil && *m.CooldownUntil != "" {
		info.Extra["cooldown_until"] = *m.CooldownUntil
	}
	if m.DeleteAt != nil {
		if t, err := time.Parse(time.RFC3339, *m.DeleteAt); err == nil {
			info.Deadline = t
		}
	}
	return info
}

// Lifetime bounds of deleteAfterSeconds (the create's schema).
const (
	minDeleteAfter = 60
	maxDeleteAfter = 86400
)

// templateCodes are the create refusals that mean the template, not the
// account or the moment, is the problem: no machine was made.
var templateCodes = map[string]bool{
	"template_not_allowed": true, "template_unavailable": true, "kernel_unavailable": true, "template_limit": true,
}

// Create makes a machine named from the run, labelled with it (metadata),
// with deleteAfterSeconds set to the run's timeout (the vendor deletes it
// then, whatever its state), from the configured template (none: the
// vendor's default, agent-browser), and waits for the create operation to
// end. A 409 means the name exists: the machine is read back and accepted
// only when it carries this run's label. A transport failure after the
// request was sent returns ErrCreateUnknown; so does an operation whose end
// could not be read.
func (c *Client) Create(ctx context.Context, spec sandboxremote.BoxSpec) (sandboxremote.BoxInfo, error) {
	if spec.TimeoutSeconds <= 0 {
		return sandboxremote.BoxInfo{}, errors.New("instabox: a box needs a timeout")
	}
	// The vendor's create takes no deny rule (decision SBXD-7): a deny it
	// cannot carry is refused, never dropped into an open box.
	if len(spec.DenyCIDRs) > 0 {
		return sandboxremote.BoxInfo{}, fmt.Errorf("instabox: %w", sandboxremote.ErrDenyNotRenderable)
	}
	name := BoxName(spec.RunID)
	labels := maps.Clone(spec.Labels)
	if labels == nil {
		labels = map[string]string{}
	}
	labels[sandboxremote.LabelKey] = spec.RunID
	ttl := min(max(spec.TimeoutSeconds, minDeleteAfter), maxDeleteAfter)
	body := map[string]any{"name": name, "deleteAfterSeconds": ttl, "metadata": labels}
	if spec.Template != "" {
		body["templateId"] = spec.Template
	}
	if len(spec.Env) > 0 {
		body["env"] = spec.Env
	}
	key, err := c.nonce(16)
	if err != nil {
		return sandboxremote.BoxInfo{}, err
	}
	var op operationJSON
	err = c.doJSON(ctx, request{method: http.MethodPost, path: "/v1/machines", header: http.Header{"Idempotency-Key": {"observer-create-" + key}}}, body, &op)
	var ae *apiError
	switch {
	case errors.As(err, &ae) && ae.status == http.StatusConflict && ae.code != "idempotency_conflict":
		got, gerr := c.Get(ctx, name)
		if gerr != nil {
			return sandboxremote.BoxInfo{}, fmt.Errorf("instabox: create: the name exists and could not be read: %w", gerr)
		}
		if got.Labels[sandboxremote.LabelKey] != spec.RunID {
			return sandboxremote.BoxInfo{}, fmt.Errorf("instabox: create: a machine named %s exists for another run", name)
		}
		return got, nil
	case errors.As(err, &ae) && templateCodes[ae.code]:
		return sandboxremote.BoxInfo{}, fmt.Errorf("instabox: create: %w: %w", sandboxremote.ErrTemplateUnavailable, err)
	case err != nil && ae == nil && !errors.Is(err, sandboxremote.ErrRateLimited) && ctx.Err() == nil,
		// A 5xx still there after the retries may come after the machine was
		// made: lost, resolved by the run label.
		err != nil && ae != nil && ae.status >= 500 && !ae.retryable && ctx.Err() == nil:
		return sandboxremote.BoxInfo{}, fmt.Errorf("instabox: create: %w (%s)", sandboxremote.ErrCreateUnknown, c.redact(err.Error()))
	case err != nil:
		return sandboxremote.BoxInfo{}, fmt.Errorf("instabox: create: %w", err)
	}
	if op.MachineID == "" {
		return sandboxremote.BoxInfo{}, fmt.Errorf("instabox: create: %w (the answer named no machine)", sandboxremote.ErrCreateUnknown)
	}
	end, err := c.waitOperation(ctx, op)
	if err != nil {
		return sandboxremote.BoxInfo{}, fmt.Errorf("instabox: create: %w (%s)", sandboxremote.ErrCreateUnknown, c.redact(err.Error()))
	}
	if end.State == "failed" {
		e := &apiError{status: http.StatusOK, msg: "the create operation failed"}
		if end.Error != nil {
			e.code, e.msg, e.retryable = c.redact(end.Error.Code), c.redact(end.Error.Message), end.Error.Retryable
		}
		if templateCodes[e.code] {
			return sandboxremote.BoxInfo{}, fmt.Errorf("instabox: create: %w: %w", sandboxremote.ErrTemplateUnavailable, e)
		}
		// A create that fails before it gets a host is deleted with the
		// failure (createMachine); any other failure leaves a machine the
		// label finds, so the lost-create path cleans it up either way.
		return sandboxremote.BoxInfo{}, fmt.Errorf("instabox: create: %w", e)
	}
	if end.Machine != nil && end.Machine.ID != "" {
		return c.info(*end.Machine), nil
	}
	return c.Get(ctx, op.MachineID)
}

// opPollWait is the long-poll each operation read asks for (capped at 30 s
// by the vendor).
const opPollWait = "25s"

// waitOperation long-polls an operation until it is succeeded or failed,
// bounded by OperationWait.
func (c *Client) waitOperation(ctx context.Context, op operationJSON) (operationJSON, error) {
	if op.State == "succeeded" || op.State == "failed" {
		return op, nil
	}
	if op.ID == "" {
		return op, errors.New("the answer named no operation")
	}
	wctx, cancel := context.WithTimeout(ctx, c.o.OperationWait)
	defer cancel()
	for {
		var cur operationJSON
		err := c.doJSON(wctx, request{method: http.MethodGet, path: "/v1/operations/" + url.PathEscape(op.ID), query: url.Values{"wait": {opPollWait}}}, nil, &cur)
		if err != nil {
			return op, err
		}
		if cur.State == "succeeded" || cur.State == "failed" {
			return cur, nil
		}
		if err := wctx.Err(); err != nil {
			return op, err
		}
	}
}

// Get reads a machine by id or name (a read never wakes it).
func (c *Client) Get(ctx context.Context, id string) (sandboxremote.BoxInfo, error) {
	var m machineJSON
	if err := c.doJSON(ctx, request{method: http.MethodGet, path: "/v1/machines/" + url.PathEscape(id)}, nil, &m); err != nil {
		return sandboxremote.BoxInfo{}, err
	}
	if m.ID == "" {
		m.ID = id
	}
	return c.info(m), nil
}

// ListByLabel lists the machines whose metadata carries key=value (the
// vendor's metadata filter, re-checked here), following the cursor.
func (c *Client) ListByLabel(ctx context.Context, key, value string) ([]sandboxremote.BoxInfo, error) {
	var boxes []sandboxremote.BoxInfo
	cursor := ""
	for page := 0; page < 100; page++ {
		q := url.Values{"metadata": {key + ":" + value}, "limit": {"100"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var out struct {
			Machines   []machineJSON `json:"machines"`
			NextCursor *string       `json:"nextCursor"`
		}
		if err := c.doJSON(ctx, request{method: http.MethodGet, path: "/v1/machines", query: q}, nil, &out); err != nil {
			return nil, err
		}
		for _, m := range out.Machines {
			if m.Metadata[key] != value {
				continue
			}
			boxes = append(boxes, c.info(m))
		}
		if out.NextCursor == nil || *out.NextCursor == "" {
			return boxes, nil
		}
		cursor = *out.NextCursor
	}
	return boxes, errors.New("instabox: list: too many pages")
}

// Delete deletes a machine, its system files and its storage (snapshots are
// kept; the driver takes none), confirming the id in X-Confirm-Delete, and
// waits for the delete operation to end.
func (c *Client) Delete(ctx context.Context, id string) error {
	key, err := c.nonce(16)
	if err != nil {
		return err
	}
	var op operationJSON
	err = c.doJSON(ctx, request{method: http.MethodDelete, path: "/v1/machines/" + url.PathEscape(id), header: http.Header{
		"Idempotency-Key": {"observer-delete-" + key}, "X-Confirm-Delete": {id},
	}}, nil, &op)
	if err != nil {
		return err
	}
	end, err := c.waitOperation(ctx, op)
	if err != nil {
		return fmt.Errorf("instabox: delete %s: %w", id, err)
	}
	if end.State == "failed" {
		msg := "the delete operation failed"
		if end.Error != nil {
			msg = c.redact(end.Error.Code + ": " + end.Error.Message)
		}
		return fmt.Errorf("instabox: delete %s: %s", id, msg)
	}
	return nil
}

// WriteFiles uploads each file with PUT .../files (the raw bytes streamed,
// written to a temporary file the vendor renames over the path only once
// every byte arrived), creating missing parents and setting the mode.
func (c *Client) WriteFiles(ctx context.Context, id string, files []sandboxremote.UploadFile) error {
	for _, f := range files {
		if err := c.writeFile(ctx, id, f); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) writeFile(ctx context.Context, id string, f sandboxremote.UploadFile) error {
	if !path.IsAbs(f.Path) || path.Clean(f.Path) != f.Path {
		return fmt.Errorf("instabox: upload path %q is not a clean absolute path", f.Path)
	}
	mode := f.Mode & 0o7777
	if mode == 0 {
		mode = 0o644
	}
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	length := int64(-1)
	var stream io.Reader = rc
	if f.Size > 0 {
		// Exactly the declared size: a file that grew while uploading is
		// refused rather than sent short or long.
		length, stream = f.Size, &exactReader{r: rc, n: f.Size, path: f.Path}
	}
	q := url.Values{"path": {f.Path}, "mode": {fmt.Sprintf("%04o", mode)}, "parents": {"true"}}
	resp, err := c.do(ctx, request{method: http.MethodPut, path: "/v1/machines/" + url.PathEscape(id) + "/files", query: q, stream: stream, length: length, ctype: "application/octet-stream"})
	if err != nil {
		return fmt.Errorf("instabox: upload %s: %w", f.Path, err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return resp.Body.Close()
}

// exactReader yields exactly n bytes of r and fails when r has more.
type exactReader struct {
	r    io.Reader
	n    int64
	path string
}

func (e *exactReader) Read(p []byte) (int, error) {
	if e.n <= 0 {
		var one [1]byte
		if k, _ := e.r.Read(one[:]); k > 0 {
			return 0, fmt.Errorf("instabox: %s grew while uploading", e.path)
		}
		return 0, io.EOF
	}
	if int64(len(p)) > e.n {
		p = p[:e.n]
	}
	k, err := e.r.Read(p)
	e.n -= int64(k)
	if err == io.EOF && e.n > 0 {
		return k, fmt.Errorf("instabox: %s shrank while uploading", e.path)
	}
	return k, err
}

// maxRead caps one file read when the caller names no cap.
const maxRead = 512 << 20

// ReadFile reads one file's raw bytes (GET .../files/content), refusing one
// over max bytes.
func (c *Client) ReadFile(ctx context.Context, id, p string, max int64) ([]byte, error) {
	if max <= 0 {
		max = maxRead
	}
	resp, err := c.do(ctx, request{method: http.MethodGet, path: "/v1/machines/" + url.PathEscape(id) + "/files/content", query: url.Values{"path": {p}}})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.ContentLength > max {
		return nil, fmt.Errorf("instabox: %s is over %d bytes", p, max)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, errors.New(c.redact(err.Error()))
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("instabox: %s is over %d bytes", p, max)
	}
	return data, nil
}

// Reattach: the terminal's sessions persist and replay their recent output
// to the next viewer, but how much is replayed is not documented, and a
// replay mid-line would corrupt the relay's framing, so the client offers no
// reattach (a cut transport ends the run; the agent's native resume applies).
func (c *Client) Reattach(context.Context, string, string) (sandboxremote.Process, error) {
	return nil, fmt.Errorf("instabox: reattach: %w", sandboxremote.ErrNotSupported)
}
