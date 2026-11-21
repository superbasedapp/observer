package cloudagentsnet

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudagents"
	"github.com/marmutapp/superbased-observer/internal/shimguard"
)

// maxKey bounds an API key the egress presents.
const maxKey = 4096

// maxSSELine caps one event-stream line.
const maxSSELine = 1 << 20

// MaxOutput caps one process's captured stdout, or one response body.
const MaxOutput = 4 << 20

// waitDelay bounds how long Run waits for output pipes after the process
// was killed.
const waitDelay = time.Second

// maxStderr caps captured stderr (read only for classification).
const maxStderr = 64 << 10

// DefaultTimeout bounds one vendor CLI run.
const DefaultTimeout = 45 * time.Second

// DefaultAPITimeout bounds one HTTPS call of an API connector (and so the
// window of one event-stream read, which is clamped below it). The live
// check of 2026-11-01 measured Cursor's GET /v1/agents/{id}/usage at 4 s to
// 37 s per call, too close to the CLI cap.
const DefaultAPITimeout = 90 * time.Second

// envAllow are the variables each vendor CLI inherits: its own login lives
// in its config directory or these variables. Nothing else from the
// daemon's environment reaches the child.
var envAllow = map[string][]string{
	"codex": {
		"PATH", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
		"XDG_STATE_HOME", "XDG_CACHE_HOME", "CODEX_HOME", "SYSTEMROOT", "TMPDIR", "TEMP", "TMP",
		"HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR",
	},
	"gh": {
		"PATH", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
		"XDG_STATE_HOME", "XDG_CACHE_HOME", "GH_CONFIG_DIR", "GH_TOKEN", "GITHUB_TOKEN", "SYSTEMROOT",
		"TMPDIR", "TEMP", "TMP", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy",
		"SSL_CERT_FILE", "SSL_CERT_DIR",
	},
}

// fixedEnv keeps each CLI non-interactive and plain.
var fixedEnv = map[string][]string{
	"codex": {"NO_COLOR=1", "LC_ALL=C", "TERM=dumb"},
	"gh":    {"GH_PROMPT_DISABLED=1", "GH_NO_UPDATE_NOTIFIER=1", "GH_SPINNER_DISABLED=1", "NO_COLOR=1", "LC_ALL=C", "GH_PAGER=", "PAGER="},
}

// Options configure a Client.
type Options struct {
	// Getenv reads the environment (tests). Defaults to os.Getenv.
	Getenv func(string) string
	// ExcludeDirs are PATH directories never used to resolve a CLI
	// (Observer's own shim directory).
	ExcludeDirs []string
	// Resolve overrides command resolution (tests).
	Resolve func(cmd string) (string, error)
	// Timeout overrides DefaultTimeout. When APITimeout is unset it also
	// overrides DefaultAPITimeout (one cap for every call, as tests use).
	Timeout time.Duration
	// APITimeout overrides DefaultAPITimeout for HTTPS calls.
	APITimeout time.Duration
	// HTTP overrides the HTTP client (tests); its CheckRedirect is replaced
	// so redirects are never followed.
	HTTP *http.Client
	// APIHosts overrides the exact-host table (tests). nil uses the
	// connector table's APIHosts.
	APIHosts []string
	// Version is sent in the HTTPS User-Agent.
	Version string
	// Logger receives one line per refused or failed call, never output.
	Logger *slog.Logger
}

// Client performs every cloud-agent connector network and process call.
type Client struct {
	getenv  func(string) string
	exclude map[string]bool
	resolve func(string) (string, error)
	timeout time.Duration
	// apiTimeout bounds one HTTPS call (DefaultAPITimeout).
	apiTimeout time.Duration
	http       *http.Client
	hosts      map[string]bool
	version    string
	log        *slog.Logger
}

// New returns a Client.
func New(o Options) *Client {
	c := &Client{
		getenv: o.Getenv, exclude: map[string]bool{}, resolve: o.Resolve,
		timeout: o.Timeout, version: o.Version, log: o.Logger, hosts: map[string]bool{},
	}
	if c.getenv == nil {
		c.getenv = os.Getenv
	}
	for _, d := range o.ExcludeDirs {
		if d != "" {
			c.exclude[filepath.Clean(d)] = true
		}
	}
	if c.resolve == nil {
		c.resolve = c.lookPath
	}
	c.apiTimeout = o.APITimeout
	if c.apiTimeout <= 0 {
		c.apiTimeout = DefaultAPITimeout
		if c.timeout > 0 {
			c.apiTimeout = c.timeout
		}
	}
	if c.timeout <= 0 {
		c.timeout = DefaultTimeout
	}
	hc := o.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: c.apiTimeout}
	} else {
		cp := *hc
		hc = &cp
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c.http = hc
	hosts := o.APIHosts
	if hosts == nil {
		for _, conn := range cloudagents.Connectors {
			hosts = append(hosts, conn.APIHosts...)
		}
	}
	for _, h := range hosts {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			c.hosts[h] = true
		}
	}
	if c.log == nil {
		c.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return c
}

func fail(class cloudagents.ErrorClass, msg string) error { return cloudagents.NewError(class, msg) }

// Run executes one vendor CLI request and returns its stdout.
func (c *Client) Run(ctx context.Context, req cloudagents.Request) ([]byte, error) {
	conn, ok := cloudagents.ConnectorByID(req.Connector)
	if !ok || conn.Kind != cloudagents.SourceCLI {
		return nil, fail(cloudagents.ErrInvalid, "not a CLI connector")
	}
	if len(req.Argv) == 0 || req.Argv[0] != conn.Command {
		return nil, fail(cloudagents.ErrInvalid, "argv does not start with the connector's command")
	}
	for _, a := range req.Argv[1:] {
		if strings.ContainsAny(a, "\x00\r\n") {
			return nil, fail(cloudagents.ErrInvalid, "argv carries a control character")
		}
	}
	bin, err := c.resolve(conn.Command)
	if err != nil {
		return nil, fail(cloudagents.ErrNotInstalled, conn.Command+" is not installed")
	}
	cctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, req.Argv[1:]...) //nolint:gosec // G204: argv from the cloudagents connector table, ids and cursors validated there
	cmd.Env = append(c.env(envAllow[conn.Command]), fixedEnv[conn.Command]...)
	cmd.Stdin = bytes.NewReader(nil)
	cmd.Dir = os.TempDir() // never a user repository: the CLIs here are account-scoped
	out := &capBuffer{limit: MaxOutput}
	errOut := &capBuffer{limit: maxStderr}
	cmd.Stdout, cmd.Stderr = out, errOut
	// A grandchild that inherited the pipes must not hold Run open past the
	// timeout.
	cmd.WaitDelay = waitDelay
	err = cmd.Run()
	switch {
	case cctx.Err() != nil && ctx.Err() == nil:
		c.log.Debug("cloudagents: cli timed out", "connector", conn.ID, "op", string(req.Op))
		return nil, fail(cloudagents.ErrTimeout, conn.Command+" timed out")
	case ctx.Err() != nil:
		return nil, ctx.Err()
	case out.over:
		return nil, fail(cloudagents.ErrOverCap, conn.Command+" output too large")
	case err == nil:
		return out.Bytes(), nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		class := cloudagents.ClassifyCLIFailure(conn.Command, ee.ExitCode(), errOut.String())
		c.log.Debug("cloudagents: cli failed", "connector", conn.ID, "op", string(req.Op), "class", string(class))
		return nil, fail(class, conn.Command+" failed")
	}
	return nil, fail(cloudagents.ErrNotInstalled, conn.Command+" did not start")
}

// env returns the allow-listed variables that are set.
func (c *Client) env(allow []string) []string {
	var out []string
	for _, k := range allow {
		if v := c.getenv(k); v != "" {
			out = append(out, k+"="+v)
		}
	}
	return out
}

// lookPath resolves a command on PATH, skipping excluded directories,
// relative PATH entries and any file that is an Observer shim.
func (c *Client) lookPath(name string) (string, error) {
	for _, dir := range filepath.SplitList(c.getenv("PATH")) {
		if dir == "" || !filepath.IsAbs(dir) || c.exclude[filepath.Clean(dir)] {
			continue
		}
		p, err := exec.LookPath(filepath.Join(dir, name))
		if err != nil || isShimFile(p) {
			continue
		}
		return p, nil
	}
	return "", errors.New("cloudagentsnet: " + name + " is not installed")
}

// isShimFile reports whether p carries the shim marker in its head bytes.
func isShimFile(p string) bool {
	f, err := os.Open(p) /* #nosec G304 -- a binary exec.LookPath itself located on PATH */ //nolint:gosec // G304: a binary exec.LookPath located on PATH
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	return shimguard.IsShim(head[:n])
}

// capBuffer keeps at most limit bytes and records an overflow.
type capBuffer struct {
	b     bytes.Buffer
	limit int
	over  bool
}

// Write implements io.Writer; bytes past the limit are dropped.
func (c *capBuffer) Write(p []byte) (int, error) {
	room := c.limit - c.b.Len()
	switch {
	case room <= 0:
		c.over = true
	case len(p) > room:
		c.b.Write(p[:room])
		c.over = true
	default:
		c.b.Write(p)
	}
	return len(p), nil
}

// Bytes returns the captured bytes.
func (c *capBuffer) Bytes() []byte { return c.b.Bytes() }

// String returns the captured bytes as text.
func (c *capBuffer) String() string { return c.b.String() }

// --- HTTPS (lane CA-B2's API connectors) -------------------------------------

// CheckURL enforces the URL policy: HTTPS, port 443 or none, no user info,
// no fragment, and an exact host from the table.
func (c *Client) CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fail(cloudagents.ErrHostNotAllowed, "unparseable URL")
	}
	if u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return fail(cloudagents.ErrHostNotAllowed, "only plain https URLs are allowed")
	}
	if p := u.Port(); p != "" && p != "443" {
		return fail(cloudagents.ErrHostNotAllowed, "only port 443 is allowed")
	}
	if !c.hosts[strings.ToLower(u.Hostname())] {
		return fail(cloudagents.ErrHostNotAllowed, "host is not in the connector table")
	}
	return nil
}

// statusRule classifies one non-2xx response; walked top-down.
type statusRule struct {
	match func(int) bool
	class cloudagents.ErrorClass
}

var statusRules = []statusRule{
	{func(s int) bool { return s >= 300 && s < 400 }, cloudagents.ErrHostNotAllowed}, // a redirect is never followed
	{func(s int) bool { return s == http.StatusUnauthorized }, cloudagents.ErrNotSignedIn},
	{func(s int) bool { return s == http.StatusTooManyRequests }, cloudagents.ErrRateLimited},
	{func(s int) bool { return s == http.StatusForbidden || s == http.StatusNotFound }, cloudagents.ErrPermissionDenied},
	// A 5xx is the vendor's own failure, not the network: its own class, so
	// the CLI never says "unreachable" for a vendor fault (live 2026-11-01).
	{func(s int) bool { return s >= 500 && s < 600 }, cloudagents.ErrServerError},
}

// ClassifyStatus maps a non-2xx HTTP status to an error class.
func ClassifyStatus(status int) cloudagents.ErrorClass {
	for _, r := range statusRules {
		if r.match(status) {
			return r.class
		}
	}
	return cloudagents.ErrFailed
}

// absentBody is what a read of a record the vendor says does not exist
// returns (a status the connector row declares in Absent).
var absentBody = []byte("null")

// readJSON sends a prepared request and returns its capped 2xx body. A
// status listed in absent (the connector row's Absent table for this
// operation) is a missing record, not a failure: it returns the JSON body
// null and no error, and the vendor's body is not kept.
func (c *Client) readJSON(cctx context.Context, req *http.Request, op cloudagents.Op, absent []int) ([]byte, error) {
	req.Header.Set("User-Agent", "superbased-observer-cloudagents/"+strings.TrimSpace(c.version))
	res, err := c.http.Do(req)
	if err != nil {
		if cctx.Err() != nil {
			return nil, fail(cloudagents.ErrTimeout, "request timed out")
		}
		return nil, fail(cloudagents.ErrUnreachable, "network error")
	}
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(res.Body, MaxOutput+1))
	if err != nil {
		return nil, fail(cloudagents.ErrUnreachable, "read body")
	}
	if len(b) > MaxOutput {
		return nil, fail(cloudagents.ErrOverCap, "body too large")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		for _, st := range absent {
			if res.StatusCode == st {
				return append([]byte(nil), absentBody...), nil
			}
		}
		class := classifyResponse(op, res.StatusCode, b)
		c.log.Debug("cloudagents: https call failed", "class", string(class), "status", res.StatusCode)
		return nil, fail(class, "HTTP "+http.StatusText(res.StatusCode))
	}
	return b, nil
}

// streamStatusRule classifies a refused event-stream request (Cursor run
// streams, reference chapter 02 CU01); walked before statusRules. The body
// is read for classification only, never kept.
type streamStatusRule struct {
	status   int
	contains string
	class    cloudagents.ErrorClass
}

var streamStatusRules = []streamStatusRule{
	{http.StatusGone, "", cloudagents.ErrStreamExpired},
	{http.StatusBadRequest, "invalid_last_event_id", cloudagents.ErrStreamResumeRefused},
}

// classifyResponse maps a non-2xx response of op to an error class.
func classifyResponse(op cloudagents.Op, status int, body []byte) cloudagents.ErrorClass {
	if op == cloudagents.OpStream {
		low := strings.ToLower(string(body))
		for _, r := range streamStatusRules {
			if r.status == status && strings.Contains(low, r.contains) {
				return r.class
			}
		}
	}
	return ClassifyStatus(status)
}

// --- API connectors (lane CA-B2) ---------------------------------------------

// apiRequest validates an API connector request and builds the HTTP
// request with the key. The URL must be on the row's OWN host (not merely
// any host in the table), the scheme must be the row's, and the key must be
// a plain token. Nothing of the key reaches an error or a log.
func (c *Client) apiRequest(ctx context.Context, req cloudagents.Request, key string) (*http.Request, error) {
	conn, ok := cloudagents.ConnectorByID(req.Connector)
	if !ok || conn.Kind != cloudagents.SourceAPI {
		return nil, fail(cloudagents.ErrInvalid, "not an API connector")
	}
	if err := c.CheckURL(req.URL); err != nil {
		return nil, err
	}
	u, _ := url.Parse(req.URL)
	if !contains(conn.APIHosts, strings.ToLower(u.Hostname())) {
		return nil, fail(cloudagents.ErrHostNotAllowed, "host is not this connector's")
	}
	if req.Auth != conn.Auth {
		return nil, fail(cloudagents.ErrInvalid, "auth scheme is not this connector's")
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, fail(cloudagents.ErrNotSignedIn, "no key stored for this account")
	}
	if len(key) > maxKey || strings.ContainsAny(key, "\r\n\x00 \t") {
		return nil, fail(cloudagents.ErrInvalid, "the stored key is not a plain token")
	}
	if strings.ContainsAny(req.LastEventID, "\r\n\x00") || len(req.LastEventID) > cloudagents.MaxSSEEventID {
		return nil, fail(cloudagents.ErrInvalid, "bad Last-Event-ID")
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodGet, req.URL, nil)
	if err != nil {
		return nil, fail(cloudagents.ErrInvalid, "bad request")
	}
	switch conn.Auth {
	case cloudagents.AuthBasicUser:
		hr.SetBasicAuth(key, "")
	case cloudagents.AuthBearer:
		hr.Header.Set("Authorization", "Bearer "+key)
	default:
		return nil, fail(cloudagents.ErrInvalid, "unknown auth scheme")
	}
	accept := req.Accept
	if accept == "" {
		accept = cloudagents.AcceptJSON
	}
	hr.Header.Set("Accept", accept)
	if req.LastEventID != "" {
		hr.Header.Set("Last-Event-ID", req.LastEventID)
	}
	return hr, nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

// Call performs one API connector JSON request with key and returns the 2xx
// body (capped at MaxOutput, DefaultAPITimeout).
func (c *Client) Call(ctx context.Context, req cloudagents.Request, key string) ([]byte, error) {
	if req.Op == cloudagents.OpStream {
		return nil, fail(cloudagents.ErrInvalid, "a stream is read with Stream")
	}
	cctx, cancel := context.WithTimeout(ctx, c.apiTimeout)
	defer cancel()
	hr, err := c.apiRequest(cctx, req, key)
	if err != nil {
		return nil, err
	}
	conn, _ := cloudagents.ConnectorByID(req.Connector)
	return c.readJSON(cctx, hr, req.Op, absentFor(conn, req))
}

// absentFor is the request's Absent list, kept only where the connector row
// declares the same statuses for the operation: a request can never widen
// what its own row treats as a missing record.
func absentFor(conn cloudagents.Connector, req cloudagents.Request) []int {
	declared := conn.AbsentFor(req.Op)
	var out []int
	for _, st := range req.Absent {
		for _, d := range declared {
			if st == d {
				out = append(out, st)
				break
			}
		}
	}
	return out
}

// Stream reads one event stream for at most window (clamped below the
// API call timeout), feeding every dispatched event to onEvent until it
// returns false. It returns how the read ended; the bytes read are capped
// at MaxOutput (a capped read ends like a window, resumable from the last
// event id). A refused stream is an error of class stream_expired or
// stream_resume_refused.
func (c *Client) Stream(ctx context.Context, req cloudagents.Request, key string, window time.Duration, onEvent func(cloudagents.SSEEvent) bool) (cloudagents.StreamEnd, error) {
	if req.Op != cloudagents.OpStream {
		return cloudagents.StreamEnd{}, fail(cloudagents.ErrInvalid, "not a stream request")
	}
	if window <= 0 || window >= c.apiTimeout {
		window = c.apiTimeout - time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	hr, err := c.apiRequest(cctx, req, key)
	if err != nil {
		return cloudagents.StreamEnd{}, err
	}
	hr.Header.Set("Cache-Control", "no-cache")
	hr.Header.Set("User-Agent", "superbased-observer-cloudagents/"+strings.TrimSpace(c.version))
	res, err := c.http.Do(hr)
	if err != nil {
		if cctx.Err() != nil && ctx.Err() == nil {
			return cloudagents.StreamEnd{Reason: cloudagents.StreamEndWindow}, nil
		}
		if ctx.Err() != nil {
			return cloudagents.StreamEnd{}, ctx.Err()
		}
		return cloudagents.StreamEnd{}, fail(cloudagents.ErrUnreachable, "network error")
	}
	defer func() { _ = res.Body.Close() }()
	end := cloudagents.StreamEnd{}
	if v := res.Header.Get("X-Cursor-Stream-Retention-Seconds"); v != "" {
		end.RetentionSeconds = parseSeconds(v)
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
		class := classifyResponse(req.Op, res.StatusCode, b)
		c.log.Debug("cloudagents: stream refused", "class", string(class), "status", res.StatusCode)
		return end, fail(class, "HTTP "+http.StatusText(res.StatusCode))
	}
	ct := strings.ToLower(strings.TrimSpace(strings.Split(res.Header.Get("Content-Type"), ";")[0]))
	if ct != cloudagents.AcceptEventStream {
		return end, fail(cloudagents.ErrWrongShape, "not an event stream")
	}
	var dec cloudagents.SSEDecoder
	br := bufio.NewReaderSize(io.LimitReader(res.Body, MaxOutput), 64<<10)
	read := 0
	for {
		line, err := readLine(br)
		read += len(line) + 1
		if err == nil || (errors.Is(err, io.EOF) && line != "") {
			if ev, ok := dec.Line(line); ok && !onEvent(ev) {
				end.Reason = cloudagents.StreamEndDone
				return end, nil
			}
		}
		switch {
		case err == nil:
			continue
		case cctx.Err() != nil && ctx.Err() == nil:
			// The window ended (a body cut by the deadline may read as EOF).
			end.Reason = cloudagents.StreamEndWindow
			return end, nil
		case errors.Is(err, errLineTooLong):
			return end, fail(cloudagents.ErrOverCap, "event-stream line too long")
		case errors.Is(err, io.EOF):
			if ev, ok := dec.Line(""); ok && !onEvent(ev) {
				end.Reason = cloudagents.StreamEndDone
				return end, nil
			}
			end.Reason = cloudagents.StreamEndEOF
			if read >= MaxOutput {
				end.Reason = cloudagents.StreamEndCapped
			}
			return end, nil
		case ctx.Err() != nil:
			return end, ctx.Err()
		default:
			return end, fail(cloudagents.ErrUnreachable, "stream read failed")
		}
	}
}

var errLineTooLong = errors.New("cloudagentsnet: line too long")

// readLine reads one line without its terminator, refusing one longer than
// maxSSELine.
func readLine(br *bufio.Reader) (string, error) {
	var buf []byte
	for {
		frag, err := br.ReadSlice('\n')
		buf = append(buf, frag...)
		if len(buf) > maxSSELine {
			return "", errLineTooLong
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return strings.TrimSuffix(string(buf), "\n"), err
	}
}

// parseSeconds reads a non-negative integer header value (0 when not one).
func parseSeconds(v string) int64 {
	var n int64
	for _, r := range strings.TrimSpace(v) {
		if r < '0' || r > '9' || n > 1<<40 {
			return 0
		}
		n = n*10 + int64(r-'0')
	}
	return n
}
