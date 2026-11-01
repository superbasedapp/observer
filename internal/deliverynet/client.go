package deliverynet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/delivery"
	"github.com/marmutapp/superbased-observer/internal/shimguard"
)

// MaxBody caps one response body or one process's captured output.
const MaxBody = 2 << 20

// defaultTimeout bounds one HTTP call or one gh process.
const defaultTimeout = 20 * time.Second

// etagCacheMax bounds the conditional-request cache (entries).
const etagCacheMax = 1024

// The auth modes of a provider link (delivery.ProviderLink.AuthMode).
const (
	// AuthToken is a fine-grained read-only token held in the OS keychain.
	AuthToken = "token"
	// AuthGHCLI borrows the user's gh login; Observer stores nothing.
	AuthGHCLI = "gh_cli"
)

// GitHubDotCom is the public GitHub web host.
const GitHubDotCom = "github.com"

// githubAPIHost is the public GitHub API host.
const githubAPIHost = "api.github.com"

// Auth says how one GitHub request authenticates. Token is never logged and
// never appears in an error.
type Auth struct {
	Mode  string // AuthToken | AuthGHCLI
	Host  string // web host: "github.com" or a declared GHES host
	Token string // AuthToken only
}

// Options configure a Client. The zero value is usable for github.com.
type Options struct {
	// HTTP overrides the HTTP client (tests). Its CheckRedirect is replaced
	// so redirects are never followed.
	HTTP *http.Client
	// Version is sent in the User-Agent.
	Version string
	// GHESHosts are the operator-declared GitHub Enterprise Server web
	// hosts (their API lives at https://<host>/api/v3). Empty means
	// github.com only.
	GHESHosts []string
	// Getenv reads the environment (tests). Defaults to os.Getenv.
	Getenv func(string) string
	// ExcludeDirs are PATH directories never used to resolve gh or git
	// (Observer's own shim directory).
	ExcludeDirs []string
	// Resolve overrides command resolution (tests).
	Resolve func(cmd string) (string, error)
	// MirrorRoot overrides ~/.observer/delivery/mirrors (tests).
	MirrorRoot string
	// AllowFileRemotes admits file:// remotes for mirrors (tests only; a
	// real remote is https or ssh).
	AllowFileRemotes bool
	// Now overrides the clock (tests).
	Now func() time.Time
	// Logger receives one line per refused or failed call, never a secret.
	Logger *slog.Logger
}

// Client performs every delivery network operation.
type Client struct {
	http       *http.Client
	version    string
	ghes       map[string]bool
	getenv     func(string) string
	exclude    map[string]bool
	resolve    func(string) (string, error)
	mirrorRoot string
	allowFile  bool
	now        func() time.Time
	log        *slog.Logger

	mu      sync.Mutex
	etags   map[string]cachedBody
	blocked map[string]time.Time // api host -> rate-limit reset
}

type cachedBody struct {
	etag string
	body []byte
}

// New returns a Client.
func New(o Options) *Client {
	hc := o.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: defaultTimeout}
	} else {
		cp := *hc
		hc = &cp
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c := &Client{
		http: hc, version: o.Version, ghes: map[string]bool{}, getenv: o.Getenv,
		exclude: map[string]bool{}, resolve: o.Resolve, mirrorRoot: o.MirrorRoot,
		allowFile: o.AllowFileRemotes, now: o.Now, log: o.Logger,
		etags: map[string]cachedBody{}, blocked: map[string]time.Time{},
	}
	for _, h := range o.GHESHosts {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" && h != GitHubDotCom && h != githubAPIHost {
			c.ghes[h] = true
		}
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
	if c.now == nil {
		c.now = time.Now
	}
	if c.log == nil {
		c.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return c
}

// --- Typed outcomes ----------------------------------------------------------

// Kind is the closed outcome class of a failed call. The link-level values
// equal the delivery.ProviderLink.Status strings.
type Kind string

// The closed Kind vocabulary.
const (
	KindAuthFailed     Kind = "auth_failed"
	KindRateLimited    Kind = "rate_limited"
	KindUnreachable    Kind = "unreachable"
	KindRepoMoved      Kind = "repo_moved"
	KindWrongShape     Kind = "wrong_shape"
	KindNotFound       Kind = "not_found"
	KindUnprocessable  Kind = "unprocessable"
	KindHostNotAllowed Kind = "host_not_allowed"
	KindUnavailable    Kind = "unavailable"
	KindInvalid        Kind = "invalid"
	KindOverCap        Kind = "over_cap"
	// KindNeedsNonInteractive is a git mirror operation that stopped at a
	// credential prompt it is never allowed to show (a password, a key
	// passphrase, a host key confirmation). The UI reads it as "Needs
	// non-interactive credentials".
	KindNeedsNonInteractive Kind = "needs_noninteractive_credentials"
)

// Error is a typed delivery network failure. Its text never carries a
// token, a header value or a response body.
type Error struct {
	Kind       Kind
	HTTPStatus int
	// ResetAt is when a rate limit lifts (zero when unknown).
	ResetAt time.Time
	// Msg is a short safe description.
	Msg string
}

// Error implements error.
func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("deliverynet: ")
	b.WriteString(string(e.Kind))
	if e.HTTPStatus != 0 {
		b.WriteString(" (HTTP ")
		b.WriteString(strconv.Itoa(e.HTTPStatus))
		b.WriteString(")")
	}
	if e.Msg != "" {
		b.WriteString(": ")
		b.WriteString(e.Msg)
	}
	return b.String()
}

// KindOf returns the Kind of err, or "" when err is nil, or KindUnreachable
// for an untyped error.
func KindOf(err error) Kind {
	if err == nil {
		return ""
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return KindUnreachable
}

// ResetOf returns a rate-limit reset time carried by err (zero otherwise).
func ResetOf(err error) time.Time {
	var e *Error
	if errors.As(err, &e) {
		return e.ResetAt
	}
	return time.Time{}
}

func newErr(k Kind, status int, msg string) *Error {
	return &Error{Kind: k, HTTPStatus: status, Msg: msg}
}

// statusRule classifies one non-2xx HTTP response; the table is walked top
// down, first match wins (CLAUDE.md rule 5).
type statusRule struct {
	match func(status int, rateLimited bool) bool
	kind  Kind
}

var statusRules = []statusRule{
	// A redirect is never followed: a renamed repository answers 301.
	{func(s int, _ bool) bool { return s >= 300 && s < 400 }, KindRepoMoved},
	{func(s int, _ bool) bool { return s == http.StatusUnauthorized }, KindAuthFailed},
	{func(s int, rl bool) bool { return (s == http.StatusForbidden && rl) || s == http.StatusTooManyRequests }, KindRateLimited},
	{func(s int, _ bool) bool { return s == http.StatusForbidden }, KindAuthFailed},
	{func(s int, _ bool) bool { return s == http.StatusNotFound }, KindNotFound},
	{func(s int, _ bool) bool { return s == http.StatusUnprocessableEntity }, KindUnprocessable},
	{func(s int, _ bool) bool { return s >= 500 }, KindUnreachable},
}

// ClassifyStatus maps a non-2xx status (and whether the rate-limit headers
// said the budget is spent) to a Kind.
func ClassifyStatus(status int, rateLimited bool) Kind {
	for _, r := range statusRules {
		if r.match(status, rateLimited) {
			return r.kind
		}
	}
	return KindWrongShape
}

// --- URL policy --------------------------------------------------------------

// apiBase returns the API base URL for a web host, or KindHostNotAllowed.
func (c *Client) apiBase(host string) (string, string, error) {
	h := strings.ToLower(strings.TrimSpace(host))
	switch {
	case h == GitHubDotCom || h == githubAPIHost:
		return "https://" + githubAPIHost, githubAPIHost, nil
	case c.ghes[h]:
		return "https://" + h + "/api/v3", h, nil
	}
	return "", "", newErr(KindHostNotAllowed, 0, "host is not github.com or a declared GitHub Enterprise host")
}

// CheckURL enforces the request URL policy: HTTPS, no user info, port 443 or
// none, no fragment, and the host must be api.github.com or a declared GHES
// host.
func (c *Client) CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return newErr(KindHostNotAllowed, 0, "unparseable URL")
	}
	if u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return newErr(KindHostNotAllowed, 0, "only plain https URLs are allowed")
	}
	if p := u.Port(); p != "" && p != "443" {
		return newErr(KindHostNotAllowed, 0, "only port 443 is allowed")
	}
	h := strings.ToLower(u.Hostname())
	if h == githubAPIHost || c.ghes[h] {
		return nil
	}
	return newErr(KindHostNotAllowed, 0, "host is not on the allow-list")
}

// apiPath shapes, validated before a path is built. A slug or a sha that
// fails these never reaches a URL or an argv.
var reSHA = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

// ValidSlug reports whether slug is a plain "owner/repo"; the definition is
// delivery.ValidSlug (one owner, shared with delivery.LinkServes).
func ValidSlug(slug string) bool { return delivery.ValidSlug(slug) }

// ValidSHA reports whether sha is a lowercase hex commit id.
func ValidSHA(sha string) bool { return reSHA.MatchString(sha) }

// --- HTTP / gh transport -----------------------------------------------------

// get performs one GET of an API path (leading slash, query allowed) under
// auth and returns the body of a 2xx (or the cached body on a 304), plus the
// response headers in token mode.
func (c *Client) get(ctx context.Context, auth Auth, path string) ([]byte, http.Header, error) {
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
		return nil, nil, newErr(KindInvalid, 0, "bad API path")
	}
	switch auth.Mode {
	case AuthToken:
		return c.getHTTP(ctx, auth, path)
	case AuthGHCLI:
		b, err := c.getGH(ctx, auth, path)
		return b, nil, err
	}
	return nil, nil, newErr(KindInvalid, 0, "unknown auth mode")
}

func (c *Client) cacheKey(auth Auth, full string) string {
	sum := sha256.Sum256([]byte(auth.Token))
	return hex.EncodeToString(sum[:8]) + "|" + full
}

func (c *Client) getHTTP(ctx context.Context, auth Auth, path string) ([]byte, http.Header, error) {
	base, apiHost, err := c.apiBase(auth.Host)
	if err != nil {
		return nil, nil, err
	}
	full := base + path
	if err := c.CheckURL(full); err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(auth.Token) == "" {
		return nil, nil, newErr(KindAuthFailed, 0, "no token")
	}
	now := c.now()
	c.mu.Lock()
	until := c.blocked[apiHost]
	key := c.cacheKey(auth, full)
	cached, haveCache := c.etags[key]
	c.mu.Unlock()
	if now.Before(until) {
		return nil, nil, &Error{Kind: KindRateLimited, ResetAt: until, Msg: "waiting for the rate limit to reset"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return nil, nil, newErr(KindInvalid, 0, "bad request")
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "superbased-observer-delivery/"+strings.TrimSpace(c.version))
	if haveCache {
		req.Header.Set("If-None-Match", cached.etag)
	}
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	res, err := c.http.Do(req)
	if err != nil {
		// The transport error can echo the URL; never a header.
		return nil, nil, newErr(KindUnreachable, 0, errClass(err))
	}
	defer func() { _ = res.Body.Close() }()
	reset, spent := parseRateLimit(res.Header, now)
	if spent && !reset.IsZero() {
		c.mu.Lock()
		c.blocked[apiHost] = reset
		c.mu.Unlock()
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, MaxBody+1))
	if err != nil {
		return nil, nil, newErr(KindUnreachable, res.StatusCode, "read body")
	}
	if len(b) > MaxBody {
		return nil, nil, newErr(KindWrongShape, res.StatusCode, "body too large")
	}
	switch {
	case res.StatusCode == http.StatusNotModified && haveCache:
		return cached.body, res.Header, nil
	case res.StatusCode == http.StatusNotModified:
		return nil, res.Header, newErr(KindWrongShape, res.StatusCode, "not modified without a cached copy")
	case res.StatusCode >= 200 && res.StatusCode < 300:
		if et := res.Header.Get("ETag"); et != "" {
			c.mu.Lock()
			if len(c.etags) >= etagCacheMax {
				c.etags = map[string]cachedBody{}
			}
			c.etags[key] = cachedBody{etag: et, body: b}
			c.mu.Unlock()
		}
		return b, res.Header, nil
	}
	retry := parseRetryAfter(res.Header.Get("Retry-After"), now)
	kind := ClassifyStatus(res.StatusCode, spent || retry > 0)
	e := &Error{Kind: kind, HTTPStatus: res.StatusCode}
	if kind == KindRateLimited {
		e.ResetAt = reset
		if e.ResetAt.IsZero() && retry > 0 {
			e.ResetAt = now.Add(retry)
		}
		if !e.ResetAt.IsZero() {
			c.mu.Lock()
			c.blocked[apiHost] = e.ResetAt
			c.mu.Unlock()
		}
	}
	if kind == KindRepoMoved {
		e.Msg = "the repository moved; update the remote URL"
	}
	c.log.Debug("delivery: github call failed", "kind", string(kind), "status", res.StatusCode)
	return nil, res.Header, e
}

// parseRateLimit reads X-RateLimit-Remaining / X-RateLimit-Reset. spent is
// true when the remaining budget is zero.
func parseRateLimit(h http.Header, now time.Time) (time.Time, bool) {
	rem := strings.TrimSpace(h.Get("X-RateLimit-Remaining"))
	if rem != "0" {
		return time.Time{}, false
	}
	if n, err := strconv.ParseInt(strings.TrimSpace(h.Get("X-RateLimit-Reset")), 10, 64); err == nil && n > 0 {
		return time.Unix(n, 0), true
	}
	return now.Add(time.Hour), true
}

// parseRetryAfter reads a Retry-After header in seconds or as an HTTP date.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil && t.After(now) {
		return t.Sub(now)
	}
	return 0
}

// errClass reduces a transport error to a short class, never a URL or a
// header.
func errClass(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		if ue.Timeout() {
			return "timeout"
		}
		return "network error"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	return "network error"
}

// ghEnvAllow are the variables the gh process inherits (its own login lives
// in its config dir or these variables).
var ghEnvAllow = []string{
	"PATH", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
	"XDG_STATE_HOME", "XDG_CACHE_HOME", "GH_CONFIG_DIR", "GH_TOKEN", "GITHUB_TOKEN",
	"GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN", "SYSTEMROOT", "TMPDIR", "TEMP", "TMP",
	"HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR",
}

// ghFixedEnv keeps gh non-interactive and quiet.
var ghFixedEnv = []string{
	"GH_PROMPT_DISABLED=1", "GH_NO_UPDATE_NOTIFIER=1", "GH_SPINNER_DISABLED=1", "NO_COLOR=1", "LC_ALL=C",
}

var reGHStatus = regexp.MustCompile(`\(HTTP (\d{3})\)`)

// GHArgv is the fixed argv of one gh call for an API path (no leading
// slash in the gh form). Exported so tests and the security review can see
// the exact vector.
func GHArgv(host, path string) []string {
	argv := []string{"gh", "api", "-H", "Accept:application/vnd.github+json"}
	if h := strings.ToLower(strings.TrimSpace(host)); h != "" && h != GitHubDotCom {
		argv = append(argv, "--hostname", h)
	}
	return append(argv, strings.TrimPrefix(path, "/"))
}

func (c *Client) getGH(ctx context.Context, auth Auth, path string) ([]byte, error) {
	if _, _, err := c.apiBase(auth.Host); err != nil {
		return nil, err
	}
	argv := GHArgv(auth.Host, path)
	if strings.HasPrefix(argv[len(argv)-1], "-") {
		return nil, newErr(KindInvalid, 0, "bad API path")
	}
	bin, err := c.resolve("gh")
	if err != nil {
		return nil, newErr(KindUnavailable, 0, "gh is not installed")
	}
	cctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, argv[1:]...) //nolint:gosec // G204: fixed argv; the path is built from validated slug/sha/number values
	cmd.Env = append(c.env(ghEnvAllow), ghFixedEnv...)
	cmd.Stdin = bytes.NewReader(nil)
	var out, errOut capBuffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err = cmd.Run()
	if cctx.Err() != nil {
		return nil, newErr(KindUnreachable, 0, "gh timed out")
	}
	if out.over {
		return nil, newErr(KindWrongShape, 0, "body too large")
	}
	var ee *exec.ExitError
	switch {
	case err == nil:
		return out.Bytes(), nil
	case errors.As(err, &ee):
		return nil, classifyGH(ee.ExitCode(), errOut.String())
	}
	return nil, newErr(KindUnavailable, 0, "gh did not start")
}

// classifyGH maps a failed gh run to a typed error from its exit code and
// the "(HTTP nnn)" marker gh prints on stderr. The stderr text itself is
// never returned.
func classifyGH(exit int, stderr string) *Error {
	low := strings.ToLower(stderr)
	if strings.Contains(low, "rate limit") {
		return newErr(KindRateLimited, http.StatusForbidden, "gh reported a rate limit")
	}
	if m := reGHStatus.FindStringSubmatch(stderr); m != nil {
		st, _ := strconv.Atoi(m[1])
		return newErr(ClassifyStatus(st, false), st, "")
	}
	if exit == 4 || strings.Contains(low, "gh auth login") {
		return newErr(KindAuthFailed, 0, "gh is not signed in")
	}
	return newErr(KindUnreachable, 0, "gh failed")
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

// lookPath resolves a command on PATH, skipping excluded directories and any
// file that is an Observer command-wrapping shim.
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
	return "", fmt.Errorf("deliverynet: %s is not installed", name)
}

// isShimFile reports whether p carries the shim marker in its head bytes.
func isShimFile(p string) bool {
	f, err := os.Open(p) /* #nosec G304 -- a binary exec.LookPath itself located on PATH */ //nolint:gosec // G304: a binary exec.LookPath itself located on PATH
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	return shimguard.IsShim(head[:n])
}

// capBuffer keeps at most MaxBody bytes and records an overflow.
type capBuffer struct {
	b    bytes.Buffer
	over bool
}

// Write implements io.Writer; bytes past MaxBody are dropped.
func (c *capBuffer) Write(p []byte) (int, error) {
	room := MaxBody - c.b.Len()
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

// Bytes returns the captured output.
func (c *capBuffer) Bytes() []byte { return c.b.Bytes() }

// String returns the captured output as text.
func (c *capBuffer) String() string { return c.b.String() }
