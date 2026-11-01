package seccifetch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// The client's bounds.
const (
	requestTimeout = 60 * time.Second
	// MaxDriverBytes caps a driver download.
	MaxDriverBytes = 512 << 20
	maxErrorBody   = 4 << 10
)

// Backoff is the wait between lookups: each step once, then the last
// repeated.
var Backoff = []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 30 * time.Second}

// The client's refusals.
var (
	// ErrBaseURL refuses an org URL that is not https (plain http only to a
	// loopback host).
	ErrBaseURL = errors.New("seccifetch: the org URL must be https (http only to a loopback host)")
	// ErrNotSupported: the org server answered 404 (no CI check there).
	ErrNotSupported = errors.New("seccifetch: the org server has no CI check (404)")
	// ErrRefused: the org server refused the credential or the request.
	ErrRefused = errors.New("seccifetch: the org server refused the request")
	// ErrDigest: a driver's bytes do not match the pinned digest.
	ErrDigest = errors.New("seccifetch: the driver's SHA-256 is not the pinned digest")
)

// Client talks to one org server with one CI credential.
type Client struct {
	base       *url.URL
	credential string
	// HTTP is the transport; New sets a client that follows no redirect.
	HTTP *http.Client
	// Sleep waits between lookups (context aware); tests replace it.
	Sleep func(ctx context.Context, d time.Duration) error
	// Now is the clock the wait is measured on.
	Now func() time.Time
}

// New checks the org URL and builds a client. The credential travels only
// as a bearer header.
func New(baseURL, credential string) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, ErrBaseURL
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !loopbackHost(u.Hostname()) {
			return nil, ErrBaseURL
		}
	default:
		return nil, ErrBaseURL
	}
	if strings.TrimSpace(credential) == "" {
		return nil, fmt.Errorf("%w: no CI credential", ErrRefused)
	}
	return &Client{
		base: u, credential: strings.TrimSpace(credential),
		HTTP: &http.Client{
			Timeout:       requestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		Sleep: sleepCtx,
		Now:   time.Now,
	}, nil
}

func loopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(h)
	return err == nil && a.IsLoopback()
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// statusError is a non-200 answer.
type statusError struct {
	code int
	body string
}

func (e statusError) Error() string {
	return fmt.Sprintf("seccifetch: org server answered %d %s", e.code, e.body)
}

func (e statusError) Unwrap() error {
	switch {
	case e.code == http.StatusNotFound:
		return ErrNotSupported
	case e.code >= 400 && e.code < 500:
		return ErrRefused
	}
	return nil
}

// transient reports whether a lookup failure may clear on a retry: a
// network error or a 5xx; a 4xx never does.
func transient(err error) bool {
	var se statusError
	if errors.As(err, &se) {
		return se.code >= 500
	}
	return err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
}

// errCodeRE keeps the org's error code only, never free text.
var errCodeRE = regexp.MustCompile(`"error"\s*:\s*"([a-z_]{1,48})"`)

// do runs one request and reads the body, capped at max.
func (c *Client) do(ctx context.Context, method, path string, body []byte, max int64) ([]byte, error) {
	return c.doWith(ctx, method, path, body, max, nil)
}

// doWith is do with extra request headers.
func (c *Client) doWith(ctx context.Context, method, path string, body []byte, max int64, hdr map[string]string) ([]byte, error) {
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + path
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.credential)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		code := ""
		if m := errCodeRE.FindSubmatch(b); m != nil {
			code = string(m[1])
		}
		return nil, statusError{code: resp.StatusCode, body: code}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("seccifetch: answer over %d bytes", max)
	}
	return b, nil
}

// Policy fetches the org's signed CI policy document, as sent.
func (c *Client) Policy(ctx context.Context) ([]byte, error) {
	return c.do(ctx, http.MethodGet, orgcontract.CIPolicyPath, nil, orgcontract.MaxCIDocumentBytes)
}

// PolicyWait reads the wait a policy document asks for (unverified: the
// fetch job only uses it as a timer; the verdict job checks the
// signature). -1 when the document does not say.
func PolicyWait(doc []byte) int {
	var d orgcontract.CISignedDocument
	var p orgcontract.CIPolicy
	if json.Unmarshal(doc, &d) != nil || json.Unmarshal(d.Body, &p) != nil || p.WaitSeconds < 0 {
		return -1
	}
	return p.WaitSeconds
}

// Lookup asks once for the commits' change records.
func (c *Client) Lookup(ctx context.Context, req orgcontract.CILookupRequest) ([]byte, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	return c.do(ctx, http.MethodPost, orgcontract.CILookupPath, body, orgcontract.MaxCIDocumentBytes)
}

// Settled reports whether a lookup answer needs no further wait: every
// commit asked about has a record and none is still waiting for the org's
// countersign. Read unverified, as a timer only.
func Settled(doc []byte, req orgcontract.CILookupRequest) bool {
	var d orgcontract.CISignedDocument
	var ans orgcontract.CILookupAnswer
	if json.Unmarshal(doc, &d) != nil || json.Unmarshal(d.Body, &ans) != nil {
		return false
	}
	got := map[string][]orgcontract.CILookupRecord{}
	for _, c := range ans.Commits {
		got[c.SHA] = c.Records
	}
	for _, c := range req.Commits {
		recs := got[c.SHA]
		if len(recs) == 0 {
			return false
		}
		for _, r := range recs {
			if r.State == orgcontract.ChangeIngestPending {
				return false
			}
		}
	}
	return true
}

// LookupResult is the bounded wait's outcome.
type LookupResult struct {
	// Doc is the last answer (nil when none came).
	Doc []byte
	// Settled: the answer needs no further wait.
	Settled bool
	// Attempts counts the lookups made.
	Attempts int
	// LastErr is the last failure, when no answer came.
	LastErr error
}

// LookupWait asks until the answer is settled or wait runs out, backing
// off between attempts (Backoff). A refusal (4xx) ends the wait at once;
// a network failure or a 5xx is retried. The last answer is returned
// either way: commits it does not cover read as unknown_provenance.
func (c *Client) LookupWait(ctx context.Context, req orgcontract.CILookupRequest, wait time.Duration) LookupResult {
	var res LookupResult
	deadline := c.Now().Add(wait)
	for step := 0; ; step++ {
		res.Attempts++
		doc, err := c.Lookup(ctx, req)
		if err == nil {
			res.Doc, res.LastErr = doc, nil
			if Settled(doc, req) {
				res.Settled = true
				return res
			}
		} else {
			res.LastErr = err
			if !transient(err) {
				return res
			}
		}
		d := Backoff[min(step, len(Backoff)-1)]
		left := deadline.Sub(c.Now())
		if left <= 0 {
			return res
		}
		if d > left {
			d = left
		}
		if c.Sleep(ctx, d) != nil {
			return res
		}
	}
}

// pinRE is a SHA-256 pin.
var pinRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// nameRE is a content kind or artifact name: no path separators.
var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// Driver downloads a mirrored artifact (kind, name, platform) into w and
// refuses it unless its SHA-256 is pin. The bytes stream into w as they
// come, so the caller writes to a temporary file and keeps it only when
// Driver returns nil.
func (c *Client) Driver(ctx context.Context, kind, name, goos, goarch, pin string, w io.Writer) (int64, error) {
	pin = strings.ToLower(pin)
	if !pinRE.MatchString(pin) || !nameRE.MatchString(kind) || !nameRE.MatchString(name) {
		return 0, fmt.Errorf("%w: kind, name and a 64-hex SHA-256 pin are required", ErrRefused)
	}
	q := url.Values{}
	if goos != "" {
		q.Set("os", goos)
	}
	if goarch != "" {
		q.Set("arch", goarch)
	}
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + orgcontract.CIContentPath + url.PathEscape(kind) + "/" + url.PathEscape(name)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.credential)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		code := ""
		if m := errCodeRE.FindSubmatch(b); m != nil {
			code = string(m[1])
		}
		return 0, statusError{code: resp.StatusCode, body: code}
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(h, w), io.LimitReader(resp.Body, MaxDriverBytes+1))
	if err != nil {
		return n, err
	}
	if n > MaxDriverBytes {
		return n, fmt.Errorf("seccifetch: driver over %d bytes", MaxDriverBytes)
	}
	if hex.EncodeToString(h.Sum(nil)) != pin {
		return n, ErrDigest
	}
	return n, nil
}
