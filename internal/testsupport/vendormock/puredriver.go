package vendormock

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	"github.com/marmutapp/superbased-observer/internal/vendorsurface"
	"github.com/marmutapp/superbased-observer/internal/vendorsurface/catalog"
)

// PureDriver adapts a pure vendorapi.Driver to the conformance suite's
// Driver seam WITHOUT the org runner (lane CA-A4, cloud agents arc). It is
// for the per-user cloud-session surfaces whose drivers are consumed by the
// node's API connectors (lane CA-B2) rather than by the org vendor-connection
// runner, so they have no entry in internal/vendorapi/drivers and the
// runner's conformance test never reaches them.
//
// The adapter is deliberately small and plays the role the egress seam plays
// in production: it sends the driver's Build request with the driver's exact
// auth contract (never another scheme), honours Retry-After on 429 through
// Conn.Sleep, classifies 401/403 as auth and a client timeout as timeout,
// passes each page through the driver's parser and vendorapi.Validate, and
// stops a cursor that repeats. Like ReferenceDriver it is NOT an independent
// oracle of any vendor; the driver under test is.
type PureDriver struct {
	Driver vendorapi.Driver
	// Params are the connection parameters Build reads (an agent id, an
	// organization id).
	Params vendorapi.Params
	// Window is the fetch window handed to Build (zero for a surface that
	// reads no window).
	Window vendorapi.Window
	// MaxRetries bounds 429 retries (default 3).
	MaxRetries int
}

// Fetch implements Driver.
func (d PureDriver) Fetch(ctx context.Context, c Conn) (Result, error) {
	var res Result
	if d.Driver.Build == nil || (d.Driver.Parse == nil) == (d.Driver.ParseResponse == nil) {
		return res, classed(ErrOther, errors.New("driver needs Build and exactly one of Parse or ParseResponse"))
	}
	base, err := url.Parse(c.BaseURL)
	if err != nil {
		return res, classed(ErrOther, err)
	}
	maxPages := c.MaxPages
	if maxPages <= 0 {
		maxPages = 100
	}
	cursor := ""
	seen := map[string]bool{}
	for {
		if res.Pages >= maxPages {
			res.Truncated = true
			return res, nil
		}
		req, err := d.Driver.Build(d.Params, d.Window, cursor)
		if err != nil {
			return res, classed(ErrOther, fmt.Errorf("build: %w", err))
		}
		resp, err := d.send(ctx, c, base, req)
		if err != nil {
			return res, err
		}
		res.Pages++
		resp.Cursor = cursor
		page, err := d.parse(resp)
		if err != nil {
			return res, err
		}
		if err := vendorapi.Validate(stampManifest(page)); err != nil {
			return res, classed(ErrSchemaDrift, err)
		}
		res.Records += records(page)
		if page.NextCursor == "" {
			return res, nil
		}
		if page.NextCursor == cursor || seen[page.NextCursor] {
			return res, classed(ErrSchemaDrift, fmt.Errorf("paging loop: cursor %q repeated", page.NextCursor))
		}
		seen[page.NextCursor] = true
		cursor = page.NextCursor
	}
}

func (d PureDriver) parse(r vendorapi.Response) (vendorapi.Page, error) {
	var (
		p   vendorapi.Page
		err error
	)
	if d.Driver.ParseResponse != nil {
		p, err = d.Driver.ParseResponse(r)
	} else {
		p, err = d.Driver.Parse(r.Body)
	}
	switch {
	case err == nil:
		return p, nil
	case errors.Is(err, vendorapi.ErrSchemaDrift):
		return p, classed(ErrSchemaDrift, err)
	default:
		return p, classed(ErrOther, err)
	}
}

// stampManifest gives a graph page the run identity the store would; an
// activity or content page is unchanged.
func stampManifest(p vendorapi.Page) vendorapi.Page {
	if p.Snapshot != nil {
		m := *p.Snapshot
		m.ManifestID, m.ObservedAt = "conformance", time.Unix(1, 0).UTC()
		p.Snapshot = &m
	}
	return p
}

// records counts a page's landings the way the runner does: the parsed
// vendor records when the driver reports them, else one per landing.
func records(p vendorapi.Page) int {
	if p.SourceRecords > 0 {
		return p.SourceRecords
	}
	return len(p.Resources) + len(p.Audit) + len(p.Usage) + len(p.Facts) + len(p.Snapshots) + len(p.Retractions) +
		len(p.Content)
}

// send issues one request with the driver's auth contract, retrying a 429
// after its Retry-After.
func (d PureDriver) send(ctx context.Context, c Conn, base *url.URL, req vendorapi.Request) (vendorapi.Response, error) {
	if req.Body != nil {
		return vendorapi.Response{}, classed(ErrOther, errors.New("PureDriver sends GET requests only"))
	}
	u := *base
	u.Path = strings.TrimRight(base.Path, "/") + req.Path
	u.RawQuery = url.Values(req.Query).Encode()
	retries := d.MaxRetries
	if retries <= 0 {
		retries = 3
	}
	for attempt := 0; ; attempt++ {
		hr, err := http.NewRequestWithContext(ctx, req.Method, u.String(), nil)
		if err != nil {
			return vendorapi.Response{}, classed(ErrOther, err)
		}
		for k, v := range d.Driver.Headers {
			hr.Header.Set(k, v)
		}
		if err := d.authorize(hr, c.Token); err != nil {
			return vendorapi.Response{}, classed(ErrOther, err)
		}
		resp, err := c.HTTP.Do(hr)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
				return vendorapi.Response{}, classed(ErrTimeout, err)
			}
			return vendorapi.Response{}, classed(ErrOther, err)
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		_ = resp.Body.Close()
		if err != nil {
			if isTimeout(err) {
				return vendorapi.Response{}, classed(ErrTimeout, err)
			}
			return vendorapi.Response{}, classed(ErrOther, err)
		}
		switch {
		case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
			return vendorapi.Response{}, classed(ErrAuth, fmt.Errorf("status %d", resp.StatusCode))
		case resp.StatusCode == http.StatusTooManyRequests:
			if attempt >= retries {
				return vendorapi.Response{}, classed(ErrRateLimited, fmt.Errorf("still limited after %d retries", attempt))
			}
			wait, ok := ParseRetryAfter(resp.Header.Get("Retry-After"), c.now())
			if !ok {
				wait = time.Second
			}
			c.sleep(wait)
			continue
		}
		hdr := map[string]string{}
		for _, name := range d.Driver.ResponseHeaders {
			if v := resp.Header.Get(name); v != "" {
				hdr[strings.ToLower(name)] = v
			}
		}
		return vendorapi.Response{
			Status: resp.StatusCode, Origin: base.Scheme + "://" + base.Host, Path: req.Path,
			Header: hdr, Body: raw, Params: d.Params,
		}, nil
	}
}

// authorize presents the credential in the driver's one documented scheme.
func (d PureDriver) authorize(r *http.Request, token string) error {
	a := d.Driver.Auth
	switch a.Scheme {
	case vendorapi.SchemeBearer:
		r.Header.Set(headerOr(a.Header, "Authorization"), "Bearer "+token)
	case vendorapi.SchemeBasicUser:
		r.SetBasicAuth(token, "")
	case vendorapi.SchemeRawHeader:
		if a.Header == "" {
			return errors.New("raw-header contract names no header")
		}
		r.Header.Set(a.Header, token)
	default:
		return fmt.Errorf("PureDriver does not present auth scheme %q", a.Scheme)
	}
	return nil
}

func headerOr(h, def string) string {
	if h == "" {
		return def
	}
	return h
}

// RunPure runs the shared conformance suite (every scenario declared for the
// driver's surface) against a pure driver through PureDriver, each scenario
// against a fresh mock seeded from the fixture corpus.
func RunPure(t *testing.T, d vendorapi.Driver, params vendorapi.Params, w vendorapi.Window) {
	t.Helper()
	root, err := DefaultCorpusRoot()
	if err != nil {
		t.Fatal(err)
	}
	c, err := LoadCorpus(root)
	if err != nil {
		t.Fatal(err)
	}
	Run(t, c, d.Surface, func() Driver { return PureDriver{Driver: d, Params: params, Window: w} })
}

// CheckDriverContract pins a pure driver that has no entry in the org driver
// table to the same catalog and corpus contract internal/vendorapi/drivers
// holds its entries to: the surface is a driverable catalog row, the auth
// kind is the row's, every supply class is one the row supplies, Build and
// exactly one parser are set, and KnownPaths equal the union of the success
// fixtures' field ledgers.
func CheckDriverContract(t *testing.T, d vendorapi.Driver) {
	t.Helper()
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	s, ok := cat.Surface(d.Surface)
	if !ok {
		t.Fatalf("%s is not a catalog row", d.Surface)
	}
	if !vendorsurface.Driverable(s.Build) {
		t.Errorf("%s: catalog row is %s, want a driverable state", d.Surface, s.Build)
	}
	if d.Auth.Kind != s.Auth.Kind {
		t.Errorf("%s: driver auth kind %s, catalog %s", d.Surface, d.Auth.Kind, s.Auth.Kind)
	}
	if d.Build == nil || (d.Parse == nil) == (d.ParseResponse == nil) {
		t.Errorf("%s: needs Build and exactly one of Parse or ParseResponse", d.Surface)
	}
	if len(d.Supplies) == 0 {
		t.Errorf("%s: declares no supply", d.Surface)
	}
	for _, cls := range d.Supplies {
		found := false
		for _, sp := range s.Supplies {
			found = found || sp.Class == cls
		}
		if !found {
			t.Errorf("%s produces %s, which the catalog row does not supply", d.Surface, cls)
		}
	}
	root, err := DefaultCorpusRoot()
	if err != nil {
		t.Fatal(err)
	}
	c, err := LoadCorpus(root)
	if err != nil {
		t.Fatal(err)
	}
	sf, ok := c.Surfaces[d.Surface]
	if !ok {
		t.Fatalf("%s has no fixtures", d.Surface)
	}
	want := map[string]bool{}
	for _, f := range sf.Fixtures {
		if f.Sidecar.HTTP.Status >= 200 && f.Sidecar.HTTP.Status < 300 {
			for k := range f.Sidecar.FieldLedger {
				want[k] = true
			}
		}
	}
	got := map[string]bool{}
	for _, k := range d.KnownPaths {
		got[k] = true
	}
	for k := range want {
		if !got[k] {
			t.Errorf("%s: ledger path %q missing from KnownPaths", d.Surface, k)
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("%s: KnownPaths has %q, which no ledger documents", d.Surface, k)
		}
	}
}
