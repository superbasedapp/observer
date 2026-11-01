package online

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/module"

	"github.com/marmutapp/superbased-observer/internal/secfeed"
)

// UserAgent is the only identifying header sent.
const UserAgent = "superbased-observer"

// OSVHost is the OSV API host.
const OSVHost = "api.osv.dev"

// FeedHost is the vendor's signed content feed host.
const FeedHost = "superbased.app"

// Caps.
const (
	maxOSVBytes      = 4 << 20
	maxRegistryBytes = 16 << 20
	maxFeedBytes     = 64 << 20
	maxBatch         = 64
	maxConcurrent    = 8
	// maxMalReads caps the MAL- records one lookup reads in full to learn
	// whether a report covers every version (an unpinned install).
	maxMalReads     = 16
	defaultCooldown = 60 * time.Second
	maxCooldown     = 15 * time.Minute
)

// The failure reasons an answer records.
const (
	ReasonTimeout     = "timeout"
	ReasonRateLimited = "rate_limited"
	ReasonDNS         = "dns"
	ReasonTLS         = "tls"
	ReasonNetwork     = "network"
	ReasonHTTPStatus  = "http_status"
	ReasonBadAnswer   = "bad_answer"
	ReasonTooLarge    = "too_large"
	ReasonNotPublic   = "not_public"
	ReasonNoRegistry  = "no_registry"
	ReasonOSV         = "osv_failed"
	ReasonCoolingDown = "cooling_down"
)

// Options configures a client.
type Options struct {
	// HTTP is the transport; nil builds one with system roots that honours
	// HTTPS_PROXY and NO_PROXY from the daemon's own environment.
	// CheckRedirect is always replaced: no redirect is followed.
	HTTP *http.Client
	// Endpoints redirects an allow-listed host to a test server (tests
	// only): the host must still be on the allow-list.
	Endpoints map[string]string
	// Now is the clock (back-off); nil is time.Now.
	Now func() time.Time
}

// Client is the public online client.
type Client struct {
	http      *http.Client
	endpoints map[string]string
	now       func() time.Time
	allowed   map[string]bool

	mu       sync.Mutex
	cooldown map[string]time.Time
}

// New returns a client.
func New(o Options) *Client {
	hc := o.HTTP
	if hc == nil {
		hc = &http.Client{Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 10 * time.Second, MaxIdleConnsPerHost: 4, IdleConnTimeout: 60 * time.Second,
			ForceAttemptHTTP2: true,
		}}
	} else {
		cp := *hc
		hc = &cp
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	now := o.Now
	if now == nil {
		now = time.Now
	}
	allowed := map[string]bool{OSVHost: true, FeedHost: true}
	for _, e := range secfeed.Ecosystems() {
		allowed[e.MetadataHost] = true
	}
	return &Client{http: hc, endpoints: o.Endpoints, now: now, allowed: allowed, cooldown: map[string]time.Time{}}
}

// AllowedHosts returns the exact host allow-list.
func (c *Client) AllowedHosts() []string {
	out := make([]string, 0, len(c.allowed))
	for h := range c.allowed {
		out = append(out, h)
	}
	return out
}

// errFailed carries a failure reason.
type errFailed struct{ reason string }

func (e errFailed) Error() string { return "online: " + e.reason }

func reasonOf(err error) string {
	var f errFailed
	if errors.As(err, &f) {
		return f.reason
	}
	var dnsErr *net.DNSError
	var certErr *tls.CertificateVerificationError
	var unknownAuth x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var recErr tls.RecordHeaderError
	switch {
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
		return ReasonTimeout
	case errors.As(err, &dnsErr):
		return ReasonDNS
	case errors.As(err, &certErr) || errors.As(err, &unknownAuth) || errors.As(err, &hostErr) || errors.As(err, &recErr):
		return ReasonTLS
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return ReasonTimeout
	}
	return ReasonNetwork
}

// do sends one request to an allow-listed https URL and returns the body
// within limit. 404 and 410 return (nil, 404, nil).
func (c *Client) do(ctx context.Context, method, raw string, body []byte, limit int64) ([]byte, int, error) {
	return c.doAccept(ctx, method, raw, body, limit, "application/json")
}

// doAccept is do with an Accept header of the caller's choosing.
func (c *Client) doAccept(ctx context.Context, method, raw string, body []byte, limit int64, accept string) ([]byte, int, error) {
	b, status, _, err := c.doHeaders(ctx, method, raw, body, limit, accept, "")
	return b, status, err
}

// doHeaders is the one request path: an Accept header, an optional
// If-None-Match, and the response headers back. 304 returns (nil, 304).
func (c *Client) doHeaders(ctx context.Context, method, raw string, body []byte, limit int64, accept, ifNoneMatch string) ([]byte, int, http.Header, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || (u.Port() != "" && u.Port() != "443") {
		return nil, 0, nil, errFailed{ReasonNotPublic}
	}
	host := u.Hostname()
	if !c.allowed[host] {
		return nil, 0, nil, errFailed{ReasonNotPublic}
	}
	c.mu.Lock()
	until := c.cooldown[host]
	c.mu.Unlock()
	if c.now().Before(until) {
		return nil, 0, nil, errFailed{ReasonCoolingDown}
	}
	target := raw
	if ep, ok := c.endpoints[host]; ok {
		target = strings.TrimSuffix(ep, "/") + u.RequestURI()
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		return nil, 0, nil, errFailed{ReasonNetwork}
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", accept)
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, nil, errFailed{reasonOf(err)}
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone || resp.StatusCode == http.StatusNotModified:
		return nil, resp.StatusCode, resp.Header, nil
	case resp.StatusCode == http.StatusTooManyRequests:
		wait := defaultCooldown
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
			wait = min(time.Duration(s)*time.Second, maxCooldown)
		}
		c.mu.Lock()
		c.cooldown[host] = c.now().Add(wait)
		c.mu.Unlock()
		return nil, resp.StatusCode, nil, errFailed{ReasonRateLimited}
	case resp.StatusCode != http.StatusOK:
		return nil, resp.StatusCode, nil, errFailed{ReasonHTTPStatus}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, 0, nil, errFailed{reasonOf(err)}
	}
	if int64(len(b)) > limit {
		return nil, 0, nil, errFailed{ReasonTooLarge}
	}
	return b, resp.StatusCode, resp.Header, nil
}

// Lookup answers for public names: the OSV batch query (malicious and
// other advisories) and each package's registry facts (exists, first
// published). specs must already be public-routable; a spec the classifier
// would not pass under defaults is refused here too (defence in depth: no
// URL, path or git spec reaches the network).
func (c *Client) Lookup(ctx context.Context, specs []secfeed.InstallSpec) []secfeed.OnlineAnswer {
	if len(specs) > maxBatch {
		specs = specs[:maxBatch]
	}
	out := make([]secfeed.OnlineAnswer, len(specs))
	var valid []int
	for i, s := range specs {
		out[i] = secfeed.OnlineAnswer{Eco: s.Eco, Name: secfeed.Normalize(s.Eco, s.Name), Version: s.Version}
		raw := s.Spec
		if raw == "" {
			raw = s.Name
		}
		if s.Invalid || secfeed.Classify(s.Eco, raw, secfeed.PrivConfig{}).Verdict != secfeed.PrivPublic {
			out[i].Status, out[i].Reason = secfeed.OnlineFailed, ReasonNotPublic
			continue
		}
		valid = append(valid, i)
	}
	if len(valid) == 0 {
		return out
	}
	osvIDs, osvErr := c.osvBatch(ctx, specs, valid)
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrent)
	for _, i := range valid {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			reg := c.registry(ctx, specs[i])
			now := c.now()
			a := &out[i]
			a.FetchedAt = now
			switch {
			case reg.err != nil:
				a.Status, a.Reason = secfeed.OnlineFailed, reasonOf(reg.err)
			case reg.notFound:
				a.Status = secfeed.OnlineNotFound
			case osvErr != nil:
				// The registry answered but the malicious source did not:
				// the online check is incomplete, never "fine".
				a.Status, a.Reason = secfeed.OnlineFailed, ReasonOSV
			default:
				a.Status, a.FirstPublished = secfeed.OnlineAnswered, reg.first
				for _, id := range osvIDs[i] {
					if strings.HasPrefix(id, "MAL-") {
						a.MalIDs = append(a.MalIDs, id)
					} else {
						a.VulnIDs = append(a.VulnIDs, id)
					}
				}
			}
		}(i)
	}
	wg.Wait()
	c.resolveMalCoverage(ctx, specs, out)
	return out
}

// resolveMalCoverage reads, for each unpinned answer with MAL- reports, the
// reports in full (`/v1/vulns/{id}`, the same host and client) until one
// covers every version: OSV answers an unpinned query with every version's
// reports, so without this a fully malicious package installed unpinned
// would read only "some versions" (S-749). At most maxMalReads records per
// lookup; a record that cannot be read leaves the answer as it was.
func (c *Client) resolveMalCoverage(ctx context.Context, specs []secfeed.InstallSpec, out []secfeed.OnlineAnswer) {
	jobs := malReadJobs(specs, out, maxMalReads)
	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		sem = make(chan struct{}, maxConcurrent)
	)
	for _, j := range jobs {
		wg.Add(1)
		go func(j malReadJob) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			mu.Lock()
			done := out[j.i].MalAllVersions
			mu.Unlock()
			if done {
				return
			}
			b, status, err := c.do(ctx, http.MethodGet, "https://"+OSVHost+"/v1/vulns/"+url.PathEscape(j.id), nil, maxOSVBytes)
			if err != nil || status != http.StatusOK {
				return
			}
			if all, ok := secfeed.MalCoversEveryVersion(b, j.id, specs[j.i].Eco, specs[j.i].Name); ok && all {
				mu.Lock()
				out[j.i].MalAllVersions = true
				mu.Unlock()
			}
		}(j)
	}
	wg.Wait()
}

// malReadJob is one MAL- record to read in full for answer i.
type malReadJob struct {
	i  int
	id string
}

// malReadJobs picks the MAL- records resolveMalCoverage reads, at most limit:
// round-robin across the unpinned answers, each answer's first report
// before any answer's second (lane SEC-DEPS3 item 12), so one package with
// many reports cannot use up the cap and leave another package's
// all-versions report unread (S-749 instead of S-741).
func malReadJobs(specs []secfeed.InstallSpec, out []secfeed.OnlineAnswer, limit int) []malReadJob {
	var jobs []malReadJob
	for round := 0; len(jobs) < limit; round++ {
		added := false
		for i := range out {
			if out[i].Status != secfeed.OnlineAnswered || specs[i].Version != "" || round >= len(out[i].MalIDs) {
				continue
			}
			added = true
			if len(jobs) < limit {
				jobs = append(jobs, malReadJob{i, out[i].MalIDs[round]})
			}
		}
		if !added {
			break
		}
	}
	return jobs
}

// osvBatch runs one querybatch for the valid specs and returns their ids
// by spec index.
func (c *Client) osvBatch(ctx context.Context, specs []secfeed.InstallSpec, valid []int) (map[int][]string, error) {
	type pkg struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	}
	type query struct {
		Package pkg    `json:"package"`
		Version string `json:"version,omitempty"`
	}
	q := struct {
		Queries []query `json:"queries"`
	}{}
	for _, i := range valid {
		e, _ := secfeed.EcosystemOf(specs[i].Eco)
		q.Queries = append(q.Queries, query{Package: pkg{Name: specs[i].Name, Ecosystem: e.OSV}, Version: specs[i].Version})
	}
	body, err := json.Marshal(q)
	if err != nil {
		return nil, errFailed{ReasonBadAnswer}
	}
	b, status, err := c.do(ctx, http.MethodPost, "https://"+OSVHost+"/v1/querybatch", body, maxOSVBytes)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, errFailed{ReasonHTTPStatus}
	}
	var resp struct {
		Results []struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
		} `json:"results"`
	}
	if err := json.Unmarshal(b, &resp); err != nil || len(resp.Results) != len(valid) {
		// Positional answers that do not line up cannot be attributed.
		return nil, errFailed{ReasonBadAnswer}
	}
	out := map[int][]string{}
	for k, r := range resp.Results {
		for _, v := range r.Vulns {
			if v.ID != "" && len(v.ID) <= 64 {
				out[valid[k]] = append(out[valid[k]], v.ID)
			}
		}
	}
	return out, nil
}

// regResult is one registry answer.
type regResult struct {
	notFound bool
	first    time.Time
	err      error
}

// registryRow is one ecosystem's metadata request and reader. facts, when
// set, replaces the one-request url-and-read path (npm's two-step read).
type registryRow struct {
	url   func(name string) (string, error)
	read  func(b []byte) (time.Time, error)
	facts func(ctx context.Context, c *Client, name string) regResult
}

// npmAbbreviated is the abbreviated packument's media type: the version
// list and the last-modified time, without the per-version readmes and
// times that make the full document tens of megabytes for a package like
// typescript or @types/node.
const npmAbbreviated = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8"

// The npm two-step read: a package last modified before npmSettledAfter
// was first published before then too, so its age is settled from the
// abbreviated document alone; a recently modified package with at most
// npmSmallPackument versions is small enough to read in full for its
// creation time; a recently modified package with more versions than that
// is not new, and its first publish stays unknown (zero), which never
// reads too_new.
const (
	npmSettledAfter   = 8 * 24 * time.Hour
	npmSmallPackument = 30
)

// npmFacts reads npm's registry facts in at most two requests, the first
// one small.
func npmFacts(ctx context.Context, c *Client, name string) regResult {
	raw := "https://registry.npmjs.org/" + url.PathEscape(name)
	b, status, err := c.doAccept(ctx, http.MethodGet, raw, nil, maxRegistryBytes, npmAbbreviated)
	if err != nil {
		return regResult{err: err}
	}
	if status == http.StatusNotFound || status == http.StatusGone {
		return regResult{notFound: true}
	}
	var d struct {
		Modified string                     `json:"modified"`
		Versions map[string]json.RawMessage `json:"versions"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return regResult{err: errFailed{ReasonBadAnswer}}
	}
	modified := parseTime(d.Modified)
	if !modified.IsZero() && c.now().Sub(modified) >= npmSettledAfter {
		// First published at or before the last modification: old enough
		// for any minimum age, and the time stands in for it.
		return regResult{first: modified}
	}
	if len(d.Versions) > npmSmallPackument {
		return regResult{}
	}
	full, status, err := c.do(ctx, http.MethodGet, raw, nil, maxRegistryBytes)
	if err != nil {
		return regResult{err: err}
	}
	if status != http.StatusOK {
		return regResult{notFound: true}
	}
	var fd struct {
		Time map[string]string `json:"time"`
	}
	if err := json.Unmarshal(full, &fd); err != nil {
		return regResult{err: errFailed{ReasonBadAnswer}}
	}
	return regResult{first: parseTime(fd.Time["created"])}
}

// registryTable is the per-ecosystem metadata table; every URL is on its
// ecosystem row's MetadataHost.
var registryTable = map[secfeed.Ecosystem]registryRow{
	secfeed.EcoNpm: {facts: npmFacts},
	secfeed.EcoPyPI: {
		url: func(n string) (string, error) { return "https://pypi.org/pypi/" + url.PathEscape(n) + "/json", nil },
		read: func(b []byte) (time.Time, error) {
			var d struct {
				Releases map[string][]struct {
					Upload string `json:"upload_time_iso_8601"`
				} `json:"releases"`
			}
			if err := json.Unmarshal(b, &d); err != nil {
				return time.Time{}, err
			}
			var first time.Time
			for _, files := range d.Releases {
				for _, f := range files {
					first = earliest(first, parseTime(f.Upload))
				}
			}
			return first, nil
		},
	},
	secfeed.EcoGo: {
		url: func(n string) (string, error) {
			esc, err := module.EscapePath(n)
			if err != nil {
				return "", errFailed{ReasonNotPublic}
			}
			return "https://proxy.golang.org/" + esc + "/@v/list", nil
		},
		read: func([]byte) (time.Time, error) { return time.Time{}, nil },
	},
	secfeed.EcoCargo: {
		url: func(n string) (string, error) { return "https://crates.io/api/v1/crates/" + url.PathEscape(n), nil },
		read: func(b []byte) (time.Time, error) {
			var d struct {
				Crate struct {
					Created string `json:"created_at"`
				} `json:"crate"`
			}
			if err := json.Unmarshal(b, &d); err != nil {
				return time.Time{}, err
			}
			return parseTime(d.Crate.Created), nil
		},
	},
	secfeed.EcoNuGet: {
		url: func(n string) (string, error) {
			return "https://api.nuget.org/v3-flatcontainer/" + url.PathEscape(strings.ToLower(n)) + "/index.json", nil
		},
		read: func(b []byte) (time.Time, error) {
			var d struct {
				Versions []string `json:"versions"`
			}
			if err := json.Unmarshal(b, &d); err != nil || len(d.Versions) == 0 {
				return time.Time{}, errFailed{ReasonBadAnswer}
			}
			return time.Time{}, nil
		},
	},
	secfeed.EcoRubyGems: {
		url: func(n string) (string, error) {
			return "https://rubygems.org/api/v1/versions/" + url.PathEscape(n) + ".json", nil
		},
		read: func(b []byte) (time.Time, error) {
			var d []struct {
				Created string `json:"created_at"`
			}
			if err := json.Unmarshal(b, &d); err != nil {
				return time.Time{}, err
			}
			var first time.Time
			for _, v := range d {
				first = earliest(first, parseTime(v.Created))
			}
			return first, nil
		},
	},
	secfeed.EcoPackagist: {
		url: func(n string) (string, error) {
			vendor, pkg, ok := strings.Cut(n, "/")
			if !ok {
				return "", errFailed{ReasonNotPublic}
			}
			return "https://repo.packagist.org/p2/" + url.PathEscape(vendor) + "/" + url.PathEscape(pkg) + ".json", nil
		},
		read: func(b []byte) (time.Time, error) {
			var d struct {
				Packages map[string][]struct {
					Time string `json:"time"`
				} `json:"packages"`
			}
			if err := json.Unmarshal(b, &d); err != nil {
				return time.Time{}, err
			}
			var first time.Time
			for _, vs := range d.Packages {
				for _, v := range vs {
					first = earliest(first, parseTime(v.Time))
				}
			}
			return first, nil
		},
	},
}

func (c *Client) registry(ctx context.Context, s secfeed.InstallSpec) regResult {
	row, ok := registryTable[s.Eco]
	if !ok {
		return regResult{err: errFailed{ReasonNoRegistry}}
	}
	if row.facts != nil {
		return row.facts(ctx, c, secfeed.Normalize(s.Eco, s.Name))
	}
	raw, err := row.url(secfeed.Normalize(s.Eco, s.Name))
	if err != nil {
		return regResult{err: err}
	}
	b, status, err := c.do(ctx, http.MethodGet, raw, nil, maxRegistryBytes)
	if err != nil {
		return regResult{err: err}
	}
	if status == http.StatusNotFound || status == http.StatusGone {
		return regResult{notFound: true}
	}
	first, err := row.read(b)
	if err != nil {
		return regResult{err: errFailed{ReasonBadAnswer}}
	}
	return regResult{first: first}
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

func earliest(a, b time.Time) time.Time {
	if b.IsZero() {
		return a
	}
	if a.IsZero() || b.Before(a) {
		return b
	}
	return a
}

// FeedURL is the vendor content feed's URL for a kind's file. The feed is
// published beside the pricing feed on the vendor site; the path is fixed.
func FeedURL(kind, file string) string {
	return "https://" + FeedHost + "/api/security/v1/content/" + url.PathEscape(kind) + "/" + url.PathEscape(file)
}

// ErrFeedNotPublished is FetchFeedFile's answer for a 404 or 410: the feed
// file does not exist (yet), which the feed loop does not treat as a fault.
var ErrFeedNotPublished = errors.New("online: the feed file is not published")

// FetchFeedFile downloads one file of the vendor content feed: a plain GET
// of a public file, capped. The caller verifies it through the signed
// content channel before using a byte of it.
func (c *Client) FetchFeedFile(ctx context.Context, kind, file string) ([]byte, error) {
	b, status, err := c.do(ctx, http.MethodGet, FeedURL(kind, file), nil, maxFeedBytes)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound || status == http.StatusGone {
		return nil, fmt.Errorf("online: feed %s/%s: %w", kind, file, ErrFeedNotPublished)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("online: feed %s/%s: status %d", kind, file, status)
	}
	return b, nil
}

// ErrFeedNotModified is FetchFeedFileIfChanged's answer for a 304: the file
// is the one the caller already has.
var ErrFeedNotModified = errors.New("online: the feed file is not modified")

// FetchFeedFileIfChanged is FetchFeedFile with ETag revalidation: etag is
// the ETag of the copy the caller has ("" for none). It returns the body
// and its ETag, or ErrFeedNotModified when the server says the copy is
// current.
func (c *Client) FetchFeedFileIfChanged(ctx context.Context, kind, file, etag string) ([]byte, string, error) {
	b, status, hdr, err := c.doHeaders(ctx, http.MethodGet, FeedURL(kind, file), nil, maxFeedBytes, "application/json", etag)
	if err != nil {
		return nil, "", err
	}
	switch status {
	case http.StatusNotModified:
		return nil, etag, ErrFeedNotModified
	case http.StatusNotFound, http.StatusGone:
		return nil, "", fmt.Errorf("online: feed %s/%s: %w", kind, file, ErrFeedNotPublished)
	case http.StatusOK:
		return b, hdr.Get("ETag"), nil
	}
	return nil, "", fmt.Errorf("online: feed %s/%s: status %d", kind, file, status)
}

// ReasonOf returns the closed failure reason of an error from this client.
func ReasonOf(err error) string { return reasonOf(err) }
