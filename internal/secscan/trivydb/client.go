package trivydb

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
)

// The allow-listed hosts and the artifact.
const (
	// RegistryHost serves the token, the manifest and the layer request.
	RegistryHost = osvdb.TrivyRegistryHost
	// BlobHost is the one host the registry redirects a layer download to.
	BlobHost = osvdb.TrivyBlobHost
	// Repository and Tag name the artifact.
	Repository = "aquasecurity/trivy-db"
	Tag        = "2"
	// ManifestMediaType is the manifest the registry serves for the tag.
	ManifestMediaType = "application/vnd.oci.image.manifest.v1+json"
	// LayerMediaType is the database layer's media type.
	LayerMediaType = "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip"
	// UserAgent is every request's User-Agent.
	UserAgent = "superbased-observer"
)

// Body caps.
const (
	maxTokenBytes    = 64 << 10
	maxManifestBytes = 64 << 10
	// MaxLayerBytes caps the compressed layer (138,593,574 bytes on
	// 2026-11-04).
	MaxLayerBytes = 512 << 20
	maxRedirects  = 3
)

// AllowedHosts is the exact host allow-list.
func AllowedHosts() []string { return []string{RegistryHost, BlobHost} }

// Options tunes New. The zero value is the production client.
type Options struct {
	// Transport replaces the base transport (tests only); the scheme and
	// host checks still apply.
	Transport http.RoundTripper
	// Endpoints maps an allow-listed host to a test server's base URL
	// (tests only).
	Endpoints map[string]string
}

// Client is the lane.
type Client struct {
	// plain follows no redirect (the token and the manifest); blob follows
	// one only to BlobHost (the layer).
	plain *http.Client
	blob  *http.Client
}

// Errors of the lane.
var (
	// ErrTooLarge is a body over its cap.
	ErrTooLarge = errors.New("trivydb: the response is over its cap")
	// ErrManifest is a manifest that is not the expected artifact.
	ErrManifest = errors.New("trivydb: the manifest is not Trivy's database artifact")
	// ErrDigest is a body whose digest or size is not the one stated.
	ErrDigest = errors.New("trivydb: the digest or size does not match")
)

// New returns the lane's client.
func New(o Options) *Client {
	base := o.Transport
	if base == nil {
		base = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConns:          4,
			IdleConnTimeout:       30 * time.Second,
		}
	}
	rt := allowList{base: base, endpoints: o.Endpoints}
	return &Client{
		plain: &http.Client{Transport: rt, CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			return fmt.Errorf("trivydb: a redirect to %s://%s is refused", req.URL.Scheme, req.URL.Hostname())
		}},
		blob: &http.Client{Transport: rt, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errors.New("trivydb: too many redirects")
			}
			if !allowed(req.URL) || req.URL.Hostname() != BlobHost {
				return fmt.Errorf("trivydb: a redirect to %s://%s is refused", req.URL.Scheme, req.URL.Hostname())
			}
			// Go drops Authorization on a cross-host redirect; the blob
			// host's URL is pre-signed and needs no token.
			req.Header.Del("Authorization")
			return nil
		}},
	}
}

func allowed(u *url.URL) bool {
	return u.Scheme == "https" && slices.Contains(AllowedHosts(), u.Hostname()) && (u.Port() == "" || u.Port() == "443")
}

type allowList struct {
	base      http.RoundTripper
	endpoints map[string]string
}

func (a allowList) RoundTrip(r *http.Request) (*http.Response, error) {
	if !allowed(r.URL) {
		return nil, fmt.Errorf("trivydb: %s://%s is not on the allow-list", r.URL.Scheme, r.URL.Host)
	}
	if ep, ok := a.endpoints[r.URL.Hostname()]; ok {
		t, err := url.Parse(ep)
		if err != nil {
			return nil, err
		}
		r2 := r.Clone(r.Context())
		r2.URL.Scheme, r2.URL.Host = t.Scheme, t.Host
		r2.Host = t.Host
		return a.base.RoundTrip(r2)
	}
	return a.base.RoundTrip(r)
}

// Descriptor names one layer.
type Descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

// Manifest is the artifact's manifest as the lane checked it.
type Manifest struct {
	// Digest is "sha256:<hex>" of the manifest body (the epoch's first
	// half).
	Digest string
	// Layer is the one database layer.
	Layer Descriptor
	// Created is the manifest's creation annotation ("" when absent).
	Created string
	// token is the pull token the layer request reuses.
	token string
}

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (c *Client) get(ctx context.Context, hc *http.Client, raw, accept, token string, limit int64) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return nil, nil, ErrTooLarge
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(b)) > limit {
		return nil, nil, ErrTooLarge
	}
	return b, resp.Header, nil
}

// token asks the registry for an anonymous pull token for the repository.
func (c *Client) token(ctx context.Context) (string, error) {
	q := url.Values{"scope": {"repository:" + Repository + ":pull"}, "service": {RegistryHost}}
	b, _, err := c.get(ctx, c.plain, "https://"+RegistryHost+"/token?"+q.Encode(), "application/json", "", maxTokenBytes)
	if err != nil {
		return "", fmt.Errorf("trivydb: token: %w", err)
	}
	var t struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(b, &t); err != nil {
		return "", fmt.Errorf("trivydb: token: %w", err)
	}
	tok := t.Token
	if tok == "" {
		tok = t.AccessToken
	}
	if tok == "" || len(tok) > 8192 || strings.ContainsAny(tok, " \r\n") {
		return "", errors.New("trivydb: token: none in the answer")
	}
	return tok, nil
}

// Manifest fetches the tag's manifest and checks it: its digest (the
// registry's Docker-Content-Digest, when stated, equals the body's), its
// media type, and exactly one database layer with a sha256 digest and a
// size within MaxLayerBytes.
func (c *Client) Manifest(ctx context.Context) (Manifest, error) {
	tok, err := c.token(ctx)
	if err != nil {
		return Manifest{}, err
	}
	b, h, err := c.get(ctx, c.plain, "https://"+RegistryHost+"/v2/"+Repository+"/manifests/"+Tag, ManifestMediaType, tok, maxManifestBytes)
	if err != nil {
		return Manifest{}, fmt.Errorf("trivydb: manifest: %w", err)
	}
	sum := sha256.Sum256(b)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if stated := strings.TrimSpace(h.Get("Docker-Content-Digest")); stated != "" && stated != digest {
		return Manifest{}, fmt.Errorf("%w: the manifest's digest is %s, the registry states %s", ErrDigest, digest, stated)
	}
	if ct := h.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, ManifestMediaType) {
		return Manifest{}, fmt.Errorf("%w: content type %q", ErrManifest, ct)
	}
	var m struct {
		SchemaVersion int               `json:"schemaVersion"`
		MediaType     string            `json:"mediaType"`
		Layers        []Descriptor      `json:"layers"`
		Annotations   map[string]string `json:"annotations"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return Manifest{}, fmt.Errorf("%w: %w", ErrManifest, err)
	}
	if m.SchemaVersion != 2 || (m.MediaType != "" && m.MediaType != ManifestMediaType) || len(m.Layers) != 1 {
		return Manifest{}, fmt.Errorf("%w: schema %d, media type %q, %d layers", ErrManifest, m.SchemaVersion, m.MediaType, len(m.Layers))
	}
	l := m.Layers[0]
	if l.MediaType != LayerMediaType || !digestRE.MatchString(l.Digest) || l.Size <= 0 || l.Size > MaxLayerBytes {
		return Manifest{}, fmt.Errorf("%w: layer %s %s %d bytes", ErrManifest, l.MediaType, l.Digest, l.Size)
	}
	created := m.Annotations["org.opencontainers.image.created"]
	if len(created) > 64 {
		created = ""
	}
	return Manifest{Digest: digest, Layer: l, Created: created, token: tok}, nil
}

// Layer streams the manifest's layer into w and checks its size and
// sha256 against the manifest. The registry's redirect is followed only to
// BlobHost. The caller discards whatever reached w on an error.
func (c *Client) Layer(ctx context.Context, m Manifest, w io.Writer) error {
	if !digestRE.MatchString(m.Layer.Digest) || m.Layer.Size <= 0 || m.Layer.Size > MaxLayerBytes {
		return fmt.Errorf("%w: no layer", ErrManifest)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+RegistryHost+"/v2/"+Repository+"/blobs/"+m.Layer.Digest, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", UserAgent)
	if m.token != "" {
		req.Header.Set("Authorization", "Bearer "+m.token)
	}
	resp, err := c.blob.Do(req)
	if err != nil {
		return fmt.Errorf("trivydb: layer: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("trivydb: layer: HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > m.Layer.Size {
		return ErrTooLarge
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(resp.Body, m.Layer.Size+1))
	if err != nil {
		return fmt.Errorf("trivydb: layer: %w", err)
	}
	if n != m.Layer.Size {
		return fmt.Errorf("%w: %d bytes, the manifest states %d", ErrDigest, n, m.Layer.Size)
	}
	if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); got != m.Layer.Digest {
		return fmt.Errorf("%w: the layer's digest is %s, the manifest states %s", ErrDigest, got, m.Layer.Digest)
	}
	return nil
}
