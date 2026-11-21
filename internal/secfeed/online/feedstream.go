package online

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// feedstream.go is the streamed feed download (lane SEC-H2, SECP-26): an
// artifact the signed manifest lists can be far larger than the 64 MiB a
// buffered feed file may be (the OSV exports run to hundreds of MiB), so
// `observer-org security mirror sync` streams it to a file instead, bounded
// by the manifest's exact size and checked against its SHA-256 as it is
// written. The same exact-host allow-list, no redirects and cool-down apply
// as to every other request this client makes.

// MaxStreamBytes is the ceiling a streamed artifact may declare, whatever
// its manifest says.
const MaxStreamBytes int64 = 8 << 30

// ErrStreamDigest is a streamed artifact whose size or digest does not
// match what the signed manifest names.
var ErrStreamDigest = errors.New("online: the streamed feed file does not match its manifest entry")

// NotPublished reports whether err is ErrFeedNotPublished, the feed's 404 or
// 410 (the org mirror's sync reads it through secrelay.FeedSource, which
// does not import this package).
func (c *Client) NotPublished(err error) bool { return errors.Is(err, ErrFeedNotPublished) }

// FetchFeedFileTo streams one feed file into w, refusing more than size
// bytes, and checks it is exactly size bytes with the SHA-256 hex digest
// sha. It returns ErrFeedNotPublished for a 404 or 410. w holds partial
// bytes after an error; the caller discards them.
func (c *Client) FetchFeedFileTo(ctx context.Context, kind, file string, size int64, sha string, w io.Writer) error {
	if size <= 0 || size > MaxStreamBytes || len(sha) != 64 {
		return fmt.Errorf("online: feed %s/%s: %w (size %d)", kind, file, ErrStreamDigest, size)
	}
	raw := FeedURL(kind, file)
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || !c.allowed[u.Hostname()] {
		return errFailed{ReasonNotPublic}
	}
	host := u.Hostname()
	c.mu.Lock()
	until := c.cooldown[host]
	c.mu.Unlock()
	if c.now().Before(until) {
		return errFailed{ReasonCoolingDown}
	}
	target := raw
	if ep, ok := c.endpoints[host]; ok {
		target = strings.TrimSuffix(ep, "/") + u.RequestURI()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return errFailed{ReasonNetwork}
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/octet-stream")
	resp, err := c.http.Do(req)
	if err != nil {
		return errFailed{reasonOf(err)}
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return fmt.Errorf("online: feed %s/%s: %w", kind, file, ErrFeedNotPublished)
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("online: feed %s/%s: status %d", kind, file, resp.StatusCode)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(resp.Body, size+1))
	if err != nil {
		return errFailed{reasonOf(err)}
	}
	if n != size || hex.EncodeToString(h.Sum(nil)) != strings.ToLower(sha) {
		return fmt.Errorf("online: feed %s/%s: %w (%d bytes)", kind, file, ErrStreamDigest, n)
	}
	return nil
}
