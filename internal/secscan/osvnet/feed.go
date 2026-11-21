package osvnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
)

// feed.go is the lane's second source: SuperBased's signed mirror of the
// OSV exports on superbased.app (the security.osv_export content kind,
// static feed mirroring plan section 7, row 3). It fetches public files
// only, by kind and file name; the caller verifies every byte through the
// signed content channel before using it.

// feedPathPrefix is the content feed's path on FeedHost.
const feedPathPrefix = "/api/security/v1/content/"

// MaxFeedFileBytes caps a feed file read whole (a manifest envelope).
const MaxFeedFileBytes = 2 << 20

// maxFeedArtifactBytes caps one streamed feed artifact (an ecosystem's
// base export; npm is about 220 MB).
const maxFeedArtifactBytes = osvdb.MaxExportBytes

// UserAgent is sent on every feed request: the product, nothing about the
// node.
const UserAgent = "superbased-observer"

// ErrFeedNotPublished is the feed's 404 or 410: the file is not published
// (yet), which the caller treats as "no feed", not as a fault.
var ErrFeedNotPublished = errors.New("osvnet: the feed file is not published")

// ErrFeedNotModified is FetchFeedFile's answer for a 304: the copy whose
// ETag was sent is current.
var ErrFeedNotModified = errors.New("osvnet: the feed file is not modified")

// validFeedSegment keeps a kind or file name a plain path segment: letters,
// digits, '.', '-' and '_' only, not "." or ".." (the feed host serves no
// other name; an ecosystem with a space is published under
// osvdb.ExportArtifact's name).
func validFeedSegment(s string) bool {
	if s == "" || len(s) > 128 || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		if !(r == '.' || r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// feedFileURL is the URL of one feed file.
func (c *Client) feedFileURL(kind, file string) (string, error) {
	if !validFeedSegment(kind) || !validFeedSegment(file) {
		return "", fmt.Errorf("osvnet: bad feed path %q/%q", kind, file)
	}
	return c.feedURL + feedPathPrefix + url.PathEscape(kind) + "/" + url.PathEscape(file), nil
}

// feedGet issues one GET of a feed file.
func (c *Client) feedGet(ctx context.Context, kind, file, etag string) (*http.Response, error) {
	u, err := c.feedFileURL(kind, file)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osvnet: feed %s/%s: %w", kind, file, err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return resp, nil
	case http.StatusNotModified:
		_ = resp.Body.Close()
		return nil, ErrFeedNotModified
	case http.StatusNotFound, http.StatusGone:
		_ = resp.Body.Close()
		return nil, fmt.Errorf("osvnet: feed %s/%s: %w", kind, file, ErrFeedNotPublished)
	default:
		_ = resp.Body.Close()
		return nil, fmt.Errorf("osvnet: feed %s/%s: HTTP %d", kind, file, resp.StatusCode)
	}
}

// FetchFeedFile reads one feed file whole (at most MaxFeedFileBytes) and
// returns it with its ETag. A non-empty etag is sent as If-None-Match, and
// a 304 answers ErrFeedNotModified.
func (c *Client) FetchFeedFile(ctx context.Context, kind, file, etag string) ([]byte, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	resp, err := c.feedGet(ctx, kind, file, etag)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxFeedFileBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("osvnet: feed %s/%s: %w", kind, file, err)
	}
	if len(b) > MaxFeedFileBytes {
		return nil, "", fmt.Errorf("osvnet: feed %s/%s is larger than %d bytes", kind, file, MaxFeedFileBytes)
	}
	tag := resp.Header.Get("ETag")
	if len(tag) > 256 {
		tag = ""
	}
	return b, strings.TrimSpace(tag), nil
}

// StreamFeedArtifact streams one feed artifact into w and refuses anything
// but exactly size bytes (at most osvdb.MaxExportBytes); the caller checks the
// digest. w holds partial bytes after an error; the caller discards them.
func (c *Client) StreamFeedArtifact(ctx context.Context, kind, file string, size int64, w io.Writer) error {
	if size <= 0 || size > maxFeedArtifactBytes {
		return fmt.Errorf("osvnet: feed %s/%s: size %d out of range", kind, file, size)
	}
	resp, err := c.feedGet(ctx, kind, file, "")
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	n, err := io.Copy(w, io.LimitReader(resp.Body, size+1))
	if err != nil {
		return fmt.Errorf("osvnet: feed %s/%s: %w", kind, file, err)
	}
	if n != size {
		return fmt.Errorf("osvnet: feed %s/%s: %d bytes, the manifest lists %d", kind, file, n, size)
	}
	return nil
}
