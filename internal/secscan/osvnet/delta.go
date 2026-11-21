package osvnet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
)

// The change listing's read sizes.
const (
	// ListChunk is one Range request's size over modified_id.csv: a quiet
	// ecosystem costs one such read.
	ListChunk = 64 << 10
	// maxListBytes caps a listing whose size the server did not state (npm's
	// is about 8.7 MB).
	maxListBytes = 256 << 20
	// maxLineBytes caps one listing line (a 30-byte timestamp, a comma and
	// an id of at most osvdb.MaxIDLength).
	maxLineBytes = 1 << 10
	// requestTimeout bounds each request of the incremental path.
	requestTimeout = 30 * time.Second
)

func (c *Client) objectURL(eco, name string) (string, error) {
	if !validEco(eco) {
		return "", fmt.Errorf("osvnet: bad ecosystem %q", eco)
	}
	return c.bucketURL + "/" + url.PathEscape(eco) + "/" + url.PathEscape(name), nil
}

// listReader walks modified_id.csv lines (newest first) and decides when
// to stop.
type listReader struct {
	since   time.Time
	limit   int
	ids     []osvdb.Modified
	carry   []byte
	done    bool
	overflw bool
}

// feed takes the next bytes of the listing; final marks its end.
func (l *listReader) feed(b []byte, final bool) error {
	l.carry = append(l.carry, b...)
	for !l.done {
		i := bytes.IndexByte(l.carry, '\n')
		if i < 0 {
			break
		}
		line := l.carry[:i]
		l.carry = l.carry[i+1:]
		if err := l.line(line); err != nil {
			return err
		}
	}
	if l.done {
		return nil
	}
	if len(l.carry) > maxLineBytes {
		return fmt.Errorf("a listing line is longer than %d bytes", maxLineBytes)
	}
	if final {
		line := l.carry
		l.carry = nil
		if err := l.line(line); err != nil {
			return err
		}
		l.done = true
	}
	return nil
}

func (l *listReader) line(raw []byte) error {
	s := strings.TrimRight(string(raw), "\r")
	if s == "" {
		return nil
	}
	ts, id, ok := strings.Cut(s, ",")
	if !ok {
		return fmt.Errorf("malformed listing line %q", clip(s))
	}
	at, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return fmt.Errorf("malformed listing time %q", clip(ts))
	}
	if !osvdb.ValidID(id) {
		return fmt.Errorf("malformed listing id %q", clip(id))
	}
	if !at.After(l.since) {
		l.done = true
		return nil
	}
	if len(l.ids) >= l.limit {
		l.done, l.overflw = true, true
		return nil
	}
	l.ids = append(l.ids, osvdb.Modified{ID: id, At: at})
	return nil
}

func clip(s string) string {
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}

// ModifiedSince lists the records of eco modified strictly after since,
// newest first, from the bucket's <eco>/modified_id.csv (lines
// "RFC3339Nano,ID", newest first): it reads ListChunk-byte Range requests
// from the start and stops at the first line not after since, so a quiet
// ecosystem costs one small read. More than limit records stops the read
// with overflow (and the first limit records). A server that ignores Range
// (HTTP 200) is read as one stream, still stopping early. A malformed line
// is an error; the bytes read never pass the object's stated size. Only
// the ecosystem name is sent.
func (c *Client) ModifiedSince(ctx context.Context, eco string, since time.Time, limit int) ([]osvdb.Modified, bool, error) {
	u, err := c.objectURL(eco, "modified_id.csv")
	if err != nil {
		return nil, false, err
	}
	l := &listReader{since: since, limit: limit}
	var off int64
	size := int64(-1)
	for !l.done {
		if size >= 0 && off >= size {
			if err := l.feed(nil, true); err != nil {
				return nil, false, fmt.Errorf("osvnet.ModifiedSince: %s: %w", eco, err)
			}
			break
		}
		if off >= maxListBytes {
			return nil, false, fmt.Errorf("osvnet.ModifiedSince: %s: the listing is larger than %d bytes", eco, maxListBytes)
		}
		total, n, err := c.listRange(ctx, u, off, l)
		if err != nil {
			return nil, false, fmt.Errorf("osvnet.ModifiedSince: %s: %w", eco, err)
		}
		if total >= 0 {
			size = total
		}
		off += n
		if n == 0 && !l.done && size < 0 {
			return nil, false, fmt.Errorf("osvnet.ModifiedSince: %s: the listing read made no progress", eco)
		}
	}
	return l.ids, l.overflw, nil
}

// listRange reads one Range request at off into l. It returns the
// object's size (-1 when unknown) and the bytes consumed. A 200 answer
// (Range ignored) is read sequentially to its end or to l's stop and
// reported as the whole object.
func (c *Client) listRange(ctx context.Context, u string, off int64, l *listReader) (int64, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return -1, 0, err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", off, off+ListChunk-1))
	resp, err := c.http.Do(req)
	if err != nil {
		return -1, 0, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusPartialContent:
		start, end, total, err := parseContentRange(resp.Header.Get("Content-Range"))
		if err != nil {
			return -1, 0, err
		}
		if start != off || end < start || end-start+1 > ListChunk || (total >= 0 && end >= total) {
			return -1, 0, fmt.Errorf("unexpected Content-Range %q for offset %d", resp.Header.Get("Content-Range"), off)
		}
		want := end - start + 1
		b, err := io.ReadAll(io.LimitReader(resp.Body, want+1))
		if err != nil {
			return -1, 0, err
		}
		if int64(len(b)) != want {
			return -1, 0, fmt.Errorf("range read %d bytes, the server stated %d", len(b), want)
		}
		// The last chunk: the stated size reached, or (size unstated) a
		// short chunk.
		final := (total >= 0 && end+1 >= total) || (total < 0 && want < ListChunk)
		if err := l.feed(b, final); err != nil {
			return -1, 0, err
		}
		return total, want, nil
	case http.StatusRequestedRangeNotSatisfiable:
		// Past the end: an empty listing, or one that ended exactly on
		// the previous chunk's boundary.
		if err := l.feed(nil, true); err != nil {
			return -1, 0, err
		}
		return off, 0, nil
	case http.StatusOK:
		if off != 0 {
			return -1, 0, errors.New("the server ignored Range after honouring it")
		}
		limit := int64(maxListBytes)
		if resp.ContentLength >= 0 && resp.ContentLength < limit {
			limit = resp.ContentLength
		}
		r := io.LimitReader(resp.Body, limit)
		buf := make([]byte, ListChunk)
		var read int64
		for !l.done {
			n, rerr := r.Read(buf)
			read += int64(n)
			eof := errors.Is(rerr, io.EOF)
			if n > 0 || eof {
				if err := l.feed(buf[:n], eof); err != nil {
					return -1, 0, err
				}
			}
			if eof {
				break
			}
			if rerr != nil {
				return -1, 0, rerr
			}
		}
		if !l.done {
			if err := l.feed(nil, true); err != nil {
				return -1, 0, err
			}
		}
		return read, read, nil
	default:
		return -1, 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
}

// parseContentRange reads "bytes start-end/total" (total "*" is -1).
func parseContentRange(v string) (start, end, total int64, err error) {
	rest, ok := strings.CutPrefix(v, "bytes ")
	if !ok {
		return 0, 0, 0, fmt.Errorf("bad Content-Range %q", v)
	}
	rng, tot, ok := strings.Cut(rest, "/")
	if !ok {
		return 0, 0, 0, fmt.Errorf("bad Content-Range %q", v)
	}
	a, b, ok := strings.Cut(rng, "-")
	if !ok {
		return 0, 0, 0, fmt.Errorf("bad Content-Range %q", v)
	}
	if start, err = strconv.ParseInt(a, 10, 64); err != nil {
		return 0, 0, 0, fmt.Errorf("bad Content-Range %q", v)
	}
	if end, err = strconv.ParseInt(b, 10, 64); err != nil {
		return 0, 0, 0, fmt.Errorf("bad Content-Range %q", v)
	}
	total = -1
	if tot != "*" {
		if total, err = strconv.ParseInt(tot, 10, 64); err != nil {
			return 0, 0, 0, fmt.Errorf("bad Content-Range %q", v)
		}
	}
	return start, end, total, nil
}

// Record fetches one OSV record, <eco>/<id>.json, at most
// osvdb.MaxRecordBytes; a 404 is osvdb.ErrRecordGone (the record was
// withdrawn from the ecosystem). Only the ecosystem and the public record
// id are sent.
func (c *Client) Record(ctx context.Context, eco, id string) ([]byte, error) {
	if !osvdb.ValidID(id) {
		return nil, fmt.Errorf("osvnet.Record: bad record id %q", id)
	}
	u, err := c.objectURL(eco, osvdb.EntryName(id))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osvnet.Record: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("osvnet.Record: %s/%s: %w", eco, id, osvdb.ErrRecordGone)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osvnet.Record: %s/%s: HTTP %d", eco, id, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, osvdb.MaxRecordBytes+1))
	if err != nil {
		return nil, fmt.Errorf("osvnet.Record: %w", err)
	}
	if len(b) > osvdb.MaxRecordBytes {
		return nil, fmt.Errorf("osvnet.Record: %s/%s is larger than %d bytes", eco, id, osvdb.MaxRecordBytes)
	}
	return b, nil
}

// The client is a DeltaRemote, so osvdb takes the incremental path.
var _ osvdb.DeltaRemote = (*Client)(nil)
