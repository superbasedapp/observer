package osvshard

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvshardkey"
)

// DefaultInFlight is the most object requests a walk has open at once
// (plan section 13.3).
const DefaultInFlight = 8

// MaxShardJSONBytes caps one shard's decompressed JSON (the largest shard,
// Ubuntu 20.04's kernel family, is 14.6 MiB of gzip; JSON compresses about
// ten to one).
const MaxShardJSONBytes = 512 << 20

// Fetcher fetches one object of the shard bucket by its path
// (osvshardkey.IndexPath or ShardPath) and refuses a body larger than max.
// The production Fetcher is the security.scan.osv.shards lane
// (internal/secscan/osvshard/shardnet).
type Fetcher interface {
	Fetch(ctx context.Context, path string, max int64) ([]byte, error)
}

// Lookup is one walk's configuration.
type Lookup struct {
	// Fetch is the network side; nil makes every object not in the cache a
	// failure (an offline walk).
	Fetch Fetcher
	// Cache holds verified objects across walks.
	Cache Cache
	// InFlight caps concurrent requests; 0 means DefaultInFlight.
	InFlight int
}

// Query is one ecosystem's lookup.
type Query struct {
	// Set is the verified descriptor of the ecosystem's shard set (the
	// caller read it from the signed security.osv_shards manifest).
	Set osvshardkey.SetDescriptor
	// Names are every spelling of every package to look up, the canary's
	// included; duplicates and empty names are ignored.
	Names []string
}

// Record is one merged OSV record.
type Record struct {
	ID   string
	JSON []byte
}

// Answer is one lookup's result.
type Answer struct {
	// Set, Ecosystem and Epoch name the data the answer came from.
	Set       string
	Ecosystem string
	Epoch     int64
	// Records are the records whose affected names match a name asked for,
	// one per id (copies merged by the union of affected), in id order.
	Records []Record
	// Failed holds the canonical names (osvshardkey.Canon) whose index file
	// or shard could not be fetched or verified: their packages are not
	// matched, and the caller reports them as gaps.
	Failed map[string]bool
	// Prefixes is how many distinct prefixes the names fell in; Fetched and
	// Cached how many objects (index files and shards) came from the
	// network and from the cache.
	Prefixes int
	Fetched  int
	Cached   int
}

// NameFailed reports whether name's shard could not be read.
func (a Answer) NameFailed(base, name string) bool {
	return a.Failed[osvshardkey.Canon(base, name)]
}

// ErrBadQuery is a query the walk refuses outright (a descriptor that does
// not validate): nothing was fetched.
var ErrBadQuery = errors.New("osvshard: bad query")

// Run walks one ecosystem's shards for q.Names.
func (l Lookup) Run(ctx context.Context, q Query) (Answer, error) {
	d := q.Set
	if err := d.Validate(); err != nil {
		return Answer{}, fmt.Errorf("%w: %w", ErrBadQuery, err)
	}
	ans := Answer{Set: d.Set, Ecosystem: d.Ecosystem, Epoch: d.Epoch, Failed: map[string]bool{}}
	// Canonical name -> prefix; prefix -> the canonical names under it.
	want := map[string]bool{}
	byPrefix := map[uint32][]string{}
	for _, n := range q.Names {
		if n == "" {
			continue
		}
		c := osvshardkey.Canon(d.Base, n)
		if want[c] {
			continue
		}
		want[c] = true
		p := osvshardkey.PrefixOf(d.Base, n, d.Bits)
		byPrefix[p] = append(byPrefix[p], c)
	}
	ans.Prefixes = len(byPrefix)
	if len(byPrefix) == 0 {
		return ans, nil
	}
	fail := func(p uint32) {
		for _, c := range byPrefix[p] {
			ans.Failed[c] = true
		}
	}
	// Index files, one per distinct first byte.
	byByte := map[int][]uint32{}
	for p := range byPrefix {
		b := osvshardkey.FirstByte(p, d.Bits)
		byByte[b] = append(byByte[b], p)
	}
	firstBytes := make([]int, 0, len(byByte))
	for b := range byByte {
		firstBytes = append(firstBytes, b)
	}
	sort.Ints(firstBytes)
	type shardJob struct {
		ref    osvshardkey.ShardRef
		prefix uint32
	}
	var jobs []shardJob
	var mu sync.Mutex
	count := func(fromCache bool) {
		mu.Lock()
		defer mu.Unlock()
		if fromCache {
			ans.Cached++
		} else {
			ans.Fetched++
		}
	}
	for _, b := range firstBytes {
		ref, ok := d.IndexFor(b)
		if !ok {
			// No shard starts with this byte: no record keys under these
			// prefixes, so nothing to fetch and nothing failed.
			continue
		}
		raw, cached, err := l.object(ctx, osvshardkey.IndexPath(d.Set, ref.Object), ref.Object, ref.Size)
		if err != nil {
			for _, p := range byByte[b] {
				fail(p)
			}
			continue
		}
		count(cached)
		idx, err := osvshardkey.DecodeIndex(raw, d, b)
		if err != nil {
			for _, p := range byByte[b] {
				fail(p)
			}
			continue
		}
		ps := byByte[b]
		sort.Slice(ps, func(i, j int) bool { return ps[i] < ps[j] })
		for _, p := range ps {
			if s, ok := idx.ShardFor(p); ok {
				jobs = append(jobs, shardJob{ref: s, prefix: p})
			}
		}
	}
	// Shards, at most InFlight at once.
	n := l.InFlight
	if n <= 0 {
		n = DefaultInFlight
	}
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	results := make([][]json.RawMessage, len(jobs))
	failed := make([]bool, len(jobs))
	for i, j := range jobs {
		wg.Add(1)
		go func(i int, j shardJob) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				failed[i] = true
				return
			}
			defer func() { <-sem }()
			raw, cached, err := l.object(ctx, osvshardkey.ShardPath(d.Set, j.ref.Object), j.ref.Object, j.ref.Size)
			if err != nil {
				failed[i] = true
				return
			}
			recs, err := decodeShard(raw, d.Base, want)
			if err != nil {
				failed[i] = true
				return
			}
			count(cached)
			results[i] = recs
		}(i, j)
	}
	wg.Wait()
	var all []json.RawMessage
	for i, j := range jobs {
		if failed[i] {
			fail(j.prefix)
			continue
		}
		all = append(all, results[i]...)
	}
	recs, err := mergeRecords(all)
	if err != nil {
		// Unmergeable data from verified shards is the publisher's fault:
		// nothing of this set is trusted.
		for p := range byPrefix {
			fail(p)
		}
		return ans, nil
	}
	ans.Records = recs
	return ans, nil
}

// object returns one verified object: from the cache when it holds it,
// else from the network, verified against its digest and size, then
// cached.
func (l Lookup) object(ctx context.Context, rel, sum string, size int64) ([]byte, bool, error) {
	if b, ok := l.Cache.get(rel, sum, size); ok {
		return b, true, nil
	}
	if l.Fetch == nil {
		return nil, false, errors.New("osvshard: offline and not cached")
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	b, err := l.Fetch.Fetch(ctx, rel, size)
	if err != nil {
		return nil, false, err
	}
	if int64(len(b)) != size || hashOf(b) != sum {
		return nil, false, fmt.Errorf("osvshard: %s does not match its digest", rel)
	}
	_ = l.Cache.put(rel, b)
	return b, false, nil
}

// shardRecord is what decodeShard reads of a record to filter it.
type shardRecord struct {
	ID       string `json:"id"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
	} `json:"affected"`
}

// decodeShard reads a shard (gzip of a JSON array of records) and keeps
// the records with an affected entry of base whose canonical name is
// wanted. A record with an invalid id refuses the shard.
func decodeShard(gz []byte, base string, want map[string]bool) ([]json.RawMessage, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, err
	}
	defer func() { _ = zr.Close() }()
	lr := &io.LimitedReader{R: zr, N: MaxShardJSONBytes + 1}
	dec := json.NewDecoder(lr)
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '[' {
		return nil, errors.New("osvshard: a shard is not a JSON array")
	}
	var out []json.RawMessage
	for dec.More() {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		var r shardRecord
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, err
		}
		if !osvdb.ValidID(r.ID) {
			return nil, fmt.Errorf("osvshard: record id %q", r.ID)
		}
		for _, a := range r.Affected {
			if osvshardkey.Base(a.Package.Ecosystem) == base && want[osvshardkey.Canon(base, a.Package.Name)] {
				out = append(out, raw)
				break
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if lr.N <= 0 {
		return nil, errors.New("osvshard: a shard is over its decompressed cap")
	}
	return out, nil
}
