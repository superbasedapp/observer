package osvshardkey

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// The wire format's schemas and caps (plan section 13.11 item 4).
const (
	// SetSchema is a set descriptor's schema.
	SetSchema = "sbo.osv-shard-set.v1"
	// IndexSchema is an index file's schema.
	IndexSchema = "sbo.osv-shard-index.v1"
	// ModeStrip is the one publishing mode: a shard carries each record with
	// only the affected entries whose names hash into it.
	ModeStrip = "strip"

	// MaxShardBytes caps one shard object (its gzip bytes). More bits do not
	// shrink one package's shard, and the largest is the kernel-family one:
	// 14.6 MiB for Ubuntu 20.04 on the 2026-11-04 RM-1 run (RM-0 measured
	// 10.5 MB), so the cap is twice RM-0's 16 MiB to leave headroom before
	// upstream growth would fail the kind; an npm shard is about 419 KB.
	MaxShardBytes = 32 << 20
	// MaxIndexBytes caps one index file. At MaxBits an index file lists at
	// most 256 shards, about 33 KB.
	MaxIndexBytes = 64 << 10
	// MaxSetBytes caps one set descriptor (256 index references, about
	// 25 KB).
	MaxSetBytes = 256 << 10
	// IndexFiles is the number of first key bytes, so the most index files
	// one set can have.
	IndexFiles = 256
)

// SetDescriptor is one shard set's descriptor, <Set>.set.json: an entry of
// the signed security.osv_shards content manifest, so its digest is signed.
type SetDescriptor struct {
	Schema string `json:"schema"`
	// Set is the set's name: the artifact base the other OSV kinds use for
	// the same data (osvdb.ArtifactBase for a language ecosystem,
	// osvdb.OSRelease.Artifact for a release: "npm", "GitHub-Actions",
	// "Ubuntu-24.04-LTS").
	Set string `json:"set"`
	// Ecosystem is the OSV ecosystem the set answers ("npm", "Debian:12";
	// for the Red Hat family the release's prefix,
	// "Red Hat:enterprise_linux:9::").
	Ecosystem string `json:"ecosystem"`
	// Base is the base ecosystem every key of the set was hashed under.
	Base string `json:"base"`
	// Bits is the set's prefix length.
	Bits int `json:"bits"`
	// Mode is ModeStrip.
	Mode string `json:"mode"`
	// Epoch counts the set's content changes; it moves only when the set's
	// data changed and never goes backwards.
	Epoch int64 `json:"epoch"`
	// Records is the number of OSV records placed in at least one shard;
	// Shards the number of shard objects, and ShardBytes their total size.
	Records    int   `json:"records"`
	Shards     int   `json:"shards"`
	ShardBytes int64 `json:"shard_bytes"`
	// MaxShardBytes and MaxIndexBytes are the caps the publisher held the
	// set to; a reader enforces the smaller of these and its own.
	MaxShardBytes int64 `json:"max_shard_bytes"`
	MaxIndexBytes int64 `json:"max_index_bytes"`
	// Index lists the index files, one per first key byte that has a shard,
	// in byte order.
	Index []IndexRef `json:"index"`
}

// IndexRef is one index file of a set.
type IndexRef struct {
	// Byte is the first key byte the index file covers.
	Byte int `json:"byte"`
	// Object is the index file's sha256 (hex), its name; Size its length.
	Object string `json:"object"`
	Size   int64  `json:"size"`
}

// IndexFile is one index file, <Set>/index/<sha256>.json.
type IndexFile struct {
	Schema string `json:"schema"`
	Set    string `json:"set"`
	Bits   int    `json:"bits"`
	// Byte is the first key byte of every prefix listed.
	Byte   int        `json:"byte"`
	Shards []ShardRef `json:"shards"`
}

// ShardRef is one shard of an index file.
type ShardRef struct {
	// Prefix is the shard's prefix: the first Bits bits of every key whose
	// records it holds.
	Prefix uint32 `json:"prefix"`
	// Object is the shard's sha256 (hex), its name; Size its length.
	Object string `json:"object"`
	Size   int64  `json:"size"`
	// Records is how many records the shard holds.
	Records int `json:"records"`
}

// SetFile is a set descriptor's file name in the content kind's directory.
func SetFile(set string) string { return set + ".set.json" }

// IndexPath is an index file's object path in the shard bucket.
func IndexPath(set, object string) string { return set + "/index/" + object + ".json" }

// ShardPath is a shard's object path in the shard bucket.
func ShardPath(set, object string) string { return set + "/obj/" + object + ".json.gz" }

// ValidSetName reports a set name that is one path element and one plain
// artifact name: a letter or digit, then up to 63 letters, digits, '.', '-'
// or '_', never "..".
func ValidSetName(set string) bool {
	if set == "" || len(set) > 64 || strings.Contains(set, "..") {
		return false
	}
	for i := 0; i < len(set); i++ {
		c := set[i]
		alnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if i == 0 && !alnum {
			return false
		}
		if !alnum && c != '.' && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// ErrFormat wraps every refusal of a descriptor or index file.
var ErrFormat = errors.New("osvshardkey: malformed shard object")

func bad(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrFormat, fmt.Sprintf(format, a...))
}

// Validate checks a descriptor's structure.
func (d SetDescriptor) Validate() error {
	if d.Schema != SetSchema {
		return bad("unknown set schema %q", d.Schema)
	}
	if !ValidSetName(d.Set) {
		return bad("set name %q", d.Set)
	}
	if d.Ecosystem == "" || d.Base == "" || Base(d.Ecosystem) != d.Base {
		return bad("set %s: ecosystem %q and base %q disagree", d.Set, d.Ecosystem, d.Base)
	}
	if !ValidBits(d.Bits) {
		return bad("set %s: bits %d (want %d to %d)", d.Set, d.Bits, MinBits, MaxBits)
	}
	if d.Mode != ModeStrip {
		return bad("set %s: mode %q", d.Set, d.Mode)
	}
	if d.Epoch < 0 || d.Records < 0 || d.Shards < 0 || d.ShardBytes < 0 {
		return bad("set %s: negative counter", d.Set)
	}
	if d.MaxShardBytes <= 0 || d.MaxShardBytes > MaxShardBytes || d.MaxIndexBytes <= 0 || d.MaxIndexBytes > MaxIndexBytes {
		return bad("set %s: caps %d/%d out of range", d.Set, d.MaxShardBytes, d.MaxIndexBytes)
	}
	if len(d.Index) > IndexFiles {
		return bad("set %s: %d index files", d.Set, len(d.Index))
	}
	for i, r := range d.Index {
		if r.Byte < 0 || r.Byte >= IndexFiles || (i > 0 && d.Index[i-1].Byte >= r.Byte) {
			return bad("set %s: index byte %d out of order", d.Set, r.Byte)
		}
		if !isHexSHA256(r.Object) {
			return bad("set %s: index object %q", d.Set, r.Object)
		}
		if r.Size <= 0 || r.Size > d.MaxIndexBytes {
			return bad("set %s: index file of %d bytes", d.Set, r.Size)
		}
	}
	if (d.Shards == 0) != (len(d.Index) == 0) {
		return bad("set %s: %d shards and %d index files", d.Set, d.Shards, len(d.Index))
	}
	return nil
}

// IndexFor returns the index reference that covers first key byte b.
func (d SetDescriptor) IndexFor(b int) (IndexRef, bool) {
	for _, r := range d.Index {
		if r.Byte == b {
			return r, true
		}
	}
	return IndexRef{}, false
}

// Validate checks an index file against the descriptor that named it and
// the first key byte it was fetched for.
func (f IndexFile) Validate(d SetDescriptor, b int) error {
	if f.Schema != IndexSchema {
		return bad("unknown index schema %q", f.Schema)
	}
	if f.Set != d.Set || f.Bits != d.Bits || f.Byte != b {
		return bad("index file names set %q bits %d byte %d, want %q %d %d", f.Set, f.Bits, f.Byte, d.Set, d.Bits, b)
	}
	if len(f.Shards) == 0 {
		return bad("index file of set %s byte %d lists no shard", d.Set, b)
	}
	limit := uint32(1) << uint(d.Bits)
	for i, s := range f.Shards {
		if s.Prefix >= limit || FirstByte(s.Prefix, d.Bits) != b || (i > 0 && f.Shards[i-1].Prefix >= s.Prefix) {
			return bad("set %s byte %d: prefix %d out of place", d.Set, b, s.Prefix)
		}
		if !isHexSHA256(s.Object) {
			return bad("set %s: shard object %q", d.Set, s.Object)
		}
		if s.Size <= 0 || s.Size > d.MaxShardBytes || s.Records <= 0 {
			return bad("set %s prefix %d: shard of %d bytes and %d records", d.Set, s.Prefix, s.Size, s.Records)
		}
	}
	return nil
}

// ShardFor returns the shard of prefix p in an index file.
func (f IndexFile) ShardFor(p uint32) (ShardRef, bool) {
	for _, s := range f.Shards {
		if s.Prefix == p {
			return s, true
		}
	}
	return ShardRef{}, false
}

// EncodeSet is a descriptor's bytes: validated, compact JSON of the struct
// (the field order is the struct's, so the same descriptor always gives the
// same bytes).
func EncodeSet(d SetDescriptor) ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("osvshardkey.EncodeSet: %w", err)
	}
	if len(b) > MaxSetBytes {
		return nil, bad("set %s: descriptor is %d bytes, over %d", d.Set, len(b), MaxSetBytes)
	}
	return b, nil
}

// EncodeIndex is an index file's bytes, checked against its descriptor's
// fields (Set, Bits and the caps) and its cap.
func EncodeIndex(f IndexFile, d SetDescriptor) ([]byte, error) {
	if err := f.Validate(d, f.Byte); err != nil {
		return nil, err
	}
	b, err := json.Marshal(f)
	if err != nil {
		return nil, fmt.Errorf("osvshardkey.EncodeIndex: %w", err)
	}
	if int64(len(b)) > d.MaxIndexBytes {
		return nil, bad("set %s byte %d: index file is %d bytes, over %d", d.Set, f.Byte, len(b), d.MaxIndexBytes)
	}
	return b, nil
}

// DecodeSet parses and validates a descriptor (unknown fields refused).
func DecodeSet(data []byte) (SetDescriptor, error) {
	var d SetDescriptor
	if len(data) == 0 || len(data) > MaxSetBytes {
		return d, bad("descriptor is %d bytes", len(data))
	}
	if err := decodeStrict(data, &d); err != nil {
		return SetDescriptor{}, bad("descriptor: %v", err)
	}
	if err := d.Validate(); err != nil {
		return SetDescriptor{}, err
	}
	return d, nil
}

// DecodeIndex parses an index file and validates it against its descriptor
// and the first key byte it was fetched for.
func DecodeIndex(data []byte, d SetDescriptor, b int) (IndexFile, error) {
	var f IndexFile
	if len(data) == 0 || int64(len(data)) > d.MaxIndexBytes {
		return f, bad("index file is %d bytes", len(data))
	}
	if err := decodeStrict(data, &f); err != nil {
		return IndexFile{}, bad("index file: %v", err)
	}
	if err := f.Validate(d, b); err != nil {
		return IndexFile{}, err
	}
	return f, nil
}

func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

func isHexSHA256(s string) bool {
	if len(s) != 64 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// ObjectPath is one parsed object path of the shard bucket (IndexPath or
// ShardPath).
type ObjectPath struct {
	// Set is the set name; Index is true for an index file, false for a
	// shard; Object is the lower-case hex sha256 the path names.
	Set    string
	Index  bool
	Object string
}

// ParseObjectPath admits exactly the two object shapes of the shard bucket,
// <Set>/index/<sha256>.json and <Set>/obj/<sha256>.json.gz, with a valid
// set name and a lower-case hex digest. It is the ONE path check: the
// node's shard lane (shardnet), the org server's shard route and the
// managed node's org client all call it (lane RM-3), so no other spelling,
// query, dot segment or traversal can name an object anywhere.
func ParseObjectPath(p string) (ObjectPath, bool) {
	set, rest, ok := strings.Cut(p, "/")
	if !ok || !ValidSetName(set) {
		return ObjectPath{}, false
	}
	var out ObjectPath
	out.Set = set
	switch {
	case strings.HasPrefix(rest, "index/") && strings.HasSuffix(rest, ".json"):
		out.Index = true
		out.Object = strings.TrimSuffix(strings.TrimPrefix(rest, "index/"), ".json")
	case strings.HasPrefix(rest, "obj/") && strings.HasSuffix(rest, ".json.gz"):
		out.Object = strings.TrimSuffix(strings.TrimPrefix(rest, "obj/"), ".json.gz")
	default:
		return ObjectPath{}, false
	}
	if !isHexSHA256(out.Object) {
		return ObjectPath{}, false
	}
	return out, true
}

// ValidObjectPath reports a path ParseObjectPath admits.
func ValidObjectPath(p string) bool {
	_, ok := ParseObjectPath(p)
	return ok
}

// MaxObjectBytes is the cap of the object a path names: MaxIndexBytes for
// an index file, MaxShardBytes for a shard.
func (o ObjectPath) MaxObjectBytes() int64 {
	if o.Index {
		return MaxIndexBytes
	}
	return MaxShardBytes
}
