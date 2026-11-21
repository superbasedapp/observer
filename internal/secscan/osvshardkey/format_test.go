package osvshardkey

import (
	"errors"
	"strings"
	"testing"
)

const (
	digA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func goodSet() SetDescriptor {
	return SetDescriptor{
		Schema: SetSchema, Set: "npm", Ecosystem: "npm", Base: "npm", Bits: 13, Mode: ModeStrip,
		Epoch: 1, Records: 3, Shards: 2, ShardBytes: 300,
		MaxShardBytes: MaxShardBytes, MaxIndexBytes: MaxIndexBytes,
		Index: []IndexRef{{Byte: 0x12, Object: digA, Size: 100}, {Byte: 0x78, Object: digB, Size: 120}},
	}
}

func goodIndex() IndexFile {
	return IndexFile{
		Schema: IndexSchema, Set: "npm", Bits: 13, Byte: 0x78,
		Shards: []ShardRef{{Prefix: 0x78 << 5, Object: digA, Size: 10, Records: 1}, {Prefix: 0x78<<5 | 3, Object: digB, Size: 20, Records: 2}},
	}
}

func TestSetRoundTrip(t *testing.T) {
	d := goodSet()
	b, err := EncodeSet(d)
	if err != nil {
		t.Fatal(err)
	}
	again, err := EncodeSet(d)
	if err != nil || string(again) != string(b) {
		t.Fatal("EncodeSet is not deterministic")
	}
	got, err := DecodeSet(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Set != "npm" || len(got.Index) != 2 || got.Index[1].Object != digB {
		t.Fatalf("round trip: %+v", got)
	}
	if r, ok := got.IndexFor(0x78); !ok || r.Object != digB {
		t.Fatal("IndexFor")
	}
	if _, ok := got.IndexFor(0); ok {
		t.Fatal("IndexFor of a missing byte")
	}
}

func TestSetValidateRefuses(t *testing.T) {
	for name, mut := range map[string]func(*SetDescriptor){
		"schema":          func(d *SetDescriptor) { d.Schema = "x" },
		"set name":        func(d *SetDescriptor) { d.Set = "../npm" },
		"base mismatch":   func(d *SetDescriptor) { d.Base = "PyPI" },
		"bits low":        func(d *SetDescriptor) { d.Bits = 7 },
		"bits high":       func(d *SetDescriptor) { d.Bits = 17 },
		"mode":            func(d *SetDescriptor) { d.Mode = "whole" },
		"cap over":        func(d *SetDescriptor) { d.MaxShardBytes = MaxShardBytes + 1 },
		"index cap over":  func(d *SetDescriptor) { d.MaxIndexBytes = MaxIndexBytes + 1 },
		"index order":     func(d *SetDescriptor) { d.Index[0].Byte = 0x78 },
		"index byte":      func(d *SetDescriptor) { d.Index[1].Byte = 256 },
		"index digest":    func(d *SetDescriptor) { d.Index[0].Object = strings.ToUpper(digA) },
		"index size":      func(d *SetDescriptor) { d.Index[0].Size = MaxIndexBytes + 1 },
		"no index":        func(d *SetDescriptor) { d.Index = nil },
		"negative epoch":  func(d *SetDescriptor) { d.Epoch = -1 },
		"empty ecosystem": func(d *SetDescriptor) { d.Ecosystem = "" },
	} {
		d := goodSet()
		d.Index = append([]IndexRef(nil), d.Index...)
		mut(&d)
		if err := d.Validate(); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDecodeSetStrict(t *testing.T) {
	b, err := EncodeSet(goodSet())
	if err != nil {
		t.Fatal(err)
	}
	extra := strings.Replace(string(b), `{"schema"`, `{"extra":1,"schema"`, 1)
	if _, err := DecodeSet([]byte(extra)); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := DecodeSet(append(append([]byte{}, b...), []byte(` {}`)...)); err == nil {
		t.Fatal("trailing data accepted")
	}
	if _, err := DecodeSet(nil); err == nil {
		t.Fatal("empty accepted")
	}
}

func TestIndexRoundTrip(t *testing.T) {
	d, f := goodSet(), goodIndex()
	b, err := EncodeIndex(f, d)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeIndex(b, d, 0x78)
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := got.ShardFor(0x78<<5 | 3); !ok || s.Records != 2 {
		t.Fatal("ShardFor")
	}
	if _, ok := got.ShardFor(1); ok {
		t.Fatal("ShardFor of a missing prefix")
	}
	if _, err := DecodeIndex(b, d, 0x12); err == nil {
		t.Fatal("an index file fetched for another byte was accepted")
	}
	other := d
	other.Set = "PyPI"
	if _, err := DecodeIndex(b, other, 0x78); err == nil {
		t.Fatal("an index file of another set was accepted")
	}
}

func TestIndexValidateRefuses(t *testing.T) {
	for name, mut := range map[string]func(*IndexFile){
		"schema":        func(f *IndexFile) { f.Schema = "x" },
		"empty":         func(f *IndexFile) { f.Shards = nil },
		"wrong byte":    func(f *IndexFile) { f.Shards[0].Prefix = 0x12 << 5 },
		"too wide":      func(f *IndexFile) { f.Shards[1].Prefix = 1 << 13 },
		"order":         func(f *IndexFile) { f.Shards[1].Prefix = f.Shards[0].Prefix },
		"digest":        func(f *IndexFile) { f.Shards[0].Object = "zz" },
		"size":          func(f *IndexFile) { f.Shards[0].Size = MaxShardBytes + 1 },
		"zero size":     func(f *IndexFile) { f.Shards[0].Size = 0 },
		"no records":    func(f *IndexFile) { f.Shards[0].Records = 0 },
		"bits mismatch": func(f *IndexFile) { f.Bits = 12 },
	} {
		f := goodIndex()
		f.Shards = append([]ShardRef(nil), f.Shards...)
		mut(&f)
		if err := f.Validate(goodSet(), 0x78); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestPaths(t *testing.T) {
	if got := SetFile("GitHub-Actions"); got != "GitHub-Actions.set.json" {
		t.Errorf("SetFile = %q", got)
	}
	if got := ShardPath("npm", digA); got != "npm/obj/"+digA+".json.gz" {
		t.Errorf("ShardPath = %q", got)
	}
	if got := IndexPath("npm", digA); got != "npm/index/"+digA+".json" {
		t.Errorf("IndexPath = %q", got)
	}
	for _, ok := range []string{"npm", "GitHub-Actions", "crates.io", "Ubuntu-24.04-LTS", "Alpine-v3.20", "Red-Hat-EL9"} {
		if !ValidSetName(ok) {
			t.Errorf("ValidSetName(%q) = false", ok)
		}
	}
	for _, no := range []string{"", ".", "..", "a..b", "-npm", "a/b", `a\b`, "GitHub Actions", strings.Repeat("a", 65)} {
		if ValidSetName(no) {
			t.Errorf("ValidSetName(%q) = true", no)
		}
	}
}

// TestParseObjectPath pins the one object-path check (lane RM-3): the two
// bucket shapes parse, everything else (traversal, other suffixes, upper
// case or short digests, a bad set name, an empty path) is refused.
func TestParseObjectPath(t *testing.T) {
	d := strings.Repeat("ab", 32)
	cases := []struct {
		path  string
		ok    bool
		index bool
		max   int64
	}{
		{"npm/index/" + d + ".json", true, true, MaxIndexBytes},
		{"GitHub-Actions/obj/" + d + ".json.gz", true, false, MaxShardBytes},
		{"Ubuntu-24.04-LTS/obj/" + d + ".json.gz", true, false, MaxShardBytes},
		{"", false, false, 0},
		{"npm", false, false, 0},
		{"npm/index/" + d + ".json.gz", false, false, 0},
		{"npm/obj/" + d + ".json", false, false, 0},
		{"npm/obj/" + strings.ToUpper(d) + ".json.gz", false, false, 0},
		{"npm/obj/" + d[:62] + ".json.gz", false, false, 0},
		{"../obj/" + d + ".json.gz", false, false, 0},
		{"npm/obj/../" + d + ".json.gz", false, false, 0},
		{"npm/obj/" + d + ".json.gz?x=1", false, false, 0},
		{"/npm/obj/" + d + ".json.gz", false, false, 0},
		{"np m/obj/" + d + ".json.gz", false, false, 0},
	}
	for _, c := range cases {
		got, ok := ParseObjectPath(c.path)
		if ok != c.ok || ValidObjectPath(c.path) != c.ok {
			t.Errorf("%q: ok %v, want %v", c.path, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if got.Index != c.index || got.Object != d || got.MaxObjectBytes() != c.max {
			t.Errorf("%q: %+v (max %d)", c.path, got, got.MaxObjectBytes())
		}
	}
}
