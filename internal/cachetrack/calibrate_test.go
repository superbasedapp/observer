package cachetrack

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestCalibrate_EmitsOneEntryPerBlock pins the JSON-Lines shape +
// the per-block emit cadence: every block fed to ObserveTurn
// produces exactly one log line.
func TestCalibrate_EmitsOneEntryPerBlock(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	e := NewEngine(8)
	e.EnableCalibrateSink(&buf)

	now := time.Date(2026, 6, 9, 22, 0, 0, 0, time.UTC)
	in := ObserveInput{
		SessionID: "sA",
		Model:     "claude-opus-4-8",
		Scope:     "default",
		Tier:      TierProxy,
		Now:       now,
		APITurnID: 42,
		Blocks: []ObserveBlock{
			{Level: LevelTools, Kind: "tool", CanonicalBytes: []byte(`{"description":"r","name":"Read"}`), RawBytes: []byte(`{"name":"Read","description":"r"}`)},
			{Level: LevelSystem, Kind: "text", CanonicalBytes: []byte(`{"text":"hi","type":"text"}`), RawBytes: []byte(`{"type":"text","text":"hi"}`)},
			{Level: LevelMessage, Kind: "text", CanonicalBytes: []byte(`{"content":"q","role":"user"}`), RawBytes: []byte(`{"role":"user","content":"q"}`)},
		},
	}
	e.ObserveTurn(in)

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d entries, want 3:\n%s", len(lines), buf.String())
	}

	var got []CalibrateEntry
	for _, ln := range lines {
		var entry CalibrateEntry
		if err := json.Unmarshal([]byte(ln), &entry); err != nil {
			t.Fatalf("parse %q: %v", ln, err)
		}
		got = append(got, entry)
	}

	if got[0].Level != "tools" || got[0].Seq != 0 || got[0].APITurnID != 42 {
		t.Errorf("entry 0: %+v", got[0])
	}
	if got[0].CanonPrefix == "" {
		t.Errorf("tools entry must carry canon_prefix; got empty")
	}
	if got[1].Level != "system" || got[1].CanonPrefix == "" {
		t.Errorf("system entry: prefix=%q level=%q", got[1].CanonPrefix, got[1].Level)
	}
	if got[2].Level != "message" || got[2].CanonPrefix != "" {
		t.Errorf("message entry MUST be hash-only (no canon_prefix); got %q", got[2].CanonPrefix)
	}
	// sha_raw vs sha_canon: the RawBytes and CanonicalBytes
	// differ in the fixtures (top-level keys reordered), so the
	// SHAs must differ too.
	if got[0].ShaRaw == got[0].ShaCanon {
		t.Errorf("entry 0: sha_raw == sha_canon for differing inputs (expected differ)")
	}
}

// TestCalibrate_AutoStopAfterCap pins the auto-stop behavior:
// once CalibrateBlockCap blocks have been emitted, the sink
// stops getting new entries even if more blocks come through.
func TestCalibrate_AutoStopAfterCap(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	e := NewEngine(8)
	e.EnableCalibrateSink(&buf)

	// Emit two turns that together exceed the cap: 150 + 100 = 250
	// blocks, cap is 200.
	mkBlocks := func(n int) []ObserveBlock {
		blocks := make([]ObserveBlock, n)
		for i := range blocks {
			blocks[i] = ObserveBlock{
				Level:          LevelTools,
				Kind:           "tool",
				CanonicalBytes: []byte(`{"x":1}`),
				RawBytes:       []byte(`{"x":1}`),
			}
		}
		return blocks
	}
	e.ObserveTurn(ObserveInput{SessionID: "s1", Model: "m", Now: time.Now().UTC(), Blocks: mkBlocks(150)})
	e.ObserveTurn(ObserveInput{SessionID: "s2", Model: "m", Now: time.Now().UTC(), Blocks: mkBlocks(100)})

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != CalibrateBlockCap {
		t.Fatalf("got %d entries; want exactly CalibrateBlockCap=%d", len(lines), CalibrateBlockCap)
	}
}

// TestCalibrate_NilSinkNoOp pins that ObserveTurn does not panic
// when the sidecar is off (default).
func TestCalibrate_NilSinkNoOp(t *testing.T) {
	t.Parallel()
	e := NewEngine(8)
	// CalibrateSink left nil.
	e.ObserveTurn(ObserveInput{
		SessionID: "sA", Model: "m", Now: time.Now().UTC(),
		Blocks: []ObserveBlock{
			{Level: LevelTools, Kind: "tool", CanonicalBytes: []byte(`{"x":1}`), RawBytes: []byte(`{"x":1}`)},
		},
	})
}

// TestCalibrate_PrefixTruncation pins the bounded canonical-bytes
// prefix at CalibrateTextPrefix chars for tools+system levels.
func TestCalibrate_PrefixTruncation(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	e := NewEngine(8)
	e.EnableCalibrateSink(&buf)

	big := make([]byte, CalibrateTextPrefix*3)
	for i := range big {
		big[i] = 'x'
	}
	e.ObserveTurn(ObserveInput{
		SessionID: "sA", Model: "m", Now: time.Now().UTC(),
		Blocks: []ObserveBlock{
			{Level: LevelTools, Kind: "tool", CanonicalBytes: big, RawBytes: big},
		},
	})
	var entry CalibrateEntry
	if err := json.Unmarshal([]byte(strings.TrimRight(buf.String(), "\n")), &entry); err != nil {
		t.Fatal(err)
	}
	if len(entry.CanonPrefix) != CalibrateTextPrefix {
		t.Errorf("CanonPrefix len = %d, want %d", len(entry.CanonPrefix), CalibrateTextPrefix)
	}
	// len_canon must be the FULL canonical-bytes length, not
	// the prefix length — the diff workflow uses len_canon as
	// the size signal.
	if entry.LenCanon != len(big) {
		t.Errorf("LenCanon = %d, want %d (full len, not prefix)", entry.LenCanon, len(big))
	}
}

// TestCalibrate_ShaShape pins the sha encoding: hex-encoded
// sha256, length 64.
func TestCalibrate_ShaShape(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	e := NewEngine(8)
	e.EnableCalibrateSink(&buf)
	raw := []byte(`{"x":1}`)
	canon := []byte(`{"x":1}`)
	e.ObserveTurn(ObserveInput{
		SessionID: "sA", Model: "m", Now: time.Now().UTC(),
		Blocks: []ObserveBlock{{Level: LevelTools, Kind: "tool", CanonicalBytes: canon, RawBytes: raw}},
	})
	var entry CalibrateEntry
	if err := json.Unmarshal([]byte(strings.TrimRight(buf.String(), "\n")), &entry); err != nil {
		t.Fatal(err)
	}
	wantRawSum := sha256.Sum256(raw)
	wantCanonSum := sha256.Sum256(canon)
	if entry.ShaRaw != hex.EncodeToString(wantRawSum[:]) {
		t.Errorf("ShaRaw mismatch: got %q", entry.ShaRaw)
	}
	if entry.ShaCanon != hex.EncodeToString(wantCanonSum[:]) {
		t.Errorf("ShaCanon mismatch: got %q", entry.ShaCanon)
	}
}
