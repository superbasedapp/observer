package secrulepack

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

// setManifestKey sets (value non-nil) or removes (nil) a top-level manifest
// key of a pack's files.
func setManifestKey(t *testing.T, files map[string][]byte, key string, value []byte) {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(files[ManifestFile], &m); err != nil {
		t.Fatal(err)
	}
	delete(m, key)
	if value != nil {
		m[key] = value
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	files[ManifestFile] = b
}

// searchOnly removes every taint-mode rule from a pack's files and manifest.
func searchOnly(t *testing.T, files map[string][]byte) {
	t.Helper()
	var man struct {
		Rules []json.RawMessage `json:"rules"`
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(files[ManifestFile], &m); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(m["rules"], &man.Rules); err != nil {
		t.Fatal(err)
	}
	var keep []json.RawMessage
	for _, raw := range man.Rules {
		var r struct {
			File string `json:"file"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(files[r.File], []byte("mode: taint")) {
			delete(files, r.File)
			continue
		}
		keep = append(keep, raw)
	}
	b, err := json.Marshal(keep)
	if err != nil {
		t.Fatal(err)
	}
	setManifestKey(t, files, "rules", b)
}

// TestTaintIntrafileField is the manifest field's table: its decoding, the
// validator's refusals and the engine flags the pack then declares.
func TestTaintIntrafileField(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*testing.T, map[string][]byte)
		wantErr string
		want    []string
	}{
		{"absent: an older pack keeps today's flags", func(t *testing.T, f map[string][]byte) { setManifestKey(t, f, "taint_intrafile", nil) }, "", nil},
		{"false", func(t *testing.T, f map[string][]byte) { setManifestKey(t, f, "taint_intrafile", []byte("false")) }, "", nil},
		{"true", func(t *testing.T, f map[string][]byte) { setManifestKey(t, f, "taint_intrafile", []byte("true")) }, "", []string{FlagTaintIntrafile}},
		{"not a bool", func(t *testing.T, f map[string][]byte) { setManifestKey(t, f, "taint_intrafile", []byte(`"yes"`)) }, "taint_intrafile", nil},
		{"a number", func(t *testing.T, f map[string][]byte) { setManifestKey(t, f, "taint_intrafile", []byte("1")) }, "taint_intrafile", nil},
		{"true with no taint rule", func(t *testing.T, f map[string][]byte) {
			searchOnly(t, f)
			setManifestKey(t, f, "taint_intrafile", []byte("true"))
		}, "no rule is taint mode", nil},
		{"false with no taint rule", func(t *testing.T, f map[string][]byte) {
			searchOnly(t, f)
			setManifestKey(t, f, "taint_intrafile", []byte("false"))
		}, "", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := floorFiles(t)
			c.mutate(t, f)
			p, err := Parse(f)
			if c.wantErr != "" {
				if err == nil || !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("Parse = %v, want an ErrInvalid naming %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := p.EngineFlags(); !slices.Equal(got, c.want) {
				t.Errorf("EngineFlags = %v, want %v", got, c.want)
			}
			// The field is part of the digest (it is in pack.json), and a
			// signed-channel bundle carries it.
			b, err := EncodeBundle(p)
			if err != nil {
				t.Fatal(err)
			}
			back, err := DecodeBundle(b)
			if err != nil {
				t.Fatalf("DecodeBundle: %v", err)
			}
			if back.Manifest.TaintIntrafile != p.Manifest.TaintIntrafile || back.Digest() != p.Digest() {
				t.Errorf("the bundle changed the pack: taint %v/%v digest %s/%s", back.Manifest.TaintIntrafile, p.Manifest.TaintIntrafile, back.Digest(), p.Digest())
			}
		})
	}
}

// TestTaintIntrafileChangesTheDigest pins that flipping the field is a
// different pack (a pack measured without the flag is not the pack measured
// with it).
func TestTaintIntrafileChangesTheDigest(t *testing.T) {
	off, on := floorFiles(t), floorFiles(t)
	setManifestKey(t, off, "taint_intrafile", nil)
	setManifestKey(t, on, "taint_intrafile", []byte("true"))
	a, err := Parse(off)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse(on)
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest() == b.Digest() {
		t.Fatal("the pack digest ignores taint_intrafile")
	}
}

// TestEngineFlagsOfNoPack: a nil pack declares nothing.
func TestEngineFlagsOfNoPack(t *testing.T) {
	var p *Pack
	if got := p.EngineFlags(); got != nil {
		t.Fatalf("EngineFlags of no pack = %v", got)
	}
}

// TestTaintRulesAreReadFromTheRuleFiles: the taint-mode rules the
// intrafile taint pass runs come from each rule file's mode, not from a
// list: every one of them is a taint rule file, every other rule is not,
// and a search-only pack has none.
func TestTaintRulesAreReadFromTheRuleFiles(t *testing.T) {
	files := floorFiles(t)
	p, err := Parse(files)
	if err != nil {
		t.Fatal(err)
	}
	taint := p.TaintRules()
	if len(taint) == 0 {
		t.Fatal("the floor pack has no taint rule")
	}
	ids := map[string]bool{}
	for _, r := range taint {
		ids[r.ID] = true
		if !bytes.Contains(files[r.File], []byte("mode: taint")) {
			t.Errorf("%s is listed as a taint rule but its file is not taint mode", r.ID)
		}
	}
	for _, r := range p.Manifest.Rules {
		isTaint := bytes.Contains(files[r.File], []byte("mode: taint"))
		if isTaint != ids[r.ID] || isTaint != p.IsTaintRule(r.ID) {
			t.Errorf("%s: taint mode %v, listed %v, IsTaintRule %v", r.ID, isTaint, ids[r.ID], p.IsTaintRule(r.ID))
		}
	}
	searchOnly(t, files)
	s, err := Parse(files)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.TaintRules(); got != nil {
		t.Fatalf("a search-only pack lists taint rules %v", got)
	}
	var none *Pack
	if none.TaintRules() != nil || none.IsTaintRule("x") {
		t.Fatal("a nil pack lists taint rules")
	}
}
