package secrulepack

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"sync"
	"unicode/utf8"
)

// floorFS is the embedded floor: the pack this binary was built with.
//
//go:embed floor/observer-code
var floorFS embed.FS

const floorRoot = "floor/observer-code"

var floorOnce = sync.OnceValues(func() (*Pack, error) {
	files := map[string][]byte{}
	err := fs.WalkDir(floorFS, floorRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := floorFS.ReadFile(p)
		if err != nil {
			return err
		}
		files[p[len(floorRoot)+1:]] = b
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("secrulepack.Floor: %w", err)
	}
	return Parse(files)
})

// Floor returns the embedded pack, validated once. It is the floor: an
// imported pack replaces it only when newer (Choose).
func Floor() (*Pack, error) { return floorOnce() }

// The bundle form: one JSON file carrying every file of a pack, the
// artifact of the security.rule_pack content kind (a content entry is a
// single base name, so the pack's tree travels as one file).
const (
	// BundleSchema is the bundle's schema.
	BundleSchema = "sbo.code-rule-pack-bundle.v1"
	// BundleName is the artifact's name in a security.rule_pack manifest.
	BundleName = "observer-code-pack.json"
	// MaxBundleBytes caps one bundle (the pack cap plus JSON overhead).
	MaxBundleBytes = MaxPackBytes + MaxPackBytes/2
)

type bundle struct {
	Schema string            `json:"schema"`
	Files  map[string]string `json:"files"`
}

// EncodeBundle writes a pack's files as a bundle.
func EncodeBundle(p *Pack) ([]byte, error) {
	if p == nil {
		return nil, errors.New("secrulepack.EncodeBundle: no pack")
	}
	b := bundle{Schema: BundleSchema, Files: map[string]string{}}
	names := make([]string, 0, len(p.files))
	for n := range p.files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		b.Files[n] = string(p.files[n])
	}
	out, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("secrulepack.EncodeBundle: %w", err)
	}
	return out, nil
}

// DecodeBundle reads a bundle and validates the pack it carries.
func DecodeBundle(raw []byte) (*Pack, error) {
	if len(raw) > MaxBundleBytes {
		return nil, invalid("bundle of %d bytes over the cap", len(raw))
	}
	var b bundle
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return nil, invalid("bundle: %v", err)
	}
	if b.Schema != BundleSchema {
		return nil, invalid("bundle schema %q", b.Schema)
	}
	files := make(map[string][]byte, len(b.Files))
	for n, s := range b.Files {
		if !utf8.ValidString(s) {
			return nil, invalid("bundle file %q is not UTF-8", n)
		}
		files[n] = []byte(s)
	}
	return Parse(files)
}
