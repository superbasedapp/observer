package contentchan

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// memSource serves one envelope and its artifacts and counts the reads.
type memSource struct {
	env       []byte
	tag       string
	arts      map[string][]byte
	manifests int
	artifacts map[string]int
}

func (m *memSource) FetchManifest(_ context.Context, _ content.Kind, etag string) ([]byte, string, error) {
	m.manifests++
	if etag != "" && etag == m.tag {
		return nil, "", ErrNotModified
	}
	return m.env, m.tag, nil
}

func (m *memSource) FetchArtifact(_ context.Context, _ content.Kind, e content.Entry, w io.Writer) error {
	if m.artifacts == nil {
		m.artifacts = map[string]int{}
	}
	m.artifacts[e.Name]++
	b, ok := m.arts[e.Name]
	if !ok {
		return errors.New("not served")
	}
	_, err := w.Write(b)
	return err
}

func TestFetchInstall(t *testing.T) {
	pub, priv := key(11)
	tr := Trust{VendorKeys: []ed25519.PublicKey{pub}}
	st := Store{Root: t.TempDir(), Now: func() time.Time { return now0 }}
	ctx := context.Background()
	osvSet := func(v int64, files map[string][]byte) *memSource {
		m := manifest(v, files)
		m.Kind = content.OSVExport
		return &memSource{env: envelope(t, m, priv), tag: fmt.Sprintf(`"v%d"`, v), arts: files}
	}
	npm1, pypi := []byte("npm v1"), []byte("pypi")
	src := osvSet(1, map[string][]byte{"npm.zip": npm1, "PyPI.zip": pypi})
	res, err := st.FetchInstall(ctx, content.OSVExport, tr, src, "")
	if err != nil || res.Fetched != 2 || res.ETag != `"v1"` {
		t.Fatalf("first: %+v %v", res, err)
	}
	// The kept ETag answers not modified.
	if res, err := st.FetchInstall(ctx, content.OSVExport, tr, src, `"v1"`); err != nil || !res.Unchanged || res.ETag != `"v1"` {
		t.Fatalf("not modified: %+v %v", res, err)
	}
	// The same envelope without an ETag reads no artifact.
	if res, err := st.FetchInstall(ctx, content.OSVExport, tr, src, ""); err != nil || !res.Unchanged || src.artifacts["npm.zip"] != 1 {
		t.Fatalf("unchanged: %+v %v %v", res, err, src.artifacts)
	}
	// A new version changing npm only fetches npm and reuses PyPI.
	src2 := osvSet(2, map[string][]byte{"npm.zip": []byte("npm v2"), "PyPI.zip": pypi})
	res, err = st.FetchInstall(ctx, content.OSVExport, tr, src2, `"v1"`)
	if err != nil || res.Fetched != 1 || res.Reused != 1 || src2.artifacts["PyPI.zip"] != 0 {
		t.Fatalf("npm-only change: %+v %v %v", res, err, src2.artifacts)
	}
	// An envelope signed by another key is refused, recorded, and keeps v2.
	_, other := key(12)
	m := manifest(3, map[string][]byte{"npm.zip": []byte("npm v3")})
	m.Kind = content.OSVExport
	bad := &memSource{env: envelope(t, m, other), tag: `"v3"`, arts: map[string][]byte{"npm.zip": []byte("npm v3")}}
	res, err = st.FetchInstall(ctx, content.OSVExport, tr, bad, `"v2"`)
	if err == nil || res.State.Accepted == nil || res.State.Accepted.ManifestVersion != 2 || res.State.LastFailure == "" || len(bad.artifacts) != 0 {
		t.Fatalf("refused: %+v %v", res, err)
	}
	// A failed artifact read installs nothing.
	src4 := osvSet(4, map[string][]byte{"npm.zip": []byte("npm v4")})
	delete(src4.arts, "npm.zip")
	if _, err := st.FetchInstall(ctx, content.OSVExport, tr, src4, ""); err == nil {
		t.Fatal("a failed artifact must fail the fetch")
	}
	if s, _ := st.State(content.OSVExport); s.Accepted.ManifestVersion != 2 {
		t.Fatalf("a failed fetch changed the accepted version: %+v", s)
	}
}
