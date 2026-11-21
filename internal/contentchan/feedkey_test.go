package contentchan

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// feedEnvelope signs m with the content-feed key (Signer "feed").
func feedEnvelope(t *testing.T, m content.Manifest, priv ed25519.PrivateKey) []byte {
	t.Helper()
	env, err := content.SignFeed(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := content.EncodeEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestFeedSignedSetNeedsFeedKeys: a feed-signed ClassFeed set installs (in
// memory and from files) and reloads only when the Trust carries the
// content-feed key; the vendor key alone refuses it.
func TestFeedSignedSetNeedsFeedKeys(t *testing.T) {
	vendorPub, _ := key(7)
	feedPub, feedPriv := key(8)
	cases := []struct {
		name string
		tr   Trust
		ok   bool
	}{
		{"vendor key only refuses", Trust{VendorKeys: []ed25519.PublicKey{vendorPub}}, false},
		{"feed key installs", Trust{VendorKeys: []ed25519.PublicKey{vendorPub}, FeedKeys: []ed25519.PublicKey{feedPub}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := Store{Root: t.TempDir(), Now: func() time.Time { return now0 }}
			// The install index, in memory.
			mal := []byte("malicious list")
			m := manifest(1, map[string][]byte{"malicious.txt": mal})
			_, err := st.Install(content.MaliciousPackages, feedEnvelope(t, m, feedPriv), map[string][]byte{"malicious.txt": mal}, c.tr)
			if (err == nil) != c.ok {
				t.Fatalf("Install: %v (want ok=%v)", err, c.ok)
			}
			// An OSV export set, from files.
			exp := []byte("npm export")
			mo := manifest(1, map[string][]byte{"npm.zip": exp})
			mo.Kind = content.OSVExport
			src := filepath.Join(st.Root, ".incoming-npm.zip")
			if err := os.MkdirAll(st.Root, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(src, exp, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err = st.InstallFiles(content.OSVExport, feedEnvelope(t, mo, feedPriv), map[string]string{"npm.zip": src}, c.tr)
			if (err == nil) != c.ok {
				t.Fatalf("InstallFiles: %v (want ok=%v)", err, c.ok)
			}
			if !c.ok {
				return
			}
			if _, err := st.Load(content.OSVExport, c.tr, 0); err != nil {
				t.Fatalf("Load with the feed key: %v", err)
			}
			if _, err := st.Load(content.OSVExport, Trust{VendorKeys: []ed25519.PublicKey{vendorPub}}, 0); err == nil {
				t.Fatal("Load without the feed key must refuse the feed-signed set")
			}
		})
	}
}
